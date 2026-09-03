//! Ready-queue executor over `IR<HlApiDialect>`.
//!
//! The idea is simple: track for each instruction when its needed inputs
//! are ready, and when they all are, send the operation to a worker. Once the worker
//! has done the operation, dispatch its outputs to the operations that use/consume them,
//! rinse and repeat until all circuit outputs are collected
use std::collections::{BTreeMap, HashMap};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use super::ops::{exec_dialect_op, exec_trivial};
use super::value::{CpuInputList, CpuOutputList, RuntimeValue};
use super::CpuError;
use crate::circuit::dialects::hlapi::{
    Circuit, ClearKind, HlApiDialect, HlInstructionSet, ScalarValue,
};
use crossbeam::channel::{unbounded, Receiver, Sender};
use zhc_ir::{OpId, OpMap, ValId, IR};
use zhc_utils::small::SmallVec;
use zhc_utils::svec;

struct InstRuntime {
    /// Sum of number of inputs still missing in `partial_inputs`
    /// and number of ops that need to be finished before being able to run this
    /// operation.
    /// When it reaches 0, the inst is ready to be dispatched as a `ReadyOp`.
    waiting_for: u32,
    partial_inputs: Vec<Option<Arc<RuntimeValue>>>,
}

impl InstRuntime {
    fn new(arity: usize) -> Self {
        Self {
            waiting_for: arity as u32,
            partial_inputs: vec![None; arity],
        }
    }
}

/// Message sent from dispatcher thread to worker threads
/// with the info of an operation that is ready to be executed
struct ReadyOp {
    /// Id of the operation to be executed
    id: OpId,
    /// The inputs of the operation
    inputs: Vec<Arc<RuntimeValue>>,
}

/// Message sent from worker threads to dispatcher thread
/// when an operation has been done
struct DoneOp {
    /// Id of the finished operation
    id: OpId,
    /// Result of the operation
    result: Result<Vec<Arc<RuntimeValue>>, CpuError>,
}

/// Static metadata derived once per `Circuit` execution.
struct ReadyQueueMeta {
    /// Map operations to a list of operations that wait for that op to be done.
    waiter_of_op: BTreeMap<OpId, SmallVec<OpId>>,
    /// `OpId` → output position, for `Output { pos, .. }` ops only. Used by
    /// `dispatch_value` to redirect values destined for circuit outputs into
    /// `program_outputs[pos]` instead of dispatching them as ReadyOps.
    output_pos_of_op: HashMap<OpId, u32>,
}

impl ReadyQueueMeta {
    fn from_circuit(circuit: &Circuit) -> (Self, OpMap<InstRuntime>) {
        let ir = circuit.ir();
        let mut output_pos_of_op = HashMap::new();
        for op_ref in ir.walk_ops_linear() {
            if let HlInstructionSet::Output { pos, .. } = op_ref.get_instruction() {
                output_pos_of_op.insert(op_ref.get_id(), pos);
            }
        }

        // Same rationale as `consumers_of_value`: `OpMap` is gap-aware,
        // whereas `Store<OpId, _>` populated by push assumes dense OpIds.
        let mut inst_rt: OpMap<InstRuntime> =
            ir.totally_mapped_opmap(|op| InstRuntime::new(op.get_args_arity()));

        // Second pass: KVStore mutating ops act as barriers, requiring all
        // *readers* of the same store version to complete first. Encoded by
        // bumping `waiting_for` on the mutating op and recording the reverse
        // dependency in `waiter_of_op`.
        let mut waiter_of_op = BTreeMap::new();
        for op_ref in ir.walk_ops_linear() {
            match op_ref.get_instruction() {
                HlInstructionSet::KVStoreInsertWithClearKey { .. }
                | HlInstructionSet::KVStoreRemoveWithClearKey { .. }
                | HlInstructionSet::KVStoreUpdate { .. } => {
                    let store_id = op_ref.get_arg_valids()[0];
                    let store_ref = circuit.ir().get_val(store_id);
                    for op_use in store_ref.get_users_iter() {
                        if op_use == op_ref {
                            continue;
                        }
                        // `Output` ops are handled by the coordinator (collected
                        // into `program_outputs`); they never produce a `DoneOp`,
                        // so they can't be the trigger that decrements the
                        // mutating op's `waiting_for`. Excluding them keeps the
                        // barrier counter consistent.
                        if matches!(op_use.get_instruction(), HlInstructionSet::Output { .. }) {
                            continue;
                        }
                        waiter_of_op
                            .entry(op_use.get_id())
                            .or_insert_with(|| svec![])
                            .push(op_ref.get_id());
                        inst_rt[op_ref.get_id()].waiting_for += 1;
                    }
                }
                _ => {}
            }
        }

        let meta = Self {
            waiter_of_op,
            output_pos_of_op,
        };

        (meta, inst_rt)
    }
}

/// References bundled together so `dispatch_value` doesn't need 6+ args.
struct DispatchCtx<'a> {
    ir: &'a IR<HlApiDialect>,
    meta: &'a ReadyQueueMeta,
    inst_rt: &'a mut OpMap<InstRuntime>,
    program_outputs: &'a mut [Option<Arc<RuntimeValue>>],
    outputs_needed: &'a mut usize,
    ready_sender: &'a Sender<ReadyOp>,
}

/// Distribute one freshly-produced value to its consumers and to
/// `program_outputs` if any consumer is an `Output` op. May queue
/// newly-ready ReadyOps.
fn dispatch_value(value_id: ValId, value: Arc<RuntimeValue>, ctx: &mut DispatchCtx<'_>) {
    let mut to_send: SmallVec<ReadyOp> = SmallVec::new();
    let ir = ctx.ir;
    for val_use in ir.get_val(value_id).get_uses_iter() {
        let consumer = val_use.opref.get_id();
        if let Some(&out_pos) = ctx.meta.output_pos_of_op.get(&consumer) {
            // Output op consumer: collect into program_outputs, nothing to
            // dispatch.
            ctx.program_outputs[out_pos as usize] = Some(value.clone());
            *ctx.outputs_needed -= 1;
        } else {
            // Normal consumer: fill its partial_inputs slot, decrement
            // waiting_for, queue a ReadyOp (deferred send) if all inputs are
            // now in place.
            let rt = &mut ctx.inst_rt[consumer];
            rt.partial_inputs[usize::from(val_use.position)] = Some(value.clone());
            if rt.waiting_for == 1 {
                to_send.push(ReadyOp {
                    id: consumer,
                    inputs: rt.partial_inputs.drain(..).map(Option::unwrap).collect(),
                });
            }
            rt.waiting_for -= 1;
        }
    }
    // Drop our reference before notifying workers. Otherwise a worker
    // recv'ing a ReadyOp and taking ownership of its store input via
    // `take_store` could see refcount > 1 (us + the worker's clone) and
    // fall back to cloning the whole store.
    drop(value);
    for r in to_send.into_iter() {
        ctx.ready_sender.send(r).unwrap();
    }
}

fn worker(
    sks: &crate::ServerKey,
    in_channel: &Receiver<ReadyOp>,
    circuit: &Circuit,
    out_channel: &Sender<DoneOp>,
) {
    // 4 outputs should be enough for > 99% of ops
    let mut output_buf: Vec<RuntimeValue> = Vec::with_capacity(4);

    loop {
        // coordinator dropped ready_tx, we're done
        let Ok(ReadyOp { id, mut inputs }) = in_channel.recv() else {
            return;
        };

        output_buf.clear();

        let op_ref = circuit.ir().get_op(id);
        let op = op_ref.get_instruction();
        let op_name = op.name();

        // Wrap the dispatch in catch_unwind so a panic inside an op
        // (intentional `todo!()`s, type-mismatch invariants, FHE-op bugs)
        // gets surfaced as a CpuError instead of bringing down the worker
        // thread (and through `thread::scope`, the whole executor).
        let dispatch_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            exec_dialect_op(sks, &op, &mut inputs, &mut output_buf)
        }));

        let result = match dispatch_result {
            Ok(Ok(())) => Ok(output_buf.drain(..).map(Arc::new).collect()),
            Ok(Err(e)) => Err(e),
            Err(panic_payload) => Err(CpuError::ExecutionError {
                node_index: id.0 as usize,
                op: op_name,
                message: panic_payload_to_string(panic_payload),
            }),
        };

        // Release our references to the inputs before notifying the
        // coordinator, to make sure that we don't count as a potential
        // owner
        drop(inputs);

        let _ = out_channel.send(DoneOp { id, result });
    }
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send + 'static>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => payload.downcast::<&'static str>().map_or_else(
            |_| "non-string panic payload".to_string(),
            |message| (*message).to_string(),
        ),
    }
}

/// Crate-internal executor entry point.
pub(crate) fn execute_circuit(
    sks: &crate::ServerKey,
    circuit: &Circuit,
    inputs: CpuInputList,
    num_workers: usize,
) -> Result<CpuOutputList, CpuError> {
    let (meta, mut inst_rt) = ReadyQueueMeta::from_circuit(circuit);
    let ir = circuit.ir();

    let circuit_inputs = circuit.inputs();
    let output_count = circuit.outputs().len();

    if inputs.inputs.len() != circuit_inputs.len() {
        return Err(CpuError::InputCountMismatch {
            expected: circuit_inputs.len(),
            got: inputs.inputs.len(),
        });
    }

    let mut program_outputs: Vec<Option<Arc<RuntimeValue>>> = vec![None; output_count];
    let mut outputs_needed = output_count;

    let (work_ready_sender, work_ready_receiver) = unbounded::<ReadyOp>();
    let (work_done_sender, work_done_receiver) = unbounded::<DoneOp>();

    // Seed: validate input types and dispatch each circuit input. The seed
    // loop's `ctx` is scoped so its borrows release before the thread::scope.
    {
        let mut ctx = DispatchCtx {
            ir,
            meta: &meta,
            inst_rt: &mut inst_rt,
            program_outputs: &mut program_outputs,
            outputs_needed: &mut outputs_needed,
            ready_sender: &work_ready_sender,
        };

        // Dispatch the inputs
        for (i, (val_id, input_value)) in circuit_inputs.iter().zip(inputs.inputs).enumerate() {
            let expected_kind = circuit.input_kind(i);
            input_value.check_input(i, &expected_kind, sks.pbs_key())?;
            dispatch_value(*val_id, Arc::new(input_value), &mut ctx);
        }

        // "Constant" operations are doable directly and are just about dispatching the stored value
        for op_ref in ir.walk_ops_linear() {
            let HlInstructionSet::Constant { kind, value } = op_ref.get_instruction() else {
                continue;
            };
            let exec_value = match (kind, value) {
                (ClearKind::Bool, ScalarValue::Bool(v)) => RuntimeValue::ClearBool(v),
                (ClearKind::Uint(_), ScalarValue::Unsigned(v)) => RuntimeValue::ClearUint(v),
                (ClearKind::Int(_), ScalarValue::Signed(v)) => RuntimeValue::ClearInt(v),
                _ => panic!("Constant: kind/value mismatch ({kind:?} vs {value:?})"),
            };
            let val_id = op_ref.get_returns_iter().next().unwrap().get_id();
            dispatch_value(val_id, Arc::new(exec_value), &mut ctx);
        }

        // `EncryptTrivial` is just an encryption so it's cheap
        // Do them now as the input + constant dispatch may have made some ready
        let mut held: Vec<ReadyOp> = Vec::new();
        while let Ok(r) = work_ready_receiver.try_recv() {
            let op_ref = ir.get_op(r.id);
            if let HlInstructionSet::EncryptTrivial { kind } = op_ref.get_instruction() {
                let output = exec_trivial(r.inputs[0].as_ref(), kind, sks);
                let val_id = op_ref.get_returns_iter().next().unwrap().get_id();
                dispatch_value(val_id, Arc::new(output), &mut ctx);
            } else {
                held.push(r);
            }
        }
        for r in held {
            ctx.ready_sender.send(r).unwrap();
        }
    }

    // Arity-0 non-boundary ops become ready immediately.
    // Their `waiting_for` was 0 from construction so the seed
    // loop never triggered them.
    for op_ref in ir.walk_ops_linear() {
        let opid = op_ref.get_id();
        let is_handled_in_seed = matches!(
            op_ref.get_instruction(),
            HlInstructionSet::Input { .. }
                | HlInstructionSet::Output { .. }
                // Constants were handled earlier
                | HlInstructionSet::Constant { .. }
        );
        if !is_handled_in_seed && op_ref.get_args_arity() == 0 {
            work_ready_sender
                .send(ReadyOp {
                    id: opid,
                    inputs: vec![],
                })
                .unwrap();
        }
    }

    let mut execution_error: Option<CpuError> = None;

    std::thread::scope(|s| {
        for _ in 0..num_workers {
            let circuit_ref = circuit;
            let rx = work_ready_receiver.clone();
            let tx = work_done_sender.clone();
            s.spawn(move || worker(sks, &rx, circuit_ref, &tx));
        }
        // Dropping it now means `work_done_receiver.recv()` returns Err exactly
        // when all workers have exited.
        drop(work_done_sender);

        let mut ctx = DispatchCtx {
            ir,
            meta: &meta,
            inst_rt: &mut inst_rt,
            program_outputs: &mut program_outputs,
            outputs_needed: &mut outputs_needed,
            ready_sender: &work_ready_sender,
        };

        // Coordinator loop.
        'main: loop {
            // outputs_needed == 0 covers both the normal "all done" case and
            // the passthrough case where Input → Output filled everything in
            // the seed loop.
            if *ctx.outputs_needed == 0 {
                break 'main;
            }

            let Ok(DoneOp { id, result }) = work_done_receiver.recv() else {
                // All workers exited while outputs are still missing
                // (e.g. a worker died outside its catch_unwind).
                break 'main;
            };

            let outputs = match result {
                Ok(o) => o,
                Err(e) => {
                    execution_error = Some(e);
                    break 'main;
                }
            };

            // Map this op's produced ValIds in order, dispatch each value.
            let op_ref = ir.get_op(id);
            // A count mismatch would silently truncate the zip below and
            // leave the missing value's consumers waiting forever
            assert_eq!(
                outputs.len(),
                op_ref.get_returns_iter().count(),
                "op {id:?} ({}) produced {} value(s) but its IR signature declares {}",
                op_ref.get_instruction().name(),
                outputs.len(),
                op_ref.get_returns_iter().count(),
            );
            for (value, val_ref) in outputs.into_iter().zip(op_ref.get_returns_iter()) {
                let val_id = val_ref.get_id();
                dispatch_value(val_id, value, &mut ctx);
                if *ctx.outputs_needed == 0 {
                    break 'main;
                }
            }

            // Decrement `waiting_for` for ops that were implicitly depending on
            // this op (barrier deps from `waiter_of_op`).
            if let Some(dependants) = meta.waiter_of_op.get(&op_ref.get_id()) {
                for &dep_id in dependants.iter() {
                    let rt = &mut ctx.inst_rt[dep_id];
                    debug_assert!(rt.waiting_for > 0);
                    if rt.waiting_for == 1 {
                        let r = ReadyOp {
                            id: dep_id,
                            inputs: rt.partial_inputs.drain(..).map(Option::unwrap).collect(),
                        };
                        ctx.ready_sender.send(r).unwrap();
                    }
                    rt.waiting_for -= 1;
                }
            }
        }

        // Disconnect the ready channel so workers see Disconnected on their
        // next recv() and exit.
        drop(work_ready_sender);
    });

    if let Some(err) = execution_error {
        return Err(err);
    }

    // Results carry the executing key's tag, like classic HLAPI ops.
    let mut output_list = CpuOutputList::with_tag(crate::prelude::Tagged::tag(sks).clone());
    for output in program_outputs {
        let arc = output.expect("program output not produced");
        let value = Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone());
        output_list.push(value);
    }

    Ok(output_list)
}
