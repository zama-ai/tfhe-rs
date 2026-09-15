//! Ready-queue executor over `IR<HlApiDialect>`.
//!
//! The idea is simple: track for each instruction when its needed inputs
//! are ready, and when they all are, send the operation to a worker. Once the worker
//! has done the operation, dispatch its outputs to the operations that use/consume them,
//! rinse and repeat until all circuit outputs are collected
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use super::ops::exec_dialect_op;
use super::value::{CpuInputList, CpuOutputList, RuntimeValue};
use super::CpuError;
use crate::circuit::dialects::hlapi::{Circuit, HlApiDialect, HlInstructionSet};
use crossbeam::channel::{unbounded, Receiver, Sender};
use zhc_ir::{AsValId, OpId, OpMap, IR};
use zhc_utils::small::SmallVec;
use zhc_utils::svec;

/// Readiness of an operations
///
/// There is one instance of this struct per operation to run
struct PendingOp {
    /// Sum of number of inputs still missing in `partial_inputs`
    /// and number of ops that need to be finished before being able to run this
    /// operation.
    /// When it reaches 0, the op is ready to be dispatched as a `ReadyOp`.
    waiting_for: u32,
    partial_inputs: Vec<Option<Arc<RuntimeValue>>>,
}

impl PendingOp {
    fn new(arity: u32) -> Self {
        Self {
            waiting_for: arity,
            partial_inputs: vec![None; arity as usize],
        }
    }

    /// Returns Some ReadyOp if the operation is indeed ready
    ///
    /// `id` should be the key used in the OpMap that stores the PendinOp struct
    fn ready(&mut self, id: OpId) -> Option<ReadyOp> {
        assert!(self.waiting_for > 0, "op was already dispatched");
        self.waiting_for -= 1;
        (self.waiting_for == 0).then(|| ReadyOp {
            id,
            inputs: self.partial_inputs.drain(..).map(Option::unwrap).collect(),
        })
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
    waiter_of_op: HashMap<OpId, SmallVec<OpId>>,
    /// `OpId` → output position, for `Output { pos, .. }` ops only. Used by
    /// `dispatch_value` to redirect values destined for circuit outputs into
    /// `program_outputs[pos]` instead of dispatching them as ReadyOps.
    output_pos_of_op: HashMap<OpId, u32>,
}

impl ReadyQueueMeta {
    fn from_circuit(circuit: &Circuit) -> (Self, OpMap<PendingOp>) {
        let ir = circuit.ir();
        let mut output_pos_of_op = HashMap::new();
        for op_ref in ir.walk_ops_linear() {
            if let HlInstructionSet::Output { pos, .. } = op_ref.get_instruction() {
                output_pos_of_op.insert(op_ref.get_id(), pos);
            }
        }

        let mut pending_ops: OpMap<PendingOp> =
            ir.totally_mapped_opmap(|op| PendingOp::new(op.get_args_arity() as u32));

        // Second pass: KVStore mutating ops act as barriers, requiring all
        // *readers* of the same store version to complete first. Encoded by
        // bumping `waiting_for` on the mutating op and recording the reverse
        // dependency in `waiter_of_op`.
        let mut waiter_of_op = HashMap::new();
        for op_ref in ir.walk_ops_linear() {
            if op_ref.get_instruction().mutates_kv_store() {
                let store_id = op_ref.get_arg_valids()[0];
                let store_ref = circuit.ir().get_val(store_id);
                for op_use in store_ref.get_users_iter() {
                    if op_use == op_ref {
                        continue;
                    }
                    // `Output` ops are completed by the coordinator itself (see
                    // `dispatch_value`): they never run on a worker and never
                    // send a `DoneOp`. Counting them would leave `waiting_for`
                    // stuck above 0 and deadlock the mutating op.
                    //
                    // Skipping them is also safe, and waiting for them would
                    // buy nothing: `program_outputs` keeps an `Arc` to the
                    // output's store version for the whole run, so the
                    // mutating op sees a shared `Arc` and clones the store
                    // instead of mutating it in place (see `take_store` in
                    // `ops.rs`). The output is therefore a snapshot of the
                    // version it was taken from. The barrier itself is only an
                    // optimization letting the mutating op run last and take
                    // ownership without a copy; correctness comes from `Arc`.
                    if matches!(op_use.get_instruction(), HlInstructionSet::Output { .. }) {
                        continue;
                    }
                    waiter_of_op
                        .entry(op_use.get_id())
                        .or_insert_with(|| svec![])
                        .push(op_ref.get_id());
                    pending_ops[op_ref.get_id()].waiting_for += 1;
                }
            }
        }

        let meta = Self {
            waiter_of_op,
            output_pos_of_op,
        };

        (meta, pending_ops)
    }
}

/// References bundled together so `dispatch_value` doesn't need 6+ args.
struct DispatchCtx<'a> {
    ir: &'a IR<HlApiDialect>,
    meta: &'a ReadyQueueMeta,
    pending_ops: &'a mut OpMap<PendingOp>,
    program_outputs: &'a mut [Option<Arc<RuntimeValue>>],
    outputs_needed: &'a mut u32,
    ready_sender: &'a Sender<ReadyOp>,
}

/// Distribute one freshly-produced value to its consumers and to
/// `program_outputs` if any consumer is an `Output` op. May queue
/// newly-ready ReadyOps.
fn dispatch_value(value_id: impl AsValId, value: Arc<RuntimeValue>, ctx: &mut DispatchCtx<'_>) {
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
            // Normal consumer: fill its partial_inputs slot and queue a
            // ReadyOp (deferred send) if all inputs are now in place.
            let pending = &mut ctx.pending_ops[consumer];
            pending.partial_inputs[usize::from(val_use.position)] = Some(value.clone());
            if let Some(ready_op) = pending.ready(consumer) {
                to_send.push(ready_op);
            }
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
        let result = catch_op_panic(id, op_name, || {
            exec_dialect_op(sks, &op, &mut inputs, &mut output_buf)
        })
        .map(|()| output_buf.drain(..).map(Arc::new).collect());

        // Release our references to the inputs before notifying the
        // coordinator, to make sure that we don't count as a potential
        // owner
        drop(inputs);

        let _ = out_channel.send(DoneOp { id, result });
    }
}

/// Run `f` for the op `id`, converting a panic into a
/// [`CpuError::ExecutionError`] carrying the op and the panic message.
fn catch_op_panic<T>(
    id: OpId,
    op_name: &'static str,
    f: impl FnOnce() -> T,
) -> Result<T, CpuError> {
    std::panic::catch_unwind(AssertUnwindSafe(f)).map_err(|payload| CpuError::ExecutionError {
        node_index: id.0,
        op: op_name,
        message: panic_payload_to_string(payload),
    })
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
    let (meta, mut pending_ops) = ReadyQueueMeta::from_circuit(circuit);
    let ir = circuit.ir();

    let circuit_inputs = circuit.inputs();
    let output_count = circuit.outputs().len();

    if inputs.inputs.len() != circuit_inputs.len() {
        return Err(CpuError::InputCountMismatch {
            expected: circuit.n_inputs(),
            got: inputs.inputs.len() as u32,
        });
    }

    let mut program_outputs: Vec<Option<Arc<RuntimeValue>>> = vec![None; output_count];
    let mut outputs_needed = circuit.n_outputs();

    let (work_ready_sender, work_ready_receiver) = unbounded::<ReadyOp>();
    let (work_done_sender, work_done_receiver) = unbounded::<DoneOp>();

    // Seed phase
    //
    // Dispatch inputs then send ReadyOp before starting main loop
    {
        let mut ctx = DispatchCtx {
            ir,
            meta: &meta,
            pending_ops: &mut pending_ops,
            program_outputs: &mut program_outputs,
            outputs_needed: &mut outputs_needed,
            ready_sender: &work_ready_sender,
        };

        for (i, (val_id, input_value)) in circuit_inputs.iter().zip(inputs.inputs).enumerate() {
            let i = i as u32;
            let expected_kind = circuit.input_kind(i);
            input_value.check_input(i, &expected_kind, sks.pbs_key())?;
            dispatch_value(val_id, Arc::new(input_value), &mut ctx);
        }

        for op_ref in ir.walk_ops_linear() {
            if op_ref.get_args_arity() == 0
                && !matches!(op_ref.get_instruction(), HlInstructionSet::Input { .. })
            {
                ctx.ready_sender
                    .send(ReadyOp {
                        id: op_ref.get_id(),
                        inputs: vec![],
                    })
                    .unwrap();
            }
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
            pending_ops: &mut pending_ops,
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
                // All workers exited while outputs are still missing (e.g. a
                // worker died outside its catch_unwind). The missing outputs
                // are reported as `CpuError::MissingOutput` below.
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
            // leave the missing value's consumers waiting forever. It means
            // the op's implementation disagrees with its IR signature: report
            // it rather than panic on the caller's thread.
            let declared = op_ref.get_returns_iter().count();
            if outputs.len() != declared {
                execution_error = Some(CpuError::ExecutionError {
                    node_index: id.0,
                    op: op_ref.get_instruction().name(),
                    message: format!(
                        "produced {} value(s) but its IR signature declares {declared}",
                        outputs.len()
                    ),
                });
                break 'main;
            }
            for (value, val_ref) in outputs.into_iter().zip(op_ref.get_returns_iter()) {
                dispatch_value(val_ref.get_id(), value, &mut ctx);
            }

            // Decrement `waiting_for` for ops that were implicitly depending on
            // this op (barrier deps from `waiter_of_op`).
            if let Some(dependants) = meta.waiter_of_op.get(&op_ref.get_id()) {
                for &dep_id in dependants.iter() {
                    if let Some(ready_op) = ctx.pending_ops[dep_id].ready(dep_id) {
                        ctx.ready_sender.send(ready_op).unwrap();
                    }
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
    for (pos, output) in program_outputs.into_iter().enumerate() {
        let arc = output.ok_or(CpuError::MissingOutput { pos: pos as u32 })?;
        output_list.push(Arc::unwrap_or_clone(arc));
    }

    Ok(output_list)
}
