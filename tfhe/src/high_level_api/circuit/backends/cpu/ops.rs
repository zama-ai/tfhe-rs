//! Per-op compute for the CPU backend.
use std::sync::Arc;

use super::value::RuntimeValue;
use super::CpuError;
use crate::circuit::dialects::hlapi::{
    FheIntKind, FheKind, HlInstructionSet, NonNanF64, OprfMode, ScalarValue, ValueKind,
};
use crate::high_level_api::integers::oprf::num_input_random_bits_for_max_distance;
use crate::integer::server_key::radix_parallel::cmux::ServerKeyDefaultCMux;
use crate::integer::server_key::KVStore;
use crate::integer::{BooleanBlock, RadixCiphertext, SignedRadixCiphertext};
use crate::{ReRandomizationMetadata, Tag};

// =========================================================================
// Closure-based dispatch helpers.
//
// Each helper takes `inputs: &[&RuntimeValue]` (or `input: &RuntimeValue` for
// unary scalar ops) plus closures keyed by `RuntimeValue` variant, and panics
// on type mismatch. Type mismatches can't happen in well-formed programs
// (zhc validates op signatures at IR construction time)
//
// The dialect's `kind` tag (FheIntKind / FheKind) is intentionally
// unused by these helpers — they dispatch on `RuntimeValue` variants alone.
// =========================================================================

/// Execute a binary arithmetic op that returns the same type as its inputs.
fn exec_binary_op(
    inputs: &[&RuntimeValue],
    unsigned_op: impl FnOnce(&RadixCiphertext, &RadixCiphertext) -> RadixCiphertext,
    signed_op: impl FnOnce(&SignedRadixCiphertext, &SignedRadixCiphertext) -> SignedRadixCiphertext,
) -> RuntimeValue {
    match (inputs[0], inputs[1]) {
        (RuntimeValue::FheUint(lhs), RuntimeValue::FheUint(rhs)) => {
            RuntimeValue::FheUint(unsigned_op(lhs, rhs))
        }
        (RuntimeValue::FheInt(lhs), RuntimeValue::FheInt(rhs)) => {
            RuntimeValue::FheInt(signed_op(lhs, rhs))
        }
        _ => panic!("mismatched or invalid input types for binary op"),
    }
}

/// Execute a binary bitwise op (bitand/bitor/bitxor).
fn exec_binary_bitwise_op(
    inputs: &[&RuntimeValue],
    unsigned_op: impl FnOnce(&RadixCiphertext, &RadixCiphertext) -> RadixCiphertext,
    signed_op: impl FnOnce(&SignedRadixCiphertext, &SignedRadixCiphertext) -> SignedRadixCiphertext,
    bool_op: impl FnOnce(&BooleanBlock, &BooleanBlock) -> BooleanBlock,
) -> RuntimeValue {
    match (inputs[0], inputs[1]) {
        (RuntimeValue::FheUint(lhs), RuntimeValue::FheUint(rhs)) => {
            RuntimeValue::FheUint(unsigned_op(lhs, rhs))
        }
        (RuntimeValue::FheInt(lhs), RuntimeValue::FheInt(rhs)) => {
            RuntimeValue::FheInt(signed_op(lhs, rhs))
        }
        (RuntimeValue::FheBool(lhs), RuntimeValue::FheBool(rhs)) => {
            RuntimeValue::FheBool(bool_op(lhs, rhs))
        }
        _ => panic!("mismatched or invalid input types for binary bitwise op"),
    }
}

/// Execute an ordering op (lt/le/gt/ge) returning a `Bool`.
/// Bool operands are not valid for ordering
fn exec_binary_cmp(
    inputs: &[&RuntimeValue],
    unsigned_op: impl FnOnce(&RadixCiphertext, &RadixCiphertext) -> BooleanBlock,
    signed_op: impl FnOnce(&SignedRadixCiphertext, &SignedRadixCiphertext) -> BooleanBlock,
) -> RuntimeValue {
    let block = match (inputs[0], inputs[1]) {
        (RuntimeValue::FheUint(lhs), RuntimeValue::FheUint(rhs)) => unsigned_op(lhs, rhs),
        (RuntimeValue::FheInt(lhs), RuntimeValue::FheInt(rhs)) => signed_op(lhs, rhs),
        _ => panic!("mismatched or invalid input types for binary cmp"),
    };
    RuntimeValue::FheBool(block)
}

/// Execute an equality op (eq/ne) returning a `Bool`.
fn exec_binary_eq(
    inputs: &[&RuntimeValue],
    unsigned_op: impl FnOnce(&RadixCiphertext, &RadixCiphertext) -> BooleanBlock,
    signed_op: impl FnOnce(&SignedRadixCiphertext, &SignedRadixCiphertext) -> BooleanBlock,
    bool_op: impl FnOnce(&BooleanBlock, &BooleanBlock) -> BooleanBlock,
) -> RuntimeValue {
    let block = match (inputs[0], inputs[1]) {
        (RuntimeValue::FheUint(lhs), RuntimeValue::FheUint(rhs)) => unsigned_op(lhs, rhs),
        (RuntimeValue::FheInt(lhs), RuntimeValue::FheInt(rhs)) => signed_op(lhs, rhs),
        (RuntimeValue::FheBool(lhs), RuntimeValue::FheBool(rhs)) => bool_op(lhs, rhs),
        _ => panic!("mismatched or invalid input types for binary eq"),
    };
    RuntimeValue::FheBool(block)
}

/// Execute a shift/rotate op. Shift amount (`rhs`) is always an unsigned
/// `RadixCiphertext`; lhs may be unsigned or signed and the output matches.
fn exec_shift_op(
    inputs: &[&RuntimeValue],
    unsigned_op: impl FnOnce(&RadixCiphertext, &RadixCiphertext) -> RadixCiphertext,
    signed_op: impl FnOnce(&SignedRadixCiphertext, &RadixCiphertext) -> SignedRadixCiphertext,
) -> RuntimeValue {
    match (inputs[0], inputs[1]) {
        (RuntimeValue::FheUint(lhs), RuntimeValue::FheUint(rhs)) => {
            RuntimeValue::FheUint(unsigned_op(lhs, rhs))
        }
        (RuntimeValue::FheInt(lhs), RuntimeValue::FheUint(rhs)) => {
            RuntimeValue::FheInt(signed_op(lhs, rhs))
        }
        _ => panic!("invalid input types for shift/rotate op"),
    }
}

/// Execute an overflowing op that returns `(value, BooleanBlock)`.
fn exec_overflowing_op(
    inputs: &[&RuntimeValue],
    unsigned_op: impl FnOnce(&RadixCiphertext, &RadixCiphertext) -> (RadixCiphertext, BooleanBlock),
    signed_op: impl FnOnce(
        &SignedRadixCiphertext,
        &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock),
) -> (RuntimeValue, RuntimeValue) {
    match (inputs[0], inputs[1]) {
        (RuntimeValue::FheUint(lhs), RuntimeValue::FheUint(rhs)) => {
            let (result, overflow) = unsigned_op(lhs, rhs);
            (
                RuntimeValue::FheUint(result),
                RuntimeValue::FheBool(overflow),
            )
        }
        (RuntimeValue::FheInt(lhs), RuntimeValue::FheInt(rhs)) => {
            let (result, overflow) = signed_op(lhs, rhs);
            (
                RuntimeValue::FheInt(result),
                RuntimeValue::FheBool(overflow),
            )
        }
        _ => panic!("mismatched or invalid input types for overflowing op"),
    }
}

/// Execute a scalar arithmetic-style op (add/sub/mul/div/rem/min/max/shifts/rotates).
fn exec_scalar_op(
    input: &RuntimeValue,
    scalar: &ScalarValue,
    unsigned_op: impl FnOnce(&RadixCiphertext, u128) -> RadixCiphertext,
    signed_op: impl FnOnce(&SignedRadixCiphertext, i128) -> SignedRadixCiphertext,
) -> RuntimeValue {
    match (input, scalar) {
        (RuntimeValue::FheUint(v), ScalarValue::Unsigned(s)) => {
            RuntimeValue::FheUint(unsigned_op(v, *s))
        }
        (RuntimeValue::FheInt(v), ScalarValue::Signed(s)) => RuntimeValue::FheInt(signed_op(v, *s)),
        _ => panic!("mismatched scalar/ciphertext type for scalar op"),
    }
}

/// Execute a scalar bitwise op (bitand/bitor/bitxor) with `Bool` support.
fn exec_scalar_bitwise_op(
    input: &RuntimeValue,
    scalar: &ScalarValue,
    unsigned_op: impl FnOnce(&RadixCiphertext, u128) -> RadixCiphertext,
    signed_op: impl FnOnce(&SignedRadixCiphertext, i128) -> SignedRadixCiphertext,
    bool_op: impl FnOnce(&BooleanBlock, bool) -> BooleanBlock,
) -> RuntimeValue {
    match (input, scalar) {
        (RuntimeValue::FheUint(v), ScalarValue::Unsigned(s)) => {
            RuntimeValue::FheUint(unsigned_op(v, *s))
        }
        (RuntimeValue::FheInt(v), ScalarValue::Signed(s)) => RuntimeValue::FheInt(signed_op(v, *s)),
        (RuntimeValue::FheBool(v), ScalarValue::Bool(s)) => RuntimeValue::FheBool(bool_op(v, *s)),
        _ => panic!("mismatched scalar/ciphertext type for scalar bitwise op"),
    }
}

/// Execute a scalar ordering op (lt/le/gt/ge) returning a `Bool`.
fn exec_scalar_cmp(
    input: &RuntimeValue,
    scalar: &ScalarValue,
    unsigned_op: impl FnOnce(&RadixCiphertext, u128) -> BooleanBlock,
    signed_op: impl FnOnce(&SignedRadixCiphertext, i128) -> BooleanBlock,
) -> RuntimeValue {
    let block = match (input, scalar) {
        (RuntimeValue::FheUint(v), ScalarValue::Unsigned(s)) => unsigned_op(v, *s),
        (RuntimeValue::FheInt(v), ScalarValue::Signed(s)) => signed_op(v, *s),
        _ => panic!("mismatched scalar/ciphertext type for scalar cmp"),
    };
    RuntimeValue::FheBool(block)
}

/// Execute the Select (cmux) op: `(cond, lhs, rhs) -> kind`.
/// Cond is always FheBool; lhs/rhs are integer
fn exec_if_then_else(inputs: &[&RuntimeValue], sks: &crate::ServerKey) -> RuntimeValue {
    let condition = inputs[0];
    let lhs = inputs[1];
    let rhs = inputs[2];

    let RuntimeValue::FheBool(cond) = condition else {
        panic!("wrong input type for Select condition");
    };

    match (lhs, rhs) {
        (RuntimeValue::FheUint(l), RuntimeValue::FheUint(r)) => {
            RuntimeValue::FheUint(sks.pbs_key().if_then_else_parallelized(cond, l, r))
        }
        (RuntimeValue::FheInt(l), RuntimeValue::FheInt(r)) => {
            RuntimeValue::FheInt(sks.pbs_key().if_then_else_parallelized(cond, l, r))
        }
        _ => panic!("mismatched or invalid input types for Select"),
    }
}

/// SelectScalarScalar — both branches are clear values.
/// Signature: `(FheBool, clear, clear) -> kind`.
fn exec_if_then_else_scalar_scalar(
    inputs: &[&RuntimeValue],
    kind: FheIntKind,
    sks: &crate::ServerKey,
) -> RuntimeValue {
    let RuntimeValue::FheBool(cond) = inputs[0] else {
        panic!("wrong input type for SelectScalarScalar condition");
    };
    let bits_per_block = sks.message_modulus().0.ilog2() as usize;
    let pbs = sks.pbs_key();
    match (kind, inputs[1], inputs[2]) {
        (FheIntKind::Uint(bits), RuntimeValue::ClearUint(t), RuntimeValue::ClearUint(f)) => {
            let n_blocks = (bits as usize).div_ceil(bits_per_block);
            let ct: crate::integer::RadixCiphertext =
                pbs.scalar_if_then_else_parallelized(cond, *t, *f, n_blocks);
            RuntimeValue::FheUint(ct)
        }
        (FheIntKind::Int(bits), RuntimeValue::ClearInt(t), RuntimeValue::ClearInt(f)) => {
            let n_blocks = (bits as usize).div_ceil(bits_per_block);
            let ct: crate::integer::SignedRadixCiphertext =
                pbs.scalar_if_then_else_parallelized(cond, *t, *f, n_blocks);
            RuntimeValue::FheInt(ct)
        }
        _ => panic!("mismatched kind/scalar for SelectScalarScalar"),
    }
}

/// SelectFheScalar — then-branch encrypted (inputs[1]), else-branch clear (inputs[2]).
fn exec_if_then_else_fhe_scalar(inputs: &[&RuntimeValue], sks: &crate::ServerKey) -> RuntimeValue {
    let RuntimeValue::FheBool(cond) = inputs[0] else {
        panic!("wrong input type for SelectFheScalar condition");
    };
    let pbs = sks.pbs_key();
    match (inputs[1], inputs[2]) {
        (RuntimeValue::FheUint(t), RuntimeValue::ClearUint(s)) => {
            RuntimeValue::FheUint(pbs.if_then_else_parallelized(cond, t, *s))
        }
        (RuntimeValue::FheInt(t), RuntimeValue::ClearInt(s)) => {
            RuntimeValue::FheInt(pbs.if_then_else_parallelized(cond, t, *s))
        }
        _ => panic!("mismatched types for SelectFheScalar"),
    }
}

/// SelectScalarFhe — then-branch clear (inputs[1]), else-branch encrypted (inputs[2]).
fn exec_if_then_else_scalar_fhe(inputs: &[&RuntimeValue], sks: &crate::ServerKey) -> RuntimeValue {
    let RuntimeValue::FheBool(cond) = inputs[0] else {
        panic!("wrong input type for SelectScalarFhe condition");
    };
    let pbs = sks.pbs_key();
    match (inputs[1], inputs[2]) {
        (RuntimeValue::ClearUint(s), RuntimeValue::FheUint(e)) => {
            RuntimeValue::FheUint(pbs.if_then_else_parallelized(cond, *s, e))
        }
        (RuntimeValue::ClearInt(s), RuntimeValue::FheInt(e)) => {
            RuntimeValue::FheInt(pbs.if_then_else_parallelized(cond, *s, e))
        }
        _ => panic!("mismatched types for SelectScalarFhe"),
    }
}

/// Execute a cast between FHE types.
fn exec_cast(input: &RuntimeValue, target: FheKind, sks: &crate::ServerKey) -> RuntimeValue {
    let pbs = sks.pbs_key();
    let bits_per_block = sks.message_modulus().0.ilog2() as usize;
    // `div_ceil`: the builder normally guarantees widths are multiples of
    // `bits_per_block`, but round up defensively so a non-aligned width can't
    // silently drop the high partial block.
    match (input, target) {
        (RuntimeValue::FheBool(b), FheKind::Uint(bits)) => {
            let num_blocks = (bits as usize).div_ceil(bits_per_block);
            RuntimeValue::FheUint(b.clone().into_radix(num_blocks, pbs))
        }
        (RuntimeValue::FheBool(b), FheKind::Int(bits)) => {
            let num_blocks = (bits as usize).div_ceil(bits_per_block);
            RuntimeValue::FheInt(b.clone().into_radix(num_blocks, pbs))
        }
        (RuntimeValue::FheUint(r), FheKind::Uint(bits)) => {
            let num_blocks = (bits as usize).div_ceil(bits_per_block);
            RuntimeValue::FheUint(pbs.cast_to_unsigned(r.clone(), num_blocks))
        }
        (RuntimeValue::FheUint(r), FheKind::Int(bits)) => {
            let num_blocks = (bits as usize).div_ceil(bits_per_block);
            RuntimeValue::FheInt(pbs.cast_to_signed(r.clone(), num_blocks))
        }
        (RuntimeValue::FheInt(r), FheKind::Uint(bits)) => {
            let num_blocks = (bits as usize).div_ceil(bits_per_block);
            RuntimeValue::FheUint(pbs.cast_to_unsigned(r.clone(), num_blocks))
        }
        (RuntimeValue::FheInt(r), FheKind::Int(bits)) => {
            let num_blocks = (bits as usize).div_ceil(bits_per_block);
            RuntimeValue::FheInt(pbs.cast_to_signed(r.clone(), num_blocks))
        }
        (RuntimeValue::FheUint(r), FheKind::Bool) => {
            RuntimeValue::FheBool(pbs.scalar_ne_parallelized(r, 0u64))
        }
        (RuntimeValue::FheInt(r), FheKind::Bool) => {
            RuntimeValue::FheBool(pbs.scalar_ne_parallelized(r, 0i64))
        }
        (RuntimeValue::FheBool(b), FheKind::Bool) => RuntimeValue::FheBool(b.clone()),
        // CompressedList / KVStore / ClearBool inputs are rejected by the
        // dialect signature (`from` is `FheKind`).
        _ => panic!("invalid input variant for FheCast: {input:?}"),
    }
}

/// Execute the EncryptTrivial op: produce a trivially-encrypted value of
/// the requested kind from a clear input.
pub(super) fn exec_trivial(
    clear: &RuntimeValue,
    kind: FheKind,
    sks: &crate::ServerKey,
) -> RuntimeValue {
    let pbs = sks.pbs_key();
    let bits_per_block = sks.message_modulus().0.ilog2() as usize;
    match (clear, kind) {
        (RuntimeValue::ClearBool(v), FheKind::Bool) => {
            RuntimeValue::FheBool(pbs.create_trivial_boolean_block(*v))
        }
        (RuntimeValue::ClearUint(v), FheKind::Uint(bits)) => RuntimeValue::FheUint(
            pbs.create_trivial_radix(*v, (bits as usize).div_ceil(bits_per_block)),
        ),
        (RuntimeValue::ClearInt(v), FheKind::Int(bits)) => RuntimeValue::FheInt(
            pbs.create_trivial_radix(*v, (bits as usize).div_ceil(bits_per_block)),
        ),
        _ => panic!("unsupported trivial encrypt combination: {clear:?} as {kind:?}"),
    }
}

/// Cast a (possibly variable-width) `RadixCiphertext` result from a
/// bit-counting / log op to the `FheUint32`-sized radix that HL surfaces use.
/// Centralizes the `cast_to_unsigned(_, 32-bits-worth-of-blocks)` pattern.
fn cast_to_fhe_uint32(sks: &crate::ServerKey, raw: RadixCiphertext) -> RadixCiphertext {
    let bits_per_block = sks.message_modulus().0.ilog2() as usize;
    let num_blocks = 32usize.div_ceil(bits_per_block);
    sks.pbs_key().cast_to_unsigned(raw, num_blocks)
}

/// Execute a scalar equality op (eq/ne) returning a `Bool`. Like
/// `exec_scalar_cmp` but also handles `Bool` operands.
fn exec_scalar_eq(
    input: &RuntimeValue,
    scalar: &ScalarValue,
    unsigned_op: impl FnOnce(&RadixCiphertext, u128) -> BooleanBlock,
    signed_op: impl FnOnce(&SignedRadixCiphertext, i128) -> BooleanBlock,
    bool_op: impl FnOnce(&BooleanBlock, bool) -> BooleanBlock,
) -> RuntimeValue {
    let block = match (input, scalar) {
        (RuntimeValue::FheUint(v), ScalarValue::Unsigned(s)) => unsigned_op(v, *s),
        (RuntimeValue::FheInt(v), ScalarValue::Signed(s)) => signed_op(v, *s),
        (RuntimeValue::FheBool(v), ScalarValue::Bool(s)) => bool_op(v, *s),
        _ => panic!("mismatched scalar/ciphertext type for scalar eq"),
    };
    RuntimeValue::FheBool(block)
}

fn exec_compress(
    inputs: &[&RuntimeValue],
    sks: &crate::ServerKey,
) -> Result<crate::CompressedCiphertextList, CpuError> {
    let compression_key = sks
        .compression_key()
        .ok_or(CpuError::MissingCompressionKey)?;

    let mut builder = crate::integer::ciphertext::CompressedCiphertextListBuilder::new();
    for input in inputs {
        match input {
            RuntimeValue::FheBool(b) => builder.push(b.clone()),
            RuntimeValue::FheUint(r) => builder.push(r.clone()),
            RuntimeValue::FheInt(r) => builder.push(r.clone()),
            _ => {
                return Err(CpuError::CompressionError(format!(
                    "cannot compress a {input:?} into a CompressedList"
                )));
            }
        };
    }

    let list = builder.build(compression_key);
    let len = list.len();
    let list = crate::CompressedCiphertextList::from_raw_parts(
        list,
        Tag::default(),
        vec![ReRandomizationMetadata::default(); len],
    );
    Ok(list)
}

fn exec_decompress(
    sks: &crate::ServerKey,
    inputs: &[&RuntimeValue],
    picks: &[(u32, FheKind)],
    outputs: &mut Vec<RuntimeValue>,
) -> Result<(), CpuError> {
    let decompression_key = sks
        .decompression_key()
        .ok_or(CpuError::MissingDecompressionKey)?;

    let RuntimeValue::CompressedList(list) = inputs[0] else {
        return Err(CpuError::DecompressionError(
            "invalid exec value, expected a compressed list".to_string(),
        ));
    };

    let integer_list = list.clone().into_raw_parts().0;

    for &(index, output_type) in picks {
        let idx = index as usize;
        match output_type {
            FheKind::Uint(n_bits) => {
                let radix = integer_list
                    .get::<RadixCiphertext>(idx, decompression_key)
                    .map_err(|e| {
                        CpuError::DecompressionError(format!(
                            "failed to decompress unsigned value at index {idx}: {e:?}"
                        ))
                    })?
                    .ok_or_else(|| {
                        CpuError::DecompressionError(format!("no value at index {idx}"))
                    })?;

                let actual_n_bits = radix.blocks.len() as u32 * sks.message_modulus().0.ilog2();
                if actual_n_bits != n_bits {
                    return Err(CpuError::DecompressionError(format!(
                        "Mismatched number of bits, expected {n_bits}, got {actual_n_bits}",
                    )));
                }

                outputs.push(radix.into());
            }
            FheKind::Int(n_bits) => {
                let radix = integer_list
                    .get::<SignedRadixCiphertext>(idx, decompression_key)
                    .map_err(|e| {
                        CpuError::DecompressionError(format!(
                            "failed to decompress signed value at index {idx}: {e:?}"
                        ))
                    })?
                    .ok_or_else(|| {
                        CpuError::DecompressionError(format!("no value at index {idx}"))
                    })?;
                let actual_n_bits = radix.blocks.len() as u32 * sks.message_modulus().0.ilog2();
                if actual_n_bits != n_bits {
                    return Err(CpuError::DecompressionError(format!(
                        "Mismatched number of bits, expected {n_bits}, got {actual_n_bits}",
                    )));
                }
                outputs.push(radix.into());
            }
            FheKind::Bool => {
                let block = integer_list
                    .get::<BooleanBlock>(idx, decompression_key)
                    .map_err(|e| {
                        CpuError::DecompressionError(format!(
                            "failed to decompress bool value at index {idx}: {e:?}"
                        ))
                    })?
                    .ok_or_else(|| {
                        CpuError::DecompressionError(format!("missing bool value at index {idx}"))
                    })?;
                outputs.push(block.into());
            }
        }
    }

    Ok(())
}

// =========================================================================

/// Dispatch one op against the dialect.
///
/// Workers wrap this in `catch_unwind` so any internal `panic!` (type-mismatch invariants, FHE
/// bugs) surfaces as a `CpuError::ExecutionError` instead of taking down
/// the whole executor.
pub(super) fn exec_dialect_op(
    sks: &crate::ServerKey,
    op: &HlInstructionSet,
    inputs_arc: &mut Vec<Arc<RuntimeValue>>,
    outputs: &mut Vec<RuntimeValue>,
) -> Result<(), CpuError> {
    // Mutating KVStore arms run first so they can take Arc ownership.
    // The read-only `inputs` view built below borrows `inputs_arc`, which
    // would block the move.
    //
    // Fast path: the mutating op is the sole owner of the store version
    // (the builder's use-after-move rule plus the executor's `waiter_of_op`
    // barrier make this the common case). The Arc can still be shared when
    // the same store version is also a circuit output (`program_outputs`
    // keeps a reference for the whole run); cloning then preserves the
    // output's snapshot while this op mutates its own copy.
    fn take_store(store_arc: Arc<RuntimeValue>) -> RuntimeValue {
        Arc::try_unwrap(store_arc).unwrap_or_else(|shared| (*shared).clone())
    }
    match op {
        HlInstructionSet::KVStoreInsertWithClearKey { clear_key, .. } => {
            let value_arc = inputs_arc.pop().unwrap();
            let store_arc = inputs_arc.pop().unwrap();
            let store_ev = take_store(store_arc);
            let key_u128 = clear_key.as_u128();
            let new_store_ev = match store_ev {
                RuntimeValue::FheUintKVStore(mut kv) => {
                    let RuntimeValue::FheUint(v) = &*value_arc else {
                        panic!("KVStoreInsertWithClearKey: expected FheUint value")
                    };
                    kv.insert(key_u128, v.clone());
                    RuntimeValue::FheUintKVStore(kv)
                }
                RuntimeValue::FheIntKVStore(mut kv) => {
                    let RuntimeValue::FheInt(v) = &*value_arc else {
                        panic!("KVStoreInsertWithClearKey: expected FheInt value")
                    };
                    kv.insert(key_u128, v.clone());
                    RuntimeValue::FheIntKVStore(kv)
                }
                _ => panic!("KVStoreInsertWithClearKey: expected KVStore as first input"),
            };
            outputs.push(new_store_ev);
            return Ok(());
        }
        HlInstructionSet::KVStoreRemoveWithClearKey { clear_key, .. } => {
            let store_arc = inputs_arc.pop().unwrap();
            let store_ev = take_store(store_arc);
            let key_u128 = clear_key.as_u128();
            let new_store_ev = match store_ev {
                RuntimeValue::FheUintKVStore(mut kv) => {
                    kv.remove(&key_u128);
                    RuntimeValue::FheUintKVStore(kv)
                }
                RuntimeValue::FheIntKVStore(mut kv) => {
                    kv.remove(&key_u128);
                    RuntimeValue::FheIntKVStore(kv)
                }
                _ => panic!("KVStoreRemoveWithClearKey: expected KVStore as first input"),
            };
            outputs.push(new_store_ev);
            return Ok(());
        }
        HlInstructionSet::KVStoreUpdate { .. } => {
            let new_value_arc = inputs_arc.pop().unwrap();
            let encrypted_key_arc = inputs_arc.pop().unwrap();
            let store_arc = inputs_arc.pop().unwrap();
            let store_ev = take_store(store_arc);
            let RuntimeValue::FheUint(encrypted_key) = &*encrypted_key_arc else {
                panic!("KVStoreUpdate: expected FheUint encrypted key")
            };
            let (new_store_ev, present) = match store_ev {
                RuntimeValue::FheUintKVStore(mut kv) => {
                    let RuntimeValue::FheUint(new_value) = &*new_value_arc else {
                        panic!("KVStoreUpdate: expected FheUint value")
                    };
                    let present = sks
                        .pbs_key()
                        .kv_store_update(&mut kv, encrypted_key, new_value);
                    (RuntimeValue::FheUintKVStore(kv), present)
                }
                RuntimeValue::FheIntKVStore(mut kv) => {
                    let RuntimeValue::FheInt(new_value) = &*new_value_arc else {
                        panic!("KVStoreUpdate: expected FheInt value")
                    };
                    // The dialect's encrypted_key arg is always `FheUint(N)`
                    // (= `RadixCiphertext`), but `kv_store_update<_, SignedRadixCiphertext>`
                    // needs `&SignedRadixCiphertext`. Build a temporary view over the
                    // same blocks — `compute_equality_selectors` does bit-pattern
                    // equality, so the signedness label on the wrapper doesn't matter.
                    let signed_key = SignedRadixCiphertext::from(encrypted_key.blocks.clone());
                    let present = sks
                        .pbs_key()
                        .kv_store_update(&mut kv, &signed_key, new_value);
                    (RuntimeValue::FheIntKVStore(kv), present)
                }
                _ => panic!("KVStoreUpdate: expected KVStore as first input"),
            };
            outputs.push(new_store_ev);
            outputs.push(RuntimeValue::FheBool(present));
            return Ok(());
        }
        _ => {}
    }

    // Read-only view used by every non-mutating arm.
    let inputs_owned: Vec<&RuntimeValue> = inputs_arc.iter().map(|a| a.as_ref()).collect();
    let inputs: &[&RuntimeValue] = &inputs_owned;
    match op {
        HlInstructionSet::Input { .. } | HlInstructionSet::Output { .. } => {
            unreachable!("Input/Output ops are handled by the coordinator, not workers")
        }
        HlInstructionSet::EncryptTrivial { kind } => {
            outputs.push(exec_trivial(inputs[0], *kind, sks));
            Ok(())
        }
        HlInstructionSet::Constant { .. } => {
            unreachable!(
                "Constant ops are materialized by the coordinator's seed phase, not workers"
            )
        }
        HlInstructionSet::FheAdd { kind: _ } => {
            outputs.push(exec_binary_op(
                inputs,
                |lhs, rhs| sks.pbs_key().add_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().add_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheSub { kind: _ } => {
            outputs.push(exec_binary_op(
                inputs,
                |lhs, rhs| sks.pbs_key().sub_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().sub_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheGe { kind: _ } => {
            outputs.push(exec_binary_cmp(
                inputs,
                |lhs, rhs| sks.pbs_key().ge_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().ge_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::Select { kind: _ } => {
            outputs.push(exec_if_then_else(inputs, sks));
            Ok(())
        }
        HlInstructionSet::FheFlip { kind: _ } => {
            let RuntimeValue::FheBool(cond) = inputs[0] else {
                panic!("Flip condition must be FheBool");
            };
            match (inputs[1], inputs[2]) {
                (RuntimeValue::FheUint(a), RuntimeValue::FheUint(b)) => {
                    let (x, y) = sks.pbs_key().flip_parallelized(cond, a, b);
                    outputs.push(RuntimeValue::FheUint(x));
                    outputs.push(RuntimeValue::FheUint(y));
                }
                (RuntimeValue::FheInt(a), RuntimeValue::FheInt(b)) => {
                    let (x, y) = sks.pbs_key().flip_parallelized(cond, a, b);
                    outputs.push(RuntimeValue::FheInt(x));
                    outputs.push(RuntimeValue::FheInt(y));
                }
                _ => panic!("mismatched or invalid input types for FheFlip"),
            }
            Ok(())
        }
        HlInstructionSet::SelectScalarScalar { kind } => {
            outputs.push(exec_if_then_else_scalar_scalar(inputs, *kind, sks));
            Ok(())
        }
        HlInstructionSet::SelectFheScalar { kind: _ } => {
            outputs.push(exec_if_then_else_fhe_scalar(inputs, sks));
            Ok(())
        }
        HlInstructionSet::SelectScalarFhe { kind: _ } => {
            outputs.push(exec_if_then_else_scalar_fhe(inputs, sks));
            Ok(())
        }
        HlInstructionSet::FheMul { kind: _ } => {
            outputs.push(exec_binary_op(
                inputs,
                |lhs, rhs| sks.pbs_key().mul_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().mul_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheBitOr { kind: _ } => {
            outputs.push(exec_binary_bitwise_op(
                inputs,
                |lhs, rhs| sks.pbs_key().bitor_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().bitor_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().boolean_bitor(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheNot { kind: _ } => {
            let result = match inputs[0] {
                RuntimeValue::FheUint(v) => RuntimeValue::FheUint(sks.pbs_key().bitnot(v)),
                RuntimeValue::FheInt(v) => RuntimeValue::FheInt(sks.pbs_key().bitnot(v)),
                RuntimeValue::FheBool(v) => RuntimeValue::FheBool(sks.pbs_key().boolean_bitnot(v)),
                _ => panic!("FheNot not supported on this kind"),
            };
            outputs.push(result);
            Ok(())
        }
        HlInstructionSet::FheCast { from: _, to } => {
            outputs.push(exec_cast(inputs[0], *to, sks));
            Ok(())
        }
        HlInstructionSet::FheOverflowingAdd { kind: _ } => {
            let (result, overflow) = exec_overflowing_op(
                inputs,
                |lhs, rhs| sks.pbs_key().overflowing_add_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().overflowing_add_parallelized(lhs, rhs),
            );
            outputs.push(result);
            outputs.push(overflow);
            Ok(())
        }
        HlInstructionSet::FheOverflowingSub { kind: _ } => {
            let (result, overflow) = exec_overflowing_op(
                inputs,
                |lhs, rhs| {
                    sks.pbs_key()
                        .unsigned_overflowing_sub_parallelized(lhs, rhs)
                },
                |lhs, rhs| sks.pbs_key().signed_overflowing_sub_parallelized(lhs, rhs),
            );
            outputs.push(result);
            outputs.push(overflow);
            Ok(())
        }
        HlInstructionSet::FheOverflowingMul { kind: _ } => {
            let (result, overflow) = exec_overflowing_op(
                inputs,
                |lhs, rhs| {
                    sks.pbs_key()
                        .unsigned_overflowing_mul_parallelized(lhs, rhs)
                },
                |lhs, rhs| sks.pbs_key().signed_overflowing_mul_parallelized(lhs, rhs),
            );
            outputs.push(result);
            outputs.push(overflow);
            Ok(())
        }
        HlInstructionSet::FheOverflowingNeg { kind: _ } => {
            let (result, overflow) = match inputs[0] {
                RuntimeValue::FheUint(v) => {
                    let (r, b) = sks.pbs_key().overflowing_neg_parallelized(v);
                    (RuntimeValue::FheUint(r), RuntimeValue::FheBool(b))
                }
                RuntimeValue::FheInt(v) => {
                    let (r, b) = sks.pbs_key().overflowing_neg_parallelized(v);
                    (RuntimeValue::FheInt(r), RuntimeValue::FheBool(b))
                }
                _ => panic!("FheOverflowingNeg only supports integer types"),
            };
            outputs.push(result);
            outputs.push(overflow);
            Ok(())
        }
        HlInstructionSet::FheScalarOverflowingAdd { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            let (result, overflow) = match (inputs[0], &scalar) {
                (RuntimeValue::FheUint(v), ScalarValue::Unsigned(s)) => {
                    let (r, b) = sks
                        .pbs_key()
                        .unsigned_overflowing_scalar_add_parallelized(v, *s);
                    (RuntimeValue::FheUint(r), RuntimeValue::FheBool(b))
                }
                (RuntimeValue::FheInt(v), ScalarValue::Signed(s)) => {
                    let (r, b) = sks
                        .pbs_key()
                        .signed_overflowing_scalar_add_parallelized(v, *s);
                    (RuntimeValue::FheInt(r), RuntimeValue::FheBool(b))
                }
                _ => panic!("FheScalarOverflowingAdd: kind / scalar sign mismatch"),
            };
            outputs.push(result);
            outputs.push(overflow);
            Ok(())
        }
        HlInstructionSet::FheScalarOverflowingSub { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            let (result, overflow) = match (inputs[0], &scalar) {
                (RuntimeValue::FheUint(v), ScalarValue::Unsigned(s)) => {
                    let (r, b) = sks
                        .pbs_key()
                        .unsigned_overflowing_scalar_sub_parallelized(v, *s);
                    (RuntimeValue::FheUint(r), RuntimeValue::FheBool(b))
                }
                (RuntimeValue::FheInt(v), ScalarValue::Signed(s)) => {
                    let (r, b) = sks
                        .pbs_key()
                        .signed_overflowing_scalar_sub_parallelized(v, *s);
                    (RuntimeValue::FheInt(r), RuntimeValue::FheBool(b))
                }
                _ => panic!("FheScalarOverflowingSub: kind / scalar sign mismatch"),
            };
            outputs.push(result);
            outputs.push(overflow);
            Ok(())
        }
        HlInstructionSet::FheDivRem { kind: _ } => {
            let (q, r) = match (inputs[0], inputs[1]) {
                (RuntimeValue::FheUint(a), RuntimeValue::FheUint(b)) => {
                    let (q, r) = sks.pbs_key().div_rem_parallelized(a, b);
                    (RuntimeValue::FheUint(q), RuntimeValue::FheUint(r))
                }
                (RuntimeValue::FheInt(a), RuntimeValue::FheInt(b)) => {
                    let (q, r) = sks.pbs_key().div_rem_parallelized(a, b);
                    (RuntimeValue::FheInt(q), RuntimeValue::FheInt(r))
                }
                _ => panic!("FheDivRem: mismatched or unsupported input kinds"),
            };
            outputs.push(q);
            outputs.push(r);
            Ok(())
        }
        HlInstructionSet::FheDiv { kind: _ } => {
            outputs.push(exec_binary_op(
                inputs,
                |lhs, rhs| sks.pbs_key().div_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().div_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheRem { kind: _ } => {
            outputs.push(exec_binary_op(
                inputs,
                |lhs, rhs| sks.pbs_key().rem_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().rem_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheMin { kind: _ } => {
            outputs.push(exec_binary_op(
                inputs,
                |lhs, rhs| sks.pbs_key().min_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().min_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheMax { kind: _ } => {
            outputs.push(exec_binary_op(
                inputs,
                |lhs, rhs| sks.pbs_key().max_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().max_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheNeg { kind: _ } => {
            let result = match inputs[0] {
                RuntimeValue::FheUint(v) => {
                    RuntimeValue::FheUint(sks.pbs_key().neg_parallelized(v))
                }
                RuntimeValue::FheInt(v) => RuntimeValue::FheInt(sks.pbs_key().neg_parallelized(v)),
                _ => panic!("FheNeg only supports integer types"),
            };
            outputs.push(result);
            Ok(())
        }
        HlInstructionSet::FheIsEven { kind: _ } => {
            let bb = match inputs[0] {
                RuntimeValue::FheUint(v) => sks.pbs_key().is_even_parallelized(v),
                RuntimeValue::FheInt(v) => sks.pbs_key().is_even_parallelized(v),
                _ => panic!("FheIsEven only supports integer types"),
            };
            outputs.push(RuntimeValue::FheBool(bb));
            Ok(())
        }
        HlInstructionSet::FheIsOdd { kind: _ } => {
            let bb = match inputs[0] {
                RuntimeValue::FheUint(v) => sks.pbs_key().is_odd_parallelized(v),
                RuntimeValue::FheInt(v) => sks.pbs_key().is_odd_parallelized(v),
                _ => panic!("FheIsOdd only supports integer types"),
            };
            outputs.push(RuntimeValue::FheBool(bb));
            Ok(())
        }
        HlInstructionSet::FheLeadingZeros { kind: _ } => {
            let raw = match inputs[0] {
                RuntimeValue::FheUint(v) => sks.pbs_key().leading_zeros_parallelized(v),
                RuntimeValue::FheInt(v) => sks.pbs_key().leading_zeros_parallelized(v),
                _ => panic!("FheLeadingZeros only supports integer types"),
            };
            outputs.push(RuntimeValue::FheUint(cast_to_fhe_uint32(sks, raw)));
            Ok(())
        }
        HlInstructionSet::FheLeadingOnes { kind: _ } => {
            let raw = match inputs[0] {
                RuntimeValue::FheUint(v) => sks.pbs_key().leading_ones_parallelized(v),
                RuntimeValue::FheInt(v) => sks.pbs_key().leading_ones_parallelized(v),
                _ => panic!("FheLeadingOnes only supports integer types"),
            };
            outputs.push(RuntimeValue::FheUint(cast_to_fhe_uint32(sks, raw)));
            Ok(())
        }
        HlInstructionSet::FheTrailingZeros { kind: _ } => {
            let raw = match inputs[0] {
                RuntimeValue::FheUint(v) => sks.pbs_key().trailing_zeros_parallelized(v),
                RuntimeValue::FheInt(v) => sks.pbs_key().trailing_zeros_parallelized(v),
                _ => panic!("FheTrailingZeros only supports integer types"),
            };
            outputs.push(RuntimeValue::FheUint(cast_to_fhe_uint32(sks, raw)));
            Ok(())
        }
        HlInstructionSet::FheTrailingOnes { kind: _ } => {
            let raw = match inputs[0] {
                RuntimeValue::FheUint(v) => sks.pbs_key().trailing_ones_parallelized(v),
                RuntimeValue::FheInt(v) => sks.pbs_key().trailing_ones_parallelized(v),
                _ => panic!("FheTrailingOnes only supports integer types"),
            };
            outputs.push(RuntimeValue::FheUint(cast_to_fhe_uint32(sks, raw)));
            Ok(())
        }
        HlInstructionSet::FheCountOnes { kind: _ } => {
            let raw = match inputs[0] {
                RuntimeValue::FheUint(v) => sks.pbs_key().count_ones_parallelized(v),
                RuntimeValue::FheInt(v) => sks.pbs_key().count_ones_parallelized(v),
                _ => panic!("FheCountOnes only supports integer types"),
            };
            outputs.push(RuntimeValue::FheUint(cast_to_fhe_uint32(sks, raw)));
            Ok(())
        }
        HlInstructionSet::FheCountZeros { kind: _ } => {
            let raw = match inputs[0] {
                RuntimeValue::FheUint(v) => sks.pbs_key().count_zeros_parallelized(v),
                RuntimeValue::FheInt(v) => sks.pbs_key().count_zeros_parallelized(v),
                _ => panic!("FheCountZeros only supports integer types"),
            };
            outputs.push(RuntimeValue::FheUint(cast_to_fhe_uint32(sks, raw)));
            Ok(())
        }
        HlInstructionSet::FheIlog2 { kind: _ } => {
            let raw = match inputs[0] {
                RuntimeValue::FheUint(v) => sks.pbs_key().ilog2_parallelized(v),
                RuntimeValue::FheInt(v) => sks.pbs_key().ilog2_parallelized(v),
                _ => panic!("FheIlog2 only supports integer types"),
            };
            outputs.push(RuntimeValue::FheUint(cast_to_fhe_uint32(sks, raw)));
            Ok(())
        }
        HlInstructionSet::FheCheckedIlog2 { kind: _ } => {
            let (raw, bb) = match inputs[0] {
                RuntimeValue::FheUint(v) => sks.pbs_key().checked_ilog2_parallelized(v),
                RuntimeValue::FheInt(v) => sks.pbs_key().checked_ilog2_parallelized(v),
                _ => panic!("FheCheckedIlog2 only supports integer types"),
            };
            outputs.push(RuntimeValue::FheUint(cast_to_fhe_uint32(sks, raw)));
            outputs.push(RuntimeValue::FheBool(bb));
            Ok(())
        }
        HlInstructionSet::FheReverseBits { kind: _ } => {
            let result = match inputs[0] {
                RuntimeValue::FheUint(v) => {
                    RuntimeValue::FheUint(sks.pbs_key().reverse_bits_parallelized(v))
                }
                RuntimeValue::FheInt(v) => {
                    RuntimeValue::FheInt(sks.pbs_key().reverse_bits_parallelized(v))
                }
                _ => panic!("FheReverseBits only supports integer types"),
            };
            outputs.push(result);
            Ok(())
        }
        HlInstructionSet::FheAbs { kind: _ } => {
            // Builder rejects Uint(_); executor defensively checks anyway since
            // direct IR manipulation could theoretically bypass the builder.
            let result = match inputs[0] {
                RuntimeValue::FheInt(v) => RuntimeValue::FheInt(sks.pbs_key().abs_parallelized(v)),
                _ => panic!("FheAbs only supports signed integer types"),
            };
            outputs.push(result);
            Ok(())
        }
        HlInstructionSet::FheSum { kind, n: _ } => {
            // Dispatch on the dialect's `kind` (FheIntKind) — no need to look at
            // `output_kinds` since the variant carries the type tag inline.
            let result = match kind {
                FheIntKind::Uint(_) => {
                    let elems: Vec<RadixCiphertext> = inputs
                        .iter()
                        .map(|input| match input {
                            RuntimeValue::FheUint(v) => v.clone(),
                            _ => panic!("FheSum cannot mix input types"),
                        })
                        .collect();
                    let r = sks.pbs_key().sum_ciphertexts_parallelized(&elems).unwrap();
                    RuntimeValue::FheUint(r)
                }
                FheIntKind::Int(_) => {
                    let elems: Vec<SignedRadixCiphertext> = inputs
                        .iter()
                        .map(|input| match input {
                            RuntimeValue::FheInt(v) => v.clone(),
                            _ => panic!("FheSum cannot mix input types"),
                        })
                        .collect();
                    let r = sks.pbs_key().sum_ciphertexts_parallelized(&elems).unwrap();
                    RuntimeValue::FheInt(r)
                }
            };
            outputs.push(result);
            Ok(())
        }
        HlInstructionSet::FheBitAnd { kind: _ } => {
            outputs.push(exec_binary_bitwise_op(
                inputs,
                |lhs, rhs| sks.pbs_key().bitand_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().bitand_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().boolean_bitand(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheBitXor { kind: _ } => {
            outputs.push(exec_binary_bitwise_op(
                inputs,
                |lhs, rhs| sks.pbs_key().bitxor_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().bitxor_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().boolean_bitxor(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheEq { kind: _ } => {
            outputs.push(exec_binary_eq(
                inputs,
                |lhs, rhs| sks.pbs_key().eq_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().eq_parallelized(lhs, rhs),
                // bool eq = NOT(XOR)
                |lhs, rhs| {
                    let xor = sks.pbs_key().boolean_bitxor(lhs, rhs);
                    sks.pbs_key().boolean_bitnot(&xor)
                },
            ));
            Ok(())
        }
        HlInstructionSet::FheNe { kind: _ } => {
            outputs.push(exec_binary_eq(
                inputs,
                |lhs, rhs| sks.pbs_key().ne_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().ne_parallelized(lhs, rhs),
                // bool ne = XOR
                |lhs, rhs| sks.pbs_key().boolean_bitxor(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheLt { kind: _ } => {
            outputs.push(exec_binary_cmp(
                inputs,
                |lhs, rhs| sks.pbs_key().lt_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().lt_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheLe { kind: _ } => {
            outputs.push(exec_binary_cmp(
                inputs,
                |lhs, rhs| sks.pbs_key().le_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().le_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheGt { kind: _ } => {
            outputs.push(exec_binary_cmp(
                inputs,
                |lhs, rhs| sks.pbs_key().gt_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().gt_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheShl {
            lhs_kind: _,
            rhs_bits: _,
        } => {
            outputs.push(exec_shift_op(
                inputs,
                |lhs, rhs| sks.pbs_key().left_shift_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().left_shift_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheShr {
            lhs_kind: _,
            rhs_bits: _,
        } => {
            outputs.push(exec_shift_op(
                inputs,
                |lhs, rhs| sks.pbs_key().right_shift_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().right_shift_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheRotateLeft {
            lhs_kind: _,
            rhs_bits: _,
        } => {
            outputs.push(exec_shift_op(
                inputs,
                |lhs, rhs| sks.pbs_key().rotate_left_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().rotate_left_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheRotateRight {
            lhs_kind: _,
            rhs_bits: _,
        } => {
            outputs.push(exec_shift_op(
                inputs,
                |lhs, rhs| sks.pbs_key().rotate_right_parallelized(lhs, rhs),
                |lhs, rhs| sks.pbs_key().rotate_right_parallelized(lhs, rhs),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarAdd { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_add_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_add_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarSub { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_sub_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_sub_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::ScalarFheSub { kind: _ } => {
            // clear - fhe = (-fhe) + clear
            // clear operand is first (inputs[0]); fhe is second (inputs[1])
            let scalar = inputs[0].as_clear_scalar();
            outputs.push(exec_scalar_op(
                inputs[1],
                &scalar,
                |v, s| {
                    let neg = sks.pbs_key().neg_parallelized(v);
                    sks.pbs_key().scalar_add_parallelized(&neg, s)
                },
                |v, s| {
                    let neg = sks.pbs_key().neg_parallelized(v);
                    sks.pbs_key().scalar_add_parallelized(&neg, s)
                },
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarMul { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_mul_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_mul_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarDiv { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_div_parallelized(v, s),
                |v, s| sks.pbs_key().signed_scalar_div_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarRem { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_rem_parallelized(v, s),
                |v, s| sks.pbs_key().signed_scalar_rem_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarMin { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_min_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_min_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarMax { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_max_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_max_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarShl { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_left_shift_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_left_shift_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarShr { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_right_shift_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_right_shift_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarRotateLeft { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_rotate_left_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_rotate_left_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarRotateRight { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_rotate_right_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_rotate_right_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarBitAnd { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_bitwise_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_bitand_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_bitand_parallelized(v, s),
                // bool & true = v ; bool & false = false
                |v, s| {
                    if s {
                        v.clone()
                    } else {
                        sks.pbs_key().create_trivial_boolean_block(false)
                    }
                },
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarBitOr { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_bitwise_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_bitor_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_bitor_parallelized(v, s),
                // bool | true = true ; bool | false = v
                |v, s| {
                    if s {
                        sks.pbs_key().create_trivial_boolean_block(true)
                    } else {
                        v.clone()
                    }
                },
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarBitXor { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_bitwise_op(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_bitxor_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_bitxor_parallelized(v, s),
                // bool ^ true = NOT(v) ; bool ^ false = v
                |v, s| {
                    if s {
                        sks.pbs_key().boolean_bitnot(v)
                    } else {
                        v.clone()
                    }
                },
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarEq { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_eq(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_eq_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_eq_parallelized(v, s),
                // bool == true = v ; bool == false = NOT(v)
                |v, s| {
                    if s {
                        v.clone()
                    } else {
                        sks.pbs_key().boolean_bitnot(v)
                    }
                },
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarNe { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_eq(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_ne_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_ne_parallelized(v, s),
                // bool != true = NOT(v) ; bool != false = v
                |v, s| {
                    if s {
                        sks.pbs_key().boolean_bitnot(v)
                    } else {
                        v.clone()
                    }
                },
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarLt { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_cmp(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_lt_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_lt_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarLe { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_cmp(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_le_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_le_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarGt { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_cmp(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_gt_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_gt_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::FheScalarGe { kind: _ } => {
            let scalar = inputs[1].as_clear_scalar();
            outputs.push(exec_scalar_cmp(
                inputs[0],
                &scalar,
                |v, s| sks.pbs_key().scalar_ge_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_ge_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::ScalarFheLt { kind: _ } => {
            // clear < fhe ≡ fhe > clear. Clear is inputs[0], fhe is inputs[1].
            let scalar = inputs[0].as_clear_scalar();
            outputs.push(exec_scalar_cmp(
                inputs[1],
                &scalar,
                |v, s| sks.pbs_key().scalar_gt_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_gt_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::ScalarFheLe { kind: _ } => {
            // clear <= fhe ≡ fhe >= clear
            let scalar = inputs[0].as_clear_scalar();
            outputs.push(exec_scalar_cmp(
                inputs[1],
                &scalar,
                |v, s| sks.pbs_key().scalar_ge_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_ge_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::ScalarFheGt { kind: _ } => {
            // clear > fhe ≡ fhe < clear
            let scalar = inputs[0].as_clear_scalar();
            outputs.push(exec_scalar_cmp(
                inputs[1],
                &scalar,
                |v, s| sks.pbs_key().scalar_lt_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_lt_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::ScalarFheGe { kind: _ } => {
            // clear >= fhe ≡ fhe <= clear
            let scalar = inputs[0].as_clear_scalar();
            outputs.push(exec_scalar_cmp(
                inputs[1],
                &scalar,
                |v, s| sks.pbs_key().scalar_le_parallelized(v, s),
                |v, s| sks.pbs_key().scalar_le_parallelized(v, s),
            ));
            Ok(())
        }
        HlInstructionSet::Compress { input_kinds: _ } => {
            let r = exec_compress(inputs, sks)?;
            outputs.push(r.into());
            Ok(())
        }
        HlInstructionSet::Decompress { picks } => exec_decompress(sks, inputs, picks, outputs),
        HlInstructionSet::MatchValue { lut, .. } => match &inputs[0] {
            RuntimeValue::FheUint(ct) => {
                let (result, matched) = sks.pbs_key().match_value_parallelized(ct, lut);
                outputs.push(result.into());
                outputs.push(matched.into());
                Ok(())
            }
            _ => panic!("Invalid inputs for match value"),
        },
        HlInstructionSet::FheOprf { value_kind, mode } => {
            let RuntimeValue::Seed(seed) = inputs[0] else {
                panic!("FheOprf expects a Seed input, got {:?}", inputs[0])
            };
            let oprf = sks.oprf_key();
            let pbs = sks.pbs_key();
            let message_modulus = sks.message_modulus();
            let bits_per_block = message_modulus.0.ilog2() as usize;
            let result = match (value_kind, mode) {
                (ValueKind::FheUint(n), OprfMode::Full) => {
                    let num_blocks = n.div_ceil(bits_per_block) as u64;
                    let ct = oprf.par_generate_oblivious_pseudo_random_unsigned_integer(
                        seed.clone(),
                        num_blocks,
                        pbs,
                    );
                    RuntimeValue::FheUint(ct)
                }
                (ValueKind::FheUint(n), OprfMode::Bounded { bits }) => {
                    let num_blocks = n.div_ceil(bits_per_block) as u64;
                    let ct = oprf.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                        seed.clone(),
                        *bits,
                        num_blocks,
                        pbs,
                    );
                    RuntimeValue::FheUint(ct)
                }
                (
                    ValueKind::FheUint(n),
                    OprfMode::CustomRange {
                        upper,
                        max_distance,
                    },
                ) => {
                    let num_blocks = n.div_ceil(bits_per_block) as u64;
                    let num_input_random_bits = num_input_random_bits_for_max_distance(
                        *upper,
                        max_distance.map_or(2_f64.powi(-128), NonNanF64::get),
                        message_modulus,
                    );
                    let ct = oprf.par_generate_oblivious_pseudo_random_unsigned_custom_range(
                        seed.clone(),
                        num_input_random_bits,
                        *upper,
                        num_blocks,
                        pbs,
                    );
                    RuntimeValue::FheUint(ct)
                }
                (ValueKind::FheInt(n), OprfMode::Full) => {
                    let num_blocks = n.div_ceil(bits_per_block) as u64;
                    let ct = oprf.par_generate_oblivious_pseudo_random_signed_integer(
                        seed.clone(),
                        num_blocks,
                        pbs,
                    );
                    RuntimeValue::FheInt(ct)
                }
                (ValueKind::FheInt(n), OprfMode::Bounded { bits }) => {
                    let num_blocks = n.div_ceil(bits_per_block) as u64;
                    let ct = oprf.par_generate_oblivious_pseudo_random_signed_integer_bounded(
                        seed.clone(),
                        *bits,
                        num_blocks,
                        pbs,
                    );
                    RuntimeValue::FheInt(ct)
                }
                (ValueKind::FheBool, OprfMode::Full) => {
                    let ct_vec = oprf.key.generate_oblivious_pseudo_random_bits_chunks(
                        seed.clone(),
                        &[1],
                        &pbs.key,
                    );

                    // We have to do the double unwrap, we want to keep as little primitives as
                    // possible for PRF since they also need a
                    // rerandomized_variant, so we don't have a single
                    // block primitive for that
                    let ct = ct_vec
                        .into_iter()
                        .next()
                        .expect("A single chunk was expected, got 0")
                        .into_iter()
                        .next()
                        .expect("A single ciphertext was expected, got 0");

                    RuntimeValue::FheBool(BooleanBlock::new_unchecked(ct))
                }
                _ => {
                    unreachable!("Invalid combination got value_kind={value_kind:?}, mode={mode:?}")
                }
            };
            outputs.push(result);
            Ok(())
        }
        HlInstructionSet::FheContains { kind, n: _ } => {
            let needle = inputs[0];
            let haystack = &inputs[1..];
            let pbs = sks.pbs_key();
            let result = match kind {
                FheIntKind::Uint(_) => {
                    let RuntimeValue::FheUint(needle) = needle else {
                        panic!("FheContains needle must be Unsigned for FheIntKind::Uint")
                    };
                    let cts: Vec<RadixCiphertext> = haystack
                        .iter()
                        .map(|h| match h {
                            RuntimeValue::FheUint(v) => v.clone(),
                            _ => {
                                panic!("FheContains haystack must be Unsigned for FheIntKind::Uint")
                            }
                        })
                        .collect();
                    pbs.contains_parallelized(&cts, needle)
                }
                FheIntKind::Int(_) => {
                    let RuntimeValue::FheInt(needle) = needle else {
                        panic!("FheContains needle must be Signed for FheIntKind::Int")
                    };
                    let cts: Vec<SignedRadixCiphertext> = haystack
                        .iter()
                        .map(|h| match h {
                            RuntimeValue::FheInt(v) => v.clone(),
                            _ => panic!("FheContains haystack must be Signed for FheIntKind::Int"),
                        })
                        .collect();
                    pbs.contains_parallelized(&cts, needle)
                }
            };
            outputs.push(RuntimeValue::FheBool(result));
            Ok(())
        }
        HlInstructionSet::FheContainsScalar { kind, n: _ } => {
            let pbs = sks.pbs_key();
            // Clear needle is inputs[0], haystack is inputs[1..].
            let scalar = inputs[0].as_clear_scalar();
            let haystack = &inputs[1..];
            let result = match (kind, &scalar) {
                (FheIntKind::Uint(_), ScalarValue::Unsigned(s)) => {
                    let cts: Vec<RadixCiphertext> = haystack
                        .iter()
                        .map(|h| match h {
                            RuntimeValue::FheUint(v) => v.clone(),
                            _ => panic!(
                                "FheContainsScalar haystack must be Unsigned for FheIntKind::Uint"
                            ),
                        })
                        .collect();
                    pbs.contains_clear_parallelized(&cts, *s)
                }
                (FheIntKind::Int(_), ScalarValue::Signed(s)) => {
                    let cts: Vec<SignedRadixCiphertext> = haystack
                        .iter()
                        .map(|h| match h {
                            RuntimeValue::FheInt(v) => v.clone(),
                            _ => {
                                panic!(
                                    "FheContainsScalar haystack must be Signed for FheIntKind::Int"
                                )
                            }
                        })
                        .collect();
                    pbs.contains_clear_parallelized(&cts, *s)
                }
                _ => panic!("FheContainsScalar mismatched kind/scalar"),
            };
            outputs.push(RuntimeValue::FheBool(result));
            Ok(())
        }
        HlInstructionSet::KVStoreCreate {
            key_kind: _,
            value_kind,
        } => {
            let store = match value_kind {
                FheIntKind::Uint(_) => RuntimeValue::FheUintKVStore(KVStore::new()),
                FheIntKind::Int(_) => RuntimeValue::FheIntKVStore(KVStore::new()),
            };
            outputs.push(store);
            Ok(())
        }
        HlInstructionSet::KVStoreInsertWithClearKey { .. }
        | HlInstructionSet::KVStoreRemoveWithClearKey { .. }
        | HlInstructionSet::KVStoreUpdate { .. } => {
            unreachable!("handled in the mutating-ops early-return above")
        }
        HlInstructionSet::KVStoreGetWithClearKey {
            value_kind,
            clear_key,
            ..
        } => {
            let key_u128 = clear_key.as_u128();
            let (value_ev, present) = match (inputs[0], value_kind) {
                (RuntimeValue::FheUintKVStore(kv), FheIntKind::Uint(bits)) => {
                    kv.get(&key_u128).map_or_else(
                        || {
                            let zero = exec_trivial(
                                &RuntimeValue::ClearUint(0),
                                FheKind::Uint(*bits),
                                sks,
                            );
                            (zero, false)
                        },
                        |v| (RuntimeValue::FheUint(v.clone()), true),
                    )
                }
                (RuntimeValue::FheIntKVStore(kv), FheIntKind::Int(bits)) => {
                    kv.get(&key_u128).map_or_else(
                        || {
                            let zero =
                                exec_trivial(&RuntimeValue::ClearInt(0), FheKind::Int(*bits), sks);
                            (zero, false)
                        },
                        |v| (RuntimeValue::FheInt(v.clone()), true),
                    )
                }
                _ => panic!("KVStoreGetWithClearKey: KVStore variant / value_kind mismatch"),
            };
            outputs.push(value_ev);
            outputs.push(RuntimeValue::ClearBool(present));
            Ok(())
        }
        HlInstructionSet::KVStoreGet { .. } => {
            let (value_ev, present_ev) = match (inputs[0], inputs[1]) {
                (RuntimeValue::FheUintKVStore(kv), RuntimeValue::FheUint(ek)) => {
                    let (v, p) = sks.pbs_key().kv_store_get(kv, ek);
                    (RuntimeValue::FheUint(v), RuntimeValue::FheBool(p))
                }
                (RuntimeValue::FheIntKVStore(kv), RuntimeValue::FheUint(ek)) => {
                    // See KVStoreUpdate signed arm: reinterpret the FheUint(N)
                    // encrypted_key as a SignedRadixCiphertext to match the
                    // value type bound on `kv_store_get<_, SignedRadixCiphertext>`.
                    let signed_key = SignedRadixCiphertext::from(ek.blocks.clone());
                    let (v, p) = sks.pbs_key().kv_store_get(kv, &signed_key);
                    (RuntimeValue::FheInt(v), RuntimeValue::FheBool(p))
                }
                _ => panic!("KVStoreGet: expected (KVStore, FheUint encrypted_key)"),
            };
            outputs.push(value_ev);
            outputs.push(present_ev);
            Ok(())
        }
    }
}
