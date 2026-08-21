//! End-to-end tests for the dialect/builder.
//!
//! These are the CPU `#[test]` entry points: each builds a `cpu_backend()` and
//! calls a backend-generic case in [`super::test_cases`], plus builder-only
//! (no-execution) error/shape tests that don't need a backend.
use crate::circuit::backends::cpu::{CpuBackend, CpuInputList};
use crate::circuit::backends::ExecutionBackend;
use crate::circuit::dialects::hlapi::FheIntKind;
use crate::circuit::{
    BuilderError, BuilderErrorKind, CircuitBuilder, ClearKind, HlInstructionSet, KvKey, KvKeyKind,
    OprfMode, ScalarValue, ValueKind,
};
use crate::prelude::*;
use crate::{
    generate_keys, ClientKey, ConfigBuilder, FheBool, FheInt8, FheUint32, FheUint8, Seed, ServerKey,
};

// Backend-generic case functions + the `check_*` helpers + `rand_*`.
use super::super::super::test_cases::*;

fn setup() -> (ClientKey, ServerKey) {
    let config = ConfigBuilder::default().build();
    generate_keys(config)
}

/// Build a CPU [`ExecutionBackend`] for tests.
fn cpu_backend() -> (ClientKey, CpuBackend) {
    let (ck, sk) = setup();
    (ck, CpuBackend::new(sk))
}

// ============================================================
// FheUint32 — FHE/FHE binary
// ============================================================

#[test]
fn fheuint32_add() {
    let (ck, be) = cpu_backend();
    fheuint32_add_case(&ck, &be);
}

#[test]
fn fheuint32_sub() {
    let (ck, be) = cpu_backend();
    fheuint32_sub_case(&ck, &be);
}

#[test]
fn fheuint32_mul() {
    let (ck, be) = cpu_backend();
    fheuint32_mul_case(&ck, &be);
}

#[test]
fn fheuint32_div() {
    let (ck, be) = cpu_backend();
    fheuint32_div_case(&ck, &be);
}

#[test]
fn fheuint32_rem() {
    let (ck, be) = cpu_backend();
    fheuint32_rem_case(&ck, &be);
}

#[test]
fn fheuint32_bitand() {
    let (ck, be) = cpu_backend();
    fheuint32_bitand_case(&ck, &be);
}

#[test]
fn fheuint32_bitor() {
    let (ck, be) = cpu_backend();
    fheuint32_bitor_case(&ck, &be);
}

#[test]
fn fheuint32_bitxor() {
    let (ck, be) = cpu_backend();
    fheuint32_bitxor_case(&ck, &be);
}

#[test]
fn fheuint32_min() {
    let (ck, be) = cpu_backend();
    fheuint32_min_case(&ck, &be);
}

#[test]
fn fheuint32_max() {
    let (ck, be) = cpu_backend();
    fheuint32_max_case(&ck, &be);
}

#[test]
fn fheuint32_shl() {
    let (ck, be) = cpu_backend();
    fheuint32_shl_case(&ck, &be);
}

#[test]
fn fheuint32_shr() {
    let (ck, be) = cpu_backend();
    fheuint32_shr_case(&ck, &be);
}

#[test]
fn fheuint32_rotate_left() {
    let (ck, be) = cpu_backend();
    fheuint32_rotate_left_case(&ck, &be);
}

#[test]
fn fheuint32_rotate_right() {
    let (ck, be) = cpu_backend();
    fheuint32_rotate_right_case(&ck, &be);
}

#[test]
fn fheuint32_eq() {
    let (ck, be) = cpu_backend();
    fheuint32_eq_case(&ck, &be);
}

#[test]
fn fheuint32_ne() {
    let (ck, be) = cpu_backend();
    fheuint32_ne_case(&ck, &be);
}

#[test]
fn fheuint32_lt() {
    let (ck, be) = cpu_backend();
    fheuint32_lt_case(&ck, &be);
}

#[test]
fn fheuint32_le() {
    let (ck, be) = cpu_backend();
    fheuint32_le_case(&ck, &be);
}

#[test]
fn fheuint32_gt() {
    let (ck, be) = cpu_backend();
    fheuint32_gt_case(&ck, &be);
}

#[test]
fn fheuint32_ge() {
    let (ck, be) = cpu_backend();
    fheuint32_ge_case(&ck, &be);
}

#[test]
fn fheuint32_not() {
    let (ck, be) = cpu_backend();
    fheuint32_not_case(&ck, &be);
}

// -- Unary bit-count / log / reverse on FheUint32 (output is FheUint32) --

#[test]
fn fheuint32_leading_zeros() {
    let (ck, be) = cpu_backend();
    fheuint32_leading_zeros_case(&ck, &be);
}

#[test]
fn fheuint32_leading_ones() {
    let (ck, be) = cpu_backend();
    fheuint32_leading_ones_case(&ck, &be);
}

#[test]
fn fheuint32_trailing_zeros() {
    let (ck, be) = cpu_backend();
    fheuint32_trailing_zeros_case(&ck, &be);
}

#[test]
fn fheuint32_trailing_ones() {
    let (ck, be) = cpu_backend();
    fheuint32_trailing_ones_case(&ck, &be);
}

#[test]
fn fheuint32_count_ones() {
    let (ck, be) = cpu_backend();
    fheuint32_count_ones_case(&ck, &be);
}

#[test]
fn fheuint32_count_zeros() {
    let (ck, be) = cpu_backend();
    fheuint32_count_zeros_case(&ck, &be);
}

#[test]
fn fheuint32_ilog2() {
    let (ck, be) = cpu_backend();
    fheuint32_ilog2_case(&ck, &be);
}

#[test]
fn fheuint32_reverse_bits() {
    let (ck, be) = cpu_backend();
    fheuint32_reverse_bits_case(&ck, &be);
}

#[test]
fn fheint32_reverse_bits() {
    let (ck, be) = cpu_backend();
    fheint32_reverse_bits_case(&ck, &be);
}

#[test]
fn fheint32_abs() {
    let (ck, be) = cpu_backend();
    fheint32_abs_case(&ck, &be);
}

// -- Predicates / checked_ilog2 — inline because output shape differs --

#[test]
fn fheuint32_is_even() {
    let (ck, be) = cpu_backend();
    fheuint32_is_even_case(&ck, &be);
}

#[test]
fn fheuint32_is_odd() {
    let (ck, be) = cpu_backend();
    fheuint32_is_odd_case(&ck, &be);
}

#[test]
fn fheuint32_checked_ilog2() {
    let (ck, be) = cpu_backend();
    fheuint32_checked_ilog2_case(&ck, &be);
}

#[test]
fn fheuint32_overflowing_add() {
    let (ck, be) = cpu_backend();
    fheuint32_overflowing_add_case(&ck, &be);
}

#[test]
fn fheuint32_overflowing_sub() {
    let (ck, be) = cpu_backend();
    fheuint32_overflowing_sub_case(&ck, &be);
}

#[test]
fn fheuint32_overflowing_mul() {
    let (ck, be) = cpu_backend();
    fheuint32_overflowing_mul_case(&ck, &be);
}

// ============================================================
// FheInt32 — FHE/FHE binary
// ============================================================

#[test]
fn fheint32_add() {
    let (ck, be) = cpu_backend();
    fheint32_add_case(&ck, &be);
}

#[test]
fn fheint32_sub() {
    let (ck, be) = cpu_backend();
    fheint32_sub_case(&ck, &be);
}

#[test]
fn fheint32_mul() {
    let (ck, be) = cpu_backend();
    fheint32_mul_case(&ck, &be);
}

#[test]
fn fheint32_div() {
    let (ck, be) = cpu_backend();
    fheint32_div_case(&ck, &be);
}

#[test]
fn fheint32_rem() {
    let (ck, be) = cpu_backend();
    fheint32_rem_case(&ck, &be);
}

#[test]
fn fheint32_bitand() {
    let (ck, be) = cpu_backend();
    fheint32_bitand_case(&ck, &be);
}

#[test]
fn fheint32_bitor() {
    let (ck, be) = cpu_backend();
    fheint32_bitor_case(&ck, &be);
}

#[test]
fn fheint32_bitxor() {
    let (ck, be) = cpu_backend();
    fheint32_bitxor_case(&ck, &be);
}

#[test]
fn fheint32_min() {
    let (ck, be) = cpu_backend();
    fheint32_min_case(&ck, &be);
}

#[test]
fn fheint32_max() {
    let (ck, be) = cpu_backend();
    fheint32_max_case(&ck, &be);
}

#[test]
fn fheint32_eq() {
    let (ck, be) = cpu_backend();
    fheint32_eq_case(&ck, &be);
}

#[test]
fn fheint32_ne() {
    let (ck, be) = cpu_backend();
    fheint32_ne_case(&ck, &be);
}

#[test]
fn fheint32_lt() {
    let (ck, be) = cpu_backend();
    fheint32_lt_case(&ck, &be);
}

#[test]
fn fheint32_le() {
    let (ck, be) = cpu_backend();
    fheint32_le_case(&ck, &be);
}

#[test]
fn fheint32_gt() {
    let (ck, be) = cpu_backend();
    fheint32_gt_case(&ck, &be);
}

#[test]
fn fheint32_ge() {
    let (ck, be) = cpu_backend();
    fheint32_ge_case(&ck, &be);
}

#[test]
fn fheint32_not() {
    let (ck, be) = cpu_backend();
    fheint32_not_case(&ck, &be);
}

#[test]
fn fheint32_neg() {
    let (ck, be) = cpu_backend();
    fheint32_neg_case(&ck, &be);
}

#[test]
fn fheint32_overflowing_add() {
    let (ck, be) = cpu_backend();
    fheint32_overflowing_add_case(&ck, &be);
}

#[test]
fn fheint32_overflowing_sub() {
    let (ck, be) = cpu_backend();
    fheint32_overflowing_sub_case(&ck, &be);
}

#[test]
fn fheint32_overflowing_mul() {
    let (ck, be) = cpu_backend();
    fheint32_overflowing_mul_case(&ck, &be);
}

// ============================================================
// Unary overflowing neg, div_rem, scalar overflowing add/sub, fused ops
// ============================================================

#[test]
fn fheuint32_overflowing_neg() {
    let (ck, be) = cpu_backend();
    fheuint32_overflowing_neg_case(&ck, &be);
}

#[test]
fn fheint32_overflowing_neg() {
    let (ck, be) = cpu_backend();
    fheint32_overflowing_neg_case(&ck, &be);
}

#[test]
fn fheuint32_div_rem() {
    let (ck, be) = cpu_backend();
    fheuint32_div_rem_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_overflowing_add() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_overflowing_add_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_overflowing_sub() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_overflowing_sub_case(&ck, &be);
}

#[test]
fn fheuint8_fused_mul_scalar_div() {
    let (ck, be) = cpu_backend();
    fheuint8_fused_mul_scalar_div_case(&ck, &be);
}

#[test]
fn fheuint8_fused_scalar_mul_scalar_div() {
    let (ck, be) = cpu_backend();
    fheuint8_fused_scalar_mul_scalar_div_case(&ck, &be);
}

#[test]
fn fheint32_shl() {
    let (ck, be) = cpu_backend();
    fheint32_shl_case(&ck, &be);
}

#[test]
fn fheint32_shr() {
    let (ck, be) = cpu_backend();
    fheint32_shr_case(&ck, &be);
}

#[test]
fn fheint32_rotate_left() {
    let (ck, be) = cpu_backend();
    fheint32_rotate_left_case(&ck, &be);
}

#[test]
fn fheint32_rotate_right() {
    let (ck, be) = cpu_backend();
    fheint32_rotate_right_case(&ck, &be);
}

// ============================================================
// Cast
// ============================================================

#[test]
fn cast_fheuint32_to_fheint32() {
    let (ck, be) = cpu_backend();
    cast_fheuint32_to_fheint32_case(&ck, &be);
}

#[test]
fn cast_fheint32_to_fheuint32() {
    let (ck, be) = cpu_backend();
    cast_fheint32_to_fheuint32_case(&ck, &be);
}

// ============================================================
// Cmux
// ============================================================

#[test]
fn cmux_fheuint32() {
    let (ck, be) = cpu_backend();
    cmux_fheuint32_case(&ck, &be);
}

// ============================================================
// FheUint32 — FHE/scalar
// ============================================================

#[test]
fn fheuint32_scalar_add_fhe_lhs() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_add_fhe_lhs_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_add_fhe_rhs() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_add_fhe_rhs_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_sub_fhe_lhs() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_sub_fhe_lhs_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_sub_fhe_rhs() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_sub_fhe_rhs_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_mul_fhe_lhs() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_mul_fhe_lhs_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_mul_fhe_rhs() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_mul_fhe_rhs_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_div() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_div_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_rem() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_rem_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_min() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_min_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_max() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_max_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_bitand() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_bitand_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_bitor() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_bitor_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_bitxor() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_bitxor_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_eq() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_eq_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_ne() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_ne_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_lt() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_lt_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_le() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_le_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_gt() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_gt_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_ge() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_ge_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_shl() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_shl_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_shr() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_shr_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_rotate_left() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_rotate_left_case(&ck, &be);
}

#[test]
fn fheuint32_scalar_rotate_right() {
    let (ck, be) = cpu_backend();
    fheuint32_scalar_rotate_right_case(&ck, &be);
}

// ============================================================
// KVStore — builder-error paths (no executor, no keygen)
// ============================================================

fn new_bld() -> CircuitBuilder {
    CircuitBuilder::new()
}

#[test]
fn clear_integer_kinds_reject_invalid_bit_widths() {
    for kind in [ValueKind::Uint(0), ValueKind::Int(0)] {
        let err = new_bld().input(kind).unwrap_err();
        assert!(matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::InvalidBitWidth { bits: 0 },
                op: "input",
            }
        ));
    }

    for kind in [ClearKind::Uint(0), ClearKind::Int(0)] {
        let err = new_bld().constant(0u32, kind).unwrap_err();
        assert!(matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::InvalidBitWidth { bits: 0 },
                op: "constant",
            }
        ));
    }

    if let Ok(too_wide) = usize::try_from(u64::from(u32::MAX) + 1) {
        let err = new_bld().input(ValueKind::Uint(too_wide)).unwrap_err();
        assert!(matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::InvalidBitWidth { .. },
                op: "input",
            }
        ));
    }
}

#[test]
fn kvstore_use_after_move_by_mutation() {
    let mut b = new_bld();
    let store_v0 = b
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(32))
        .unwrap();
    let v = b.input(ValueKind::FheUint(32)).unwrap();
    let _store_v1 = b
        .kv_store_insert_with_clear_key(store_v0, KvKey::U32(1), v)
        .unwrap();
    let err = b
        .kv_store_insert_with_clear_key(store_v0, KvKey::U32(2), v)
        .unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::KvStoreAlreadyMoved { .. },
                ..
            }
        ),
        "expected KvStoreAlreadyMoved, got {err:?}"
    );
}

#[test]
fn kvstore_use_after_move_by_read() {
    let mut b = new_bld();
    let store_v0 = b
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(32))
        .unwrap();
    let v = b.input(ValueKind::FheUint(32)).unwrap();
    let ek = b.input(ValueKind::FheUint(32)).unwrap();
    let _store_v1 = b
        .kv_store_insert_with_clear_key(store_v0, KvKey::U32(1), v)
        .unwrap();
    let err = b.kv_store_get(store_v0, ek).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::KvStoreAlreadyMoved { .. },
                ..
            }
        ),
        "expected KvStoreAlreadyMoved, got {err:?}"
    );
}

#[test]
fn kvstore_multiple_reads_ok() {
    let mut b = new_bld();
    let store = b
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(32))
        .unwrap();
    let ek1 = b.input(ValueKind::FheUint(32)).unwrap();
    let ek2 = b.input(ValueKind::FheUint(32)).unwrap();
    b.kv_store_get(store, ek1).unwrap();
    b.kv_store_get(store, ek2).unwrap();
    // Clear-key read on the same store version is also fine.
    b.kv_store_get_with_clear_key(store, KvKey::U32(7)).unwrap();
}

#[test]
fn kvstore_non_store_input_to_get() {
    let mut b = new_bld();
    let not_a_store = b.input(ValueKind::FheUint(32)).unwrap();
    let ek = b.input(ValueKind::FheUint(32)).unwrap();
    let err = b.kv_store_get(not_a_store, ek).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::IncompatibleKind { .. },
                op: "kv_store_get",
            }
        ),
        "expected IncompatibleKind for kv_store_get, got {err:?}"
    );
}

#[test]
fn kvstore_mismatched_clear_key() {
    let mut b = new_bld();
    let store = b
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(32))
        .unwrap();
    let v = b.input(ValueKind::FheUint(32)).unwrap();
    let err = b
        .kv_store_insert_with_clear_key(store, KvKey::U64(1), v)
        .unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::MismatchedKvKeyKind {
                    expected: KvKeyKind::U32,
                    actual: KvKeyKind::U64,
                },
                ..
            }
        ),
        "expected MismatchedKvKeyKind U32 vs U64, got {err:?}"
    );
}

#[test]
fn kvstore_wrong_width_encrypted_key() {
    let mut b = new_bld();
    // Store expects FheUint(32) encrypted keys; pass an FheUint(64) instead.
    let store = b
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(32))
        .unwrap();
    let wrong_ek = b.input(ValueKind::FheUint(64)).unwrap();
    let err = b.kv_store_get(store, wrong_ek).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::SignatureMismatch { .. },
                ..
            }
        ),
        "expected SignatureMismatch for wrong-width encrypted key, got {err:?}"
    );
}

#[test]
fn output_rejects_seed() {
    let mut b = new_bld();
    let seed = b.input(ValueKind::Seed).unwrap();
    let err = b.output(seed).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::InvalidOutputKind {
                    kind: ValueKind::Seed
                },
                op: "output",
            }
        ),
        "expected InvalidOutputKind for Seed, got {err:?}"
    );
}

#[test]
fn clear_integer_output_round_trip() {
    let mut b = new_bld();
    let unsigned = b.input(ValueKind::Uint(32)).unwrap();
    let signed = b.input(ValueKind::Int(32)).unwrap();
    let too_large_for_u8 = b.input(ValueKind::Uint(16)).unwrap();
    b.output(unsigned).unwrap();
    b.output(signed).unwrap();
    b.output(too_large_for_u8).unwrap();

    let (_, backend) = cpu_backend();
    let mut inputs = CpuInputList::new();
    inputs.push(42u32).push(-42i32).push(300u16);
    let outputs = backend.execute(&b.build(), inputs).unwrap();

    assert_eq!(outputs.get_clear::<u32>(0), 42);
    assert_eq!(outputs.get_clear::<i32>(1), -42);
    assert!(outputs.try_get_clear::<u8>(2).is_err());
}

#[test]
fn output_accepts_computed_clear_bool() {
    let mut b = new_bld();
    let store = b
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(32))
        .unwrap();
    let (_, is_present) = b.kv_store_get_with_clear_key(store, KvKey::U32(7)).unwrap();

    assert_eq!(b.kind_of(is_present), ValueKind::Bool);
    b.output(is_present).unwrap();
}

// ============================================================
// KVStore — executor end-to-end (each does its own keygen)
// ============================================================

#[test]
fn test_kv_store() {
    let mut bld = CircuitBuilder::new();

    // Circuit inputs (real ciphertexts pushed at runtime by the client).
    let in_a = bld.input(ValueKind::FheUint(8)).unwrap(); // value at clear key 1
    let in_b = bld.input(ValueKind::FheUint(8)).unwrap(); // value at clear key 2
    let in_ka = bld.input(ValueKind::FheUint(32)).unwrap(); // encrypted key 1
    let in_kb = bld.input(ValueKind::FheUint(32)).unwrap(); // encrypted key 2
    let in_na = bld.input(ValueKind::FheUint(8)).unwrap(); // new value to update at ka

    let store = bld
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(8))
        .unwrap();
    let store = bld
        .kv_store_insert_with_clear_key(store, KvKey::U32(1), in_a)
        .unwrap();
    let store = bld
        .kv_store_insert_with_clear_key(store, KvKey::U32(2), in_b)
        .unwrap();

    // Reads before the update.
    let (val_a_before, present_a_before) = bld.kv_store_get(store, in_ka).unwrap();
    let (val_b_before, present_b_before) = bld.kv_store_get(store, in_kb).unwrap();

    // Update at clear key 1 → new value `na` (encrypted key = in_ka).
    let (store, present_update) = bld.kv_store_update(store, in_ka, in_na).unwrap();

    // Reads after the update.
    let (val_a_after, present_a_after) = bld.kv_store_get(store, in_ka).unwrap();
    let (val_b_after, present_b_after) = bld.kv_store_get(store, in_kb).unwrap();

    // Outputs in declaration order — output indices follow.
    bld.output(val_a_before).unwrap(); // 0
    bld.output(present_a_before).unwrap(); // 1
    bld.output(val_b_before).unwrap(); // 2
    bld.output(present_b_before).unwrap(); // 3
    bld.output(present_update).unwrap(); // 4
    bld.output(val_a_after).unwrap(); // 5
    bld.output(present_a_after).unwrap(); // 6
    bld.output(val_b_after).unwrap(); // 7
    bld.output(present_b_after).unwrap(); // 8

    let circuit = bld.build();

    let (cks, sks) = generate_keys(ConfigBuilder::default());

    let a: u8 = 25;
    let b: u8 = 42;
    let ka: u32 = 1;
    let kb: u32 = 2;
    let na: u8 = 66;

    let mut inputs = CpuInputList::new();
    inputs.push(FheUint8::encrypt(a, &cks));
    inputs.push(FheUint8::encrypt(b, &cks));
    inputs.push(FheUint32::encrypt(ka, &cks));
    inputs.push(FheUint32::encrypt(kb, &cks));
    inputs.push(FheUint8::encrypt(na, &cks));

    let cpu = CpuBackend::new(sks);
    let outputs = cpu.execute(&circuit, inputs).unwrap();

    let val_a_before: u8 = outputs.get::<FheUint8>(0).decrypt(&cks);
    let present_a_before: bool = outputs.get::<FheBool>(1).decrypt(&cks);
    let val_b_before: u8 = outputs.get::<FheUint8>(2).decrypt(&cks);
    let present_b_before: bool = outputs.get::<FheBool>(3).decrypt(&cks);
    let present_update: bool = outputs.get::<FheBool>(4).decrypt(&cks);
    let val_a_after: u8 = outputs.get::<FheUint8>(5).decrypt(&cks);
    let present_a_after: bool = outputs.get::<FheBool>(6).decrypt(&cks);
    let val_b_after: u8 = outputs.get::<FheUint8>(7).decrypt(&cks);
    let present_b_after: bool = outputs.get::<FheBool>(8).decrypt(&cks);

    assert_eq!(
        val_a_before, a,
        "get(key=1) before update should return the inserted `a`"
    );
    assert!(present_a_before, "key 1 should be present");
    assert_eq!(
        val_b_before, b,
        "get(key=2) before update should return the inserted `b`"
    );
    assert!(present_b_before, "key 2 should be present");

    assert!(present_update, "update at key 1 should report present=true");

    assert_eq!(
        val_a_after, na,
        "get(key=1) after update should return the new value `na`"
    );
    assert!(present_a_after);
    assert_eq!(
        val_b_after, b,
        "get(key=2) after update should still return `b`"
    );
    assert!(present_b_after);
}

#[test]
fn test_kv_store_get_missing_encrypted_key() {
    let mut bld = CircuitBuilder::new();
    let in_v = bld.input(ValueKind::FheUint(8)).unwrap();
    let in_ek_missing = bld.input(ValueKind::FheUint(32)).unwrap();
    let store = bld
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(8))
        .unwrap();
    let store = bld
        .kv_store_insert_with_clear_key(store, KvKey::U32(1), in_v)
        .unwrap();
    let (val, present) = bld.kv_store_get(store, in_ek_missing).unwrap();
    bld.output(val).unwrap();
    bld.output(present).unwrap();
    let circuit = bld.build();

    let (cks, sks) = generate_keys(ConfigBuilder::default());
    let mut inputs = CpuInputList::new();
    inputs.push(FheUint8::encrypt(42u8, &cks));
    inputs.push(FheUint32::encrypt(99u32, &cks)); // not in store
    let outputs = CpuBackend::new(sks).execute(&circuit, inputs).unwrap();

    let val: u8 = outputs.get::<FheUint8>(0).decrypt(&cks);
    let present: bool = outputs.get::<FheBool>(1).decrypt(&cks);
    assert_eq!(
        val, 0,
        "missing encrypted key should return zero ciphertext"
    );
    assert!(!present, "missing key should report present=false");
}

#[test]
fn test_kv_store_get_with_clear_key_paths() {
    let mut bld = CircuitBuilder::new();
    let in_v = bld.input(ValueKind::FheUint(8)).unwrap();
    let store = bld
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(8))
        .unwrap();
    let store = bld
        .kv_store_insert_with_clear_key(store, KvKey::U32(7), in_v)
        .unwrap();

    let (val_hit, present_hit) = bld
        .kv_store_get_with_clear_key(store, KvKey::U32(7))
        .unwrap();
    let (val_miss, present_miss) = bld
        .kv_store_get_with_clear_key(store, KvKey::U32(123))
        .unwrap();

    bld.output(val_hit).unwrap(); // 0
    bld.output(present_hit).unwrap(); // 1 — ClearBool
    bld.output(val_miss).unwrap(); // 2
    bld.output(present_miss).unwrap(); // 3 — ClearBool
    let circuit = bld.build();

    let (cks, sks) = generate_keys(ConfigBuilder::default());
    let mut inputs = CpuInputList::new();
    inputs.push(FheUint8::encrypt(55u8, &cks));
    let outputs = CpuBackend::new(sks).execute(&circuit, inputs).unwrap();

    let val_hit: u8 = outputs.get::<FheUint8>(0).decrypt(&cks);
    let present_hit: bool = outputs.get_clear::<bool>(1); // ClearBool: no decrypt needed
    let val_miss: u8 = outputs.get::<FheUint8>(2).decrypt(&cks);
    let present_miss: bool = outputs.get_clear::<bool>(3);

    assert_eq!(val_hit, 55);
    assert!(present_hit, "clear-key hit should report present=true");
    assert_eq!(val_miss, 0, "clear-key miss should return zero ciphertext");
    assert!(!present_miss, "clear-key miss should report present=false");
}

#[test]
fn test_kv_store_remove() {
    let mut bld = CircuitBuilder::new();
    let in_a = bld.input(ValueKind::FheUint(8)).unwrap();
    let in_b = bld.input(ValueKind::FheUint(8)).unwrap();
    let in_ka = bld.input(ValueKind::FheUint(32)).unwrap();
    let in_kb = bld.input(ValueKind::FheUint(32)).unwrap();

    let store = bld
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(8))
        .unwrap();
    let store = bld
        .kv_store_insert_with_clear_key(store, KvKey::U32(1), in_a)
        .unwrap();
    let store = bld
        .kv_store_insert_with_clear_key(store, KvKey::U32(2), in_b)
        .unwrap();
    let store = bld
        .kv_store_remove_with_clear_key(store, KvKey::U32(1))
        .unwrap();

    let (val_a, present_a) = bld.kv_store_get(store, in_ka).unwrap();
    let (val_b, present_b) = bld.kv_store_get(store, in_kb).unwrap();
    bld.output(val_a).unwrap(); // 0
    bld.output(present_a).unwrap(); // 1
    bld.output(val_b).unwrap(); // 2
    bld.output(present_b).unwrap(); // 3
    let circuit = bld.build();

    let (cks, sks) = generate_keys(ConfigBuilder::default());
    let mut inputs = CpuInputList::new();
    inputs.push(FheUint8::encrypt(11u8, &cks));
    inputs.push(FheUint8::encrypt(22u8, &cks));
    inputs.push(FheUint32::encrypt(1u32, &cks));
    inputs.push(FheUint32::encrypt(2u32, &cks));
    let outputs = CpuBackend::new(sks).execute(&circuit, inputs).unwrap();

    let val_a: u8 = outputs.get::<FheUint8>(0).decrypt(&cks);
    let present_a: bool = outputs.get::<FheBool>(1).decrypt(&cks);
    let val_b: u8 = outputs.get::<FheUint8>(2).decrypt(&cks);
    let present_b: bool = outputs.get::<FheBool>(3).decrypt(&cks);

    assert_eq!(val_a, 0, "removed key should return zero");
    assert!(!present_a, "removed key should report present=false");
    assert_eq!(val_b, 22, "untouched key should still be readable");
    assert!(present_b);
}

#[test]
fn test_kv_store_update_missing_key() {
    let mut bld = CircuitBuilder::new();
    let in_orig = bld.input(ValueKind::FheUint(8)).unwrap();
    let in_new = bld.input(ValueKind::FheUint(8)).unwrap();
    let in_ek_missing = bld.input(ValueKind::FheUint(32)).unwrap();
    let in_ek_present = bld.input(ValueKind::FheUint(32)).unwrap();

    let store = bld
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(8))
        .unwrap();
    let store = bld
        .kv_store_insert_with_clear_key(store, KvKey::U32(5), in_orig)
        .unwrap();
    let (store, present_update) = bld.kv_store_update(store, in_ek_missing, in_new).unwrap();
    let (val_after, present_after) = bld.kv_store_get(store, in_ek_present).unwrap();
    bld.output(present_update).unwrap(); // 0
    bld.output(val_after).unwrap(); // 1
    bld.output(present_after).unwrap(); // 2
    let circuit = bld.build();

    let (cks, sks) = generate_keys(ConfigBuilder::default());
    let mut inputs = CpuInputList::new();
    inputs.push(FheUint8::encrypt(77u8, &cks)); // original value at key 5
    inputs.push(FheUint8::encrypt(99u8, &cks)); // attempted new value
    inputs.push(FheUint32::encrypt(999u32, &cks)); // missing key
    inputs.push(FheUint32::encrypt(5u32, &cks)); // present key
    let outputs = CpuBackend::new(sks).execute(&circuit, inputs).unwrap();

    let present_update: bool = outputs.get::<FheBool>(0).decrypt(&cks);
    let val_after: u8 = outputs.get::<FheUint8>(1).decrypt(&cks);
    let present_after: bool = outputs.get::<FheBool>(2).decrypt(&cks);

    assert!(
        !present_update,
        "update on missing key should report present=false"
    );
    assert_eq!(
        val_after, 77,
        "store should be unchanged after failed update"
    );
    assert!(present_after);
}

#[test]
fn test_kv_store_signed_end_to_end() {
    let mut bld = CircuitBuilder::new();
    let in_a = bld.input(ValueKind::FheInt(8)).unwrap();
    let in_b = bld.input(ValueKind::FheInt(8)).unwrap();
    let in_new = bld.input(ValueKind::FheInt(8)).unwrap();
    let in_ka = bld.input(ValueKind::FheUint(32)).unwrap();
    let in_kb = bld.input(ValueKind::FheUint(32)).unwrap();

    let store = bld
        .kv_store_create(KvKeyKind::U32, FheIntKind::Int(8))
        .unwrap();
    let store = bld
        .kv_store_insert_with_clear_key(store, KvKey::U32(1), in_a)
        .unwrap();
    let store = bld
        .kv_store_insert_with_clear_key(store, KvKey::U32(2), in_b)
        .unwrap();
    let (val_a_before, _present_a_before) = bld.kv_store_get(store, in_ka).unwrap();
    let (store, present_update) = bld.kv_store_update(store, in_ka, in_new).unwrap();
    let (val_a_after, _present_a_after) = bld.kv_store_get(store, in_ka).unwrap();
    let (val_b_after, _present_b_after) = bld.kv_store_get(store, in_kb).unwrap();
    bld.output(val_a_before).unwrap(); // 0
    bld.output(present_update).unwrap(); // 1
    bld.output(val_a_after).unwrap(); // 2
    bld.output(val_b_after).unwrap(); // 3
    let circuit = bld.build();

    let (cks, sks) = generate_keys(ConfigBuilder::default());
    let a: i8 = -42;
    let b: i8 = 17;
    let new_val: i8 = -100;
    let mut inputs = CpuInputList::new();
    inputs.push(FheInt8::encrypt(a, &cks));
    inputs.push(FheInt8::encrypt(b, &cks));
    inputs.push(FheInt8::encrypt(new_val, &cks));
    inputs.push(FheUint32::encrypt(1u32, &cks));
    inputs.push(FheUint32::encrypt(2u32, &cks));
    let outputs = CpuBackend::new(sks).execute(&circuit, inputs).unwrap();

    let val_a_before: i8 = outputs.get::<FheInt8>(0).decrypt(&cks);
    let present_update: bool = outputs.get::<FheBool>(1).decrypt(&cks);
    let val_a_after: i8 = outputs.get::<FheInt8>(2).decrypt(&cks);
    let val_b_after: i8 = outputs.get::<FheInt8>(3).decrypt(&cks);

    assert_eq!(
        val_a_before, a,
        "signed get should return inserted negative value"
    );
    assert!(present_update);
    assert_eq!(
        val_a_after, new_val,
        "signed update should overwrite with new negative value"
    );
    assert_eq!(
        val_b_after, b,
        "untouched key should still return its value"
    );
}

#[test]
fn test_kv_store_signed_get_missing() {
    let mut bld = CircuitBuilder::new();
    let in_v = bld.input(ValueKind::FheInt(8)).unwrap();
    let in_ek_missing = bld.input(ValueKind::FheUint(32)).unwrap();
    let store = bld
        .kv_store_create(KvKeyKind::U32, FheIntKind::Int(8))
        .unwrap();
    let store = bld
        .kv_store_insert_with_clear_key(store, KvKey::U32(1), in_v)
        .unwrap();
    let (val, present) = bld.kv_store_get(store, in_ek_missing).unwrap();
    bld.output(val).unwrap();
    bld.output(present).unwrap();
    let circuit = bld.build();

    let (cks, sks) = generate_keys(ConfigBuilder::default());
    let mut inputs = CpuInputList::new();
    inputs.push(FheInt8::encrypt(-5i8, &cks));
    inputs.push(FheUint32::encrypt(99u32, &cks));
    let outputs = CpuBackend::new(sks).execute(&circuit, inputs).unwrap();

    let val: i8 = outputs.get::<FheInt8>(0).decrypt(&cks);
    let present: bool = outputs.get::<FheBool>(1).decrypt(&cks);
    assert_eq!(val, 0);
    assert!(!present);
}

// ============================================================
// OPRF (oblivious pseudo-random) — circuit wiring of the FheOprf op
// ============================================================

#[test]
fn oprf_fheuint32_full() {
    let (ck, be) = cpu_backend();
    oprf_fheuint32_full_case(&ck, &be);
}

#[test]
fn oprf_fheuint32_bounded() {
    let (ck, be) = cpu_backend();
    oprf_fheuint32_bounded_case(&ck, &be);
}

#[test]
fn oprf_fheuint32_custom_range() {
    let (ck, be) = cpu_backend();
    oprf_fheuint32_custom_range_case(&ck, &be);
}

#[test]
fn oprf_power_of_two_custom_range_uses_bounded_mode() {
    let upper = std::num::NonZeroU64::new(8).unwrap();
    let singleton_upper = std::num::NonZeroU64::new(1).unwrap();
    let mut b = CircuitBuilder::new();
    let seed = b.input(ValueKind::Seed).unwrap();
    let result = b
        .oprf_custom_range(ValueKind::FheUint(32), seed, upper, Some(0.5))
        .unwrap();
    let singleton = b
        .oprf_custom_range(ValueKind::FheUint(32), seed, singleton_upper, None)
        .unwrap();
    b.output(result).unwrap();
    b.output(singleton).unwrap();
    let circuit = b.build();

    assert!(circuit.ir().walk_ops_topological().any(|op| matches!(
        op.get_instruction(),
        HlInstructionSet::FheOprf {
            mode: OprfMode::Bounded { bits: 3 },
            ..
        }
    )));
    assert!(circuit.ir().walk_ops_topological().any(|op| matches!(
        op.get_instruction(),
        HlInstructionSet::FheOprf {
            mode: OprfMode::Bounded { bits: 0 },
            ..
        }
    )));

    let (cks, sks) = generate_keys(ConfigBuilder::default());
    let mut inputs = CpuInputList::new();
    inputs.push_seed(Seed(42));
    let outputs = CpuBackend::new(sks).execute(&circuit, inputs).unwrap();
    let decrypted: u32 = outputs.get::<FheUint32>(0).decrypt(&cks);
    assert!(decrypted < upper.get() as u32);
    let singleton_decrypted: u32 = outputs.get::<FheUint32>(1).decrypt(&cks);
    assert_eq!(singleton_decrypted, 0);
}

#[test]
fn oprf_custom_range_rejects_upper_bound_that_does_not_fit() {
    let mut b = CircuitBuilder::new();
    let seed = b.input(ValueKind::Seed).unwrap();
    let upper = std::num::NonZeroU64::new(257).unwrap();
    let err = b
        .oprf_custom_range(ValueKind::FheUint(8), seed, upper, None)
        .unwrap_err();
    assert!(matches!(
        err,
        BuilderError {
            kind: BuilderErrorKind::InvalidOprfUpperBound {
                upper: 257,
                width: 8
            },
            op: "oprf_custom_range",
        }
    ));
}

#[test]
fn oprf_fheint32_full() {
    let (ck, be) = cpu_backend();
    oprf_fheint32_full_case(&ck, &be);
}

#[test]
fn oprf_fheint32_bounded() {
    let (ck, be) = cpu_backend();
    oprf_fheint32_bounded_case(&ck, &be);
}

#[test]
fn oprf_fhebool_full() {
    let (ck, be) = cpu_backend();
    oprf_fhebool_full_case(&ck, &be);
}

/// Two independent executions with the same seed must yield the same decrypted
/// value — that's the whole point of OPRF being deterministic.
#[test]
fn oprf_is_deterministic() {
    let (ck, be) = cpu_backend();
    oprf_is_deterministic_case(&ck, &be);
}

#[test]
fn oprf_rejects_custom_range_on_signed() {
    let mut b = CircuitBuilder::new();
    let seed = b.input(ValueKind::Seed).unwrap();
    let upper = std::num::NonZeroU64::new(5).unwrap();
    let err = b
        .oprf_custom_range(ValueKind::FheInt(32), seed, upper, None)
        .unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::InvalidOprfMode {
                    mode_name: "CustomRange",
                    ..
                },
                ..
            }
        ),
        "expected InvalidOprfMode for FheInt+CustomRange, got {err:?}"
    );
}

#[test]
fn oprf_rejects_bounded_on_bool() {
    let mut b = CircuitBuilder::new();
    let seed = b.input(ValueKind::Seed).unwrap();
    let err = b.oprf_bounded(ValueKind::FheBool, seed, 3).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::InvalidOprfMode {
                    mode_name: "Bounded",
                    ..
                },
                ..
            }
        ),
        "expected InvalidOprfMode for FheBool+Bounded, got {err:?}"
    );
}

#[test]
fn oprf_rejects_custom_range_on_bool() {
    let mut b = CircuitBuilder::new();
    let seed = b.input(ValueKind::Seed).unwrap();
    let upper = std::num::NonZeroU64::new(5).unwrap();
    let err = b
        .oprf_custom_range(ValueKind::FheBool, seed, upper, None)
        .unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::InvalidOprfMode {
                    mode_name: "CustomRange",
                    ..
                },
                ..
            }
        ),
        "expected InvalidOprfMode for FheBool+CustomRange, got {err:?}"
    );
}

#[test]
fn oprf_rejects_nan_max_distance() {
    let mut b = CircuitBuilder::new();
    let seed = b.input(ValueKind::Seed).unwrap();
    let upper = std::num::NonZeroU64::new(5).unwrap();
    let err = b
        .oprf_custom_range(ValueKind::FheUint(32), seed, upper, Some(f64::NAN))
        .unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::InvalidOprfMaxDistance,
                ..
            }
        ),
        "expected InvalidOprfMaxDistance for NaN, got {err:?}"
    );
}

// ============================================================
// Scalar selects / if_then_else
// ============================================================

#[test]
fn select_fheuint32_then_fhe_else_scalar() {
    let (ck, be) = cpu_backend();
    select_fheuint32_then_fhe_else_scalar_case(&ck, &be);
}

#[test]
fn select_fheuint32_then_scalar_else_fhe() {
    let (ck, be) = cpu_backend();
    select_fheuint32_then_scalar_else_fhe_case(&ck, &be);
}

#[test]
fn select_fheuint32_both_scalar() {
    let (ck, be) = cpu_backend();
    select_fheuint32_both_scalar_case(&ck, &be);
}

#[test]
fn select_fheint32_then_fhe_else_scalar() {
    let (ck, be) = cpu_backend();
    select_fheint32_then_fhe_else_scalar_case(&ck, &be);
}

#[test]
fn select_fheint32_then_scalar_else_fhe() {
    let (ck, be) = cpu_backend();
    select_fheint32_then_scalar_else_fhe_case(&ck, &be);
}

#[test]
fn select_fheint32_both_scalar() {
    let (ck, be) = cpu_backend();
    select_fheint32_both_scalar_case(&ck, &be);
}

#[test]
fn fhe_select_rejects_unsupported_operand_combination() {
    let mut b = CircuitBuilder::new();
    let cond = b.input(ValueKind::FheBool).unwrap();
    let err = b.fhe_select(cond, 1u32, 2u32).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::UnsupportedOperandCombination,
                op: "fhe_select",
            }
        ),
        "expected UnsupportedOperandCombination, got {err:?}"
    );
}

#[test]
fn fhe_select_const_rejects_invalid_scalar() {
    let mut b = CircuitBuilder::new();
    let cond = b.input(ValueKind::FheBool).unwrap();
    // The first value is valid but the second does not fit `FheUint(32)`.
    // Validation must happen before either Constant is emitted.
    let err = b
        .fhe_select_const(cond, 1u32, -1i32, FheIntKind::Uint(32))
        .unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::InvalidConstantValue,
                op: "fhe_select_const",
            }
        ),
        "expected InvalidConstantValue, got {err:?}"
    );
    b.output(cond).unwrap();
    assert_eq!(b.build().ir().n_ops(), 2, "failed select left orphan ops");
}

#[test]
fn fhe_select_rejects_invalid_condition_without_mutation() {
    let mut b = CircuitBuilder::new();
    let cond = b.input(ValueKind::FheUint(32)).unwrap();
    let value = b.input(ValueKind::FheUint(32)).unwrap();
    let err = b.fhe_select(cond, value, 1u32).unwrap_err();
    assert!(matches!(
        err,
        BuilderError {
            kind: BuilderErrorKind::IncompatibleKind { .. },
            op: "fhe_select",
        }
    ));
    b.output(value).unwrap();
    assert_eq!(
        b.build().ir().n_ops(),
        3,
        "failed select left an orphan scalar Constant"
    );
}

#[test]
fn fhe_flip_reports_unsupported_mixed_operands() {
    let mut b = CircuitBuilder::new();
    let cond = b.input(ValueKind::FheBool).unwrap();
    let value = b.input(ValueKind::FheUint(32)).unwrap();
    let err = b.fhe_flip(cond, value, 1u32).unwrap_err();
    assert!(matches!(
        err,
        BuilderError {
            kind: BuilderErrorKind::UnsupportedOperandCombination,
            op: "fhe_flip",
        }
    ));
}

// ============================================================
// fhe_contains (membership test)
// ============================================================

#[test]
fn contains_fheuint32_found() {
    let (ck, be) = cpu_backend();
    contains_fheuint32_found_case(&ck, &be);
}

#[test]
fn contains_fheuint32_not_found() {
    let (ck, be) = cpu_backend();
    contains_fheuint32_not_found_case(&ck, &be);
}

#[test]
fn contains_fheint32_found() {
    let (ck, be) = cpu_backend();
    contains_fheint32_found_case(&ck, &be);
}

#[test]
fn contains_scalar_fheuint32_found() {
    let (ck, be) = cpu_backend();
    contains_scalar_fheuint32_found_case(&ck, &be);
}

#[test]
fn contains_scalar_fheint32_not_found() {
    let (ck, be) = cpu_backend();
    contains_scalar_fheint32_not_found_case(&ck, &be);
}

#[test]
fn contains_rejects_non_int_haystack() {
    // FheBool is not an FheIntKind; fhe_contains must reject it.
    let mut b = CircuitBuilder::new();
    let needle = b.input(ValueKind::FheBool).unwrap();
    let h0 = b.input(ValueKind::FheBool).unwrap();
    let err = b.fhe_contains(&[h0], needle).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::IncompatibleKind { .. },
                op: "fhe_contains",
            }
        ),
        "expected IncompatibleKind for FheBool haystack, got {err:?}"
    );
}

#[test]
fn contains_rejects_invalid_scalar_needle() {
    let mut b = CircuitBuilder::new();
    let h0 = b.input(ValueKind::FheUint(32)).unwrap();
    // -1i32 doesn't fit in FheUint(32) and normalize_for refuses to coerce.
    let err = b.fhe_contains(&[h0], -1i32).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::InvalidConstantValue,
                op: "fhe_contains",
            }
        ),
        "expected InvalidConstantValue for out-of-range scalar, got {err:?}"
    );
}

#[test]
fn contains_errors_on_empty_haystack() {
    let mut b = CircuitBuilder::new();
    let needle = b.input(ValueKind::FheUint(32)).unwrap();
    let err = b.fhe_contains(&[], needle).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::EmptyInput,
                ..
            }
        ),
        "expected EmptyInput, got {err:?}"
    );
}

// ============================================================
// Circuit::max_concurrent_ops (ASAP DAG width)
// ============================================================

#[test]
fn max_concurrent_ops_empty_circuit() {
    let b = CircuitBuilder::new();
    let circuit = b.build();
    // Empty circuits return the floor of 1 (one worker is always sensible).
    assert_eq!(circuit.max_concurrent_ops(), 1);
}

#[test]
fn max_concurrent_ops_linear_chain() {
    // a -> add1 -> add2 -> add3 -> output: width = 1 throughout.
    let mut b = CircuitBuilder::new();
    let a = b.input(ValueKind::FheUint(32)).unwrap();
    let r1 = b.fhe_add(a, 1u32).unwrap();
    let r2 = b.fhe_add(r1, 2u32).unwrap();
    let r3 = b.fhe_add(r2, 3u32).unwrap();
    b.output(r3).unwrap();
    let circuit = b.build();
    assert_eq!(circuit.max_concurrent_ops(), 1);
}

#[test]
fn max_concurrent_ops_wide_layer() {
    // a -> {add1, add2, add3, add4} -> sum -> output: 4 ops at level 1.
    let mut b = CircuitBuilder::new();
    let a = b.input(ValueKind::FheUint(32)).unwrap();
    let r1 = b.fhe_add(a, 1u32).unwrap();
    let r2 = b.fhe_add(a, 2u32).unwrap();
    let r3 = b.fhe_add(a, 3u32).unwrap();
    let r4 = b.fhe_add(a, 4u32).unwrap();
    let s = b.fhe_sum(&[r1, r2, r3, r4]).unwrap();
    b.output(s).unwrap();
    let circuit = b.build();
    assert_eq!(circuit.max_concurrent_ops(), 4);
}

#[test]
fn max_concurrent_ops_diamond() {
    // a -> {add1, add2} -> mul -> output: width = 2 at level 1, then 1.
    let mut b = CircuitBuilder::new();
    let a = b.input(ValueKind::FheUint(32)).unwrap();
    let l = b.fhe_add(a, 1u32).unwrap();
    let r = b.fhe_add(a, 2u32).unwrap();
    let m = b.fhe_mul(l, r).unwrap();
    b.output(m).unwrap();
    let circuit = b.build();
    assert_eq!(circuit.max_concurrent_ops(), 2);
}

#[test]
fn max_concurrent_ops_input_output_only() {
    // Pure pass-through: one input, one output, no compute ops.
    // Input/Output are coordinator-handled; width of "compute" is 0,
    // floored to 1.
    let mut b = CircuitBuilder::new();
    let a = b.input(ValueKind::FheUint(32)).unwrap();
    b.output(a).unwrap();
    let circuit = b.build();
    assert_eq!(circuit.max_concurrent_ops(), 1);
}

// ============================================================
// Clear-input / Constant op tests
// ============================================================

#[test]
fn constant_op_round_trip() {
    let (_ck, be) = cpu_backend();
    constant_op_round_trip_case(&be);
}

#[test]
fn clear_value_at_recognizes_literal_in_polymorphic_add() {
    // After `b.fhe_add(fhe_input, 7u32)`, the second operand of the
    // FheScalarAdd op should be a Constant whose value is recoverable via
    // Circuit::clear_value_at. An Input-produced operand should return None.
    let mut b = CircuitBuilder::new();
    let a = b.input(ValueKind::FheUint(32)).unwrap();
    let r = b.fhe_add(a, 7u32).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    // Walk the IR to find the FheScalarAdd op and check its operands.
    let ir = circuit.ir();
    let mut checked = false;
    for op_ref in ir.walk_ops_linear() {
        if let HlInstructionSet::FheScalarAdd { .. } = op_ref.get_instruction() {
            let args = op_ref.get_arg_valids();
            assert_eq!(args.len(), 2, "FheScalarAdd takes (fhe, clear)");
            // First operand is the FHE input — not a constant.
            assert_eq!(circuit.clear_value_at(args[0]), None);
            assert!(!circuit.is_compile_time_constant(args[0]));
            // Second operand is the Constant(7).
            assert_eq!(
                circuit.clear_value_at(args[1]),
                Some(ScalarValue::Unsigned(7))
            );
            assert!(circuit.is_compile_time_constant(args[1]));
            checked = true;
        }
    }
    assert!(checked, "expected a FheScalarAdd in the IR");
}

#[test]
fn runtime_clear_input_via_fhe_add() {
    let (ck, be) = cpu_backend();
    runtime_clear_input_via_fhe_add_case(&ck, &be);
}

// ============================================================
// KVStore — output/mutation interaction
// ============================================================

#[test]
fn kvstore_output_after_move_is_rejected() {
    let mut b = new_bld();
    let store_v0 = b
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(32))
        .unwrap();
    let v = b.input(ValueKind::FheUint(32)).unwrap();
    let _store_v1 = b
        .kv_store_insert_with_clear_key(store_v0, KvKey::U32(1), v)
        .unwrap();
    let err = b.output(store_v0).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::KvStoreAlreadyMoved { .. },
                ..
            }
        ),
        "expected KvStoreAlreadyMoved, got {err:?}"
    );
}

#[test]
fn test_kv_store_output_then_mutate() {
    let mut bld = CircuitBuilder::new();

    let in_v = bld.input(ValueKind::FheUint(8)).unwrap();
    let in_k = bld.input(ValueKind::FheUint(32)).unwrap();

    let store = bld
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(8))
        .unwrap();
    let store_v1 = bld
        .kv_store_insert_with_clear_key(store, KvKey::U32(1), in_v)
        .unwrap();

    // Output the current store version, then keep mutating it. The output's
    // reference to the store lives until the end of the run, so the mutating
    // op below exercises the executor's copy-on-shared path in `take_store`.
    bld.output(store_v1).unwrap(); // 0
    let store_v2 = bld
        .kv_store_insert_with_clear_key(store_v1, KvKey::U32(2), in_v)
        .unwrap();
    let (val, present) = bld.kv_store_get(store_v2, in_k).unwrap();
    bld.output(val).unwrap(); // 1
    bld.output(present).unwrap(); // 2

    let circuit = bld.build();

    let (cks, sks) = generate_keys(ConfigBuilder::default());

    let v: u8 = 25;

    let mut inputs = CpuInputList::new();
    inputs.push(FheUint8::encrypt(v, &cks));
    inputs.push(FheUint32::encrypt(2u32, &cks));

    let cpu = CpuBackend::new(sks);
    let outputs = cpu.execute(&circuit, inputs).unwrap();

    let val: u8 = outputs.get::<FheUint8>(1).decrypt(&cks);
    let present: bool = outputs.get::<FheBool>(2).decrypt(&cks);

    assert_eq!(
        val, v,
        "get(key=2) on the mutated store should see the value"
    );
    assert!(present, "key 2 should be present in the mutated store");
}

// ============================================================
// Compression — compress → decompress round trip (executor)
// ============================================================

#[test]
fn test_compress_decompress_round_trip() {
    use crate::shortint::parameters::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let mut bld = CircuitBuilder::new();
    let in_a = bld.input(ValueKind::FheUint(32)).unwrap();
    let in_b = bld.input(ValueKind::FheInt(8)).unwrap();
    let in_c = bld.input(ValueKind::FheBool).unwrap();

    let list = bld.compress(&[in_a, in_b, in_c]).unwrap();
    let vals = bld
        .decompress_in_order(
            list,
            &[
                ValueKind::FheUint(32),
                ValueKind::FheInt(8),
                ValueKind::FheBool,
            ],
        )
        .unwrap();
    for v in vals {
        bld.output(v).unwrap();
    }
    let circuit = bld.build();

    let config = ConfigBuilder::default()
        .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
        .build();
    let (cks, sks) = generate_keys(config);

    let a: u32 = 0xDEAD_BEEF;
    let b: i8 = -42;
    let c = true;

    let mut inputs = CpuInputList::new();
    inputs.push(FheUint32::encrypt(a, &cks));
    inputs.push(FheInt8::encrypt(b, &cks));
    inputs.push(FheBool::encrypt(c, &cks));

    let cpu = CpuBackend::new(sks);
    let outputs = cpu.execute(&circuit, inputs).unwrap();

    let out_a: u32 = outputs.get::<FheUint32>(0).decrypt(&cks);
    let out_b: i8 = outputs.get::<FheInt8>(1).decrypt(&cks);
    let out_c: bool = outputs.get::<FheBool>(2).decrypt(&cks);

    assert_eq!(
        out_a, a,
        "u32 should round-trip through compress/decompress"
    );
    assert_eq!(out_b, b, "i8 should round-trip through compress/decompress");
    assert_eq!(
        out_c, c,
        "bool should round-trip through compress/decompress"
    );
}

// ============================================================
// Division by compile-time zero scalar — builder-error paths
// ============================================================

#[test]
fn div_rejects_zero_scalar() {
    let mut b = new_bld();
    let x = b.input(ValueKind::FheUint(32)).unwrap();
    for err in [
        b.fhe_div(x, 0u32).unwrap_err(),
        b.fhe_rem(x, 0u32).unwrap_err(),
    ] {
        assert!(
            matches!(
                err,
                BuilderError {
                    kind: BuilderErrorKind::DivisionByZeroScalar,
                    ..
                }
            ),
            "expected DivisionByZeroScalar, got {err:?}"
        );
    }
    // Signed zero through a signed operand.
    let sx = b.input(ValueKind::FheInt(32)).unwrap();
    let err = b.fhe_div(sx, 0i32).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::DivisionByZeroScalar,
                ..
            }
        ),
        "expected DivisionByZeroScalar for signed zero, got {err:?}"
    );
    // Nonzero divisors still build.
    b.fhe_div(x, 3u32).unwrap();
    b.fhe_rem(x, 3u32).unwrap();
}

#[test]
fn div_rejects_zero_constant_ref() {
    let mut b = new_bld();
    let x = b.input(ValueKind::FheUint(32)).unwrap();
    let zero = b.constant(0u32, ClearKind::Uint(32)).unwrap();
    let err = b.fhe_div(x, zero).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::DivisionByZeroScalar,
                ..
            }
        ),
        "expected DivisionByZeroScalar via constant ref, got {err:?}"
    );
}

#[test]
fn div_rejects_zero_scalar_without_mutation() {
    let mut b = new_bld();
    let x = b.input(ValueKind::FheUint(32)).unwrap();
    let err = b.fhe_div(x, 0u32).unwrap_err();
    assert!(matches!(
        err,
        BuilderError {
            kind: BuilderErrorKind::DivisionByZeroScalar,
            op: "fhe_div",
        }
    ));
    b.output(x).unwrap();
    assert_eq!(
        b.build().ir().n_ops(),
        2,
        "failed division left an orphan zero Constant"
    );
}

#[test]
fn fused_mul_scalar_div_rejects_zero_divisor() {
    let mut b = new_bld();
    let x = b.input(ValueKind::FheUint(32)).unwrap();
    let y = b.input(ValueKind::FheUint(32)).unwrap();
    let err = b.fhe_fused_mul_scalar_div(x, y, 0u64).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::DivisionByZeroScalar,
                ..
            }
        ),
        "expected DivisionByZeroScalar in fused op, got {err:?}"
    );
    let err = b
        .fhe_fused_scalar_mul_scalar_div(x, 3u64, 0u64)
        .unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::DivisionByZeroScalar,
                ..
            }
        ),
        "expected DivisionByZeroScalar in fused op, got {err:?}"
    );
    b.output(x).unwrap();
    b.output(y).unwrap();
    assert_eq!(
        b.build().ir().n_ops(),
        4,
        "failed fused expansions left orphan ops"
    );
}

#[test]
fn fused_mul_scalar_div_rejects_mismatched_operand_kinds_without_mutation() {
    let mut b = new_bld();
    let lhs = b.input(ValueKind::FheUint(32)).unwrap();
    let rhs = b.input(ValueKind::FheInt(32)).unwrap();
    let err = b.fhe_fused_mul_scalar_div(lhs, rhs, 3u64).unwrap_err();
    assert!(matches!(
        err,
        BuilderError {
            kind: BuilderErrorKind::MismatchedOperandKinds {
                lhs: ValueKind::FheUint(32),
                rhs: ValueKind::FheInt(32),
            },
            op: "fhe_fused_mul_scalar_div",
        }
    ));
    b.output(lhs).unwrap();
    b.output(rhs).unwrap();
    assert_eq!(
        b.build().ir().n_ops(),
        4,
        "mismatched fused operands left orphan ops"
    );
}

// ============================================================
// OPRF max_distance domain — builder-error paths
// ============================================================

#[test]
fn oprf_rejects_out_of_range_max_distance() {
    let mut b = new_bld();
    let seed = b.input(ValueKind::Seed).unwrap();
    let upper = std::num::NonZeroU64::new(5).unwrap();
    for bad in [0.0, -0.5, 1.0, 1.5, f64::NEG_INFINITY, f64::INFINITY] {
        let err = b
            .oprf_custom_range(ValueKind::FheUint(32), seed, upper, Some(bad))
            .unwrap_err();
        assert!(
            matches!(
                err,
                BuilderError {
                    kind: BuilderErrorKind::InvalidOprfMaxDistance,
                    ..
                }
            ),
            "expected InvalidOprfMaxDistance for {bad}, got {err:?}"
        );
    }
    // In-range values and the default still build.
    b.oprf_custom_range(ValueKind::FheUint(32), seed, upper, Some(0.5))
        .unwrap();
    b.oprf_custom_range(ValueKind::FheUint(32), seed, upper, None)
        .unwrap();
}

// ============================================================
// Scalar shift/rotate amounts — negative amounts rejected
// ============================================================

#[test]
fn shift_rejects_negative_scalar_amount_on_signed() {
    let mut b = new_bld();
    let sx = b.input(ValueKind::FheInt(32)).unwrap();
    for err in [
        b.fhe_shl(sx, -5i32).unwrap_err(),
        b.fhe_shr(sx, -5i32).unwrap_err(),
        b.fhe_rotate_left(sx, -5i32).unwrap_err(),
        b.fhe_rotate_right(sx, -5i32).unwrap_err(),
    ] {
        assert!(
            matches!(
                err,
                BuilderError {
                    kind: BuilderErrorKind::InvalidConstantValue,
                    ..
                }
            ),
            "expected InvalidConstantValue for negative shift amount, got {err:?}"
        );
    }
    // Non-negative amounts still build for signed operands, including
    // positive amounts written as signed literals.
    b.fhe_shl(sx, 5i32).unwrap();
    b.fhe_shr(sx, 0u32).unwrap();
    b.fhe_rotate_left(sx, 31u32).unwrap();
    // Unsigned operands are unchanged.
    let ux = b.input(ValueKind::FheUint(32)).unwrap();
    b.fhe_shl(ux, 5u32).unwrap();
    let err = b.fhe_shl(ux, -5i32).unwrap_err();
    assert!(
        matches!(
            err,
            BuilderError {
                kind: BuilderErrorKind::InvalidConstantValue,
                ..
            }
        ),
        "expected InvalidConstantValue for negative shift on unsigned, got {err:?}"
    );
}

// ============================================================
// Tag propagation — outputs carry the server key's tag
// ============================================================

#[test]
fn test_outputs_carry_server_key_tag() {
    let mut bld = CircuitBuilder::new();
    let a = bld.input(ValueKind::FheUint(32)).unwrap();
    let b = bld.input(ValueKind::FheUint(32)).unwrap();
    let sum = bld.fhe_add(a, b).unwrap();
    bld.output(sum).unwrap();
    let circuit = bld.build();

    let (cks, mut sks) = generate_keys(ConfigBuilder::default());
    sks.tag_mut().set_u64(0xDEAD);

    let mut inputs = CpuInputList::new();
    inputs.push(FheUint32::encrypt(1u32, &cks));
    inputs.push(FheUint32::encrypt(2u32, &cks));

    let cpu = CpuBackend::new(sks);
    let outputs = cpu.execute(&circuit, inputs).unwrap();

    assert_eq!(outputs.tag().as_u64(), 0xDEAD);
    let r: FheUint32 = outputs.get(0);
    assert_eq!(
        r.tag().as_u64(),
        0xDEAD,
        "retrieved output should carry the server key's tag"
    );
    let dec: u32 = r.decrypt(&cks);
    assert_eq!(dec, 3);
}

// ============================================================
// KVStore across the circuit boundary (output → HL type → input)
// ============================================================

#[test]
fn test_kv_store_across_circuit_boundary() {
    // Circuit A: build a store with one entry and output it.
    let mut bld = CircuitBuilder::new();
    let in_v = bld.input(ValueKind::FheUint(8)).unwrap();
    let store = bld
        .kv_store_create(KvKeyKind::U32, FheIntKind::Uint(8))
        .unwrap();
    let store = bld
        .kv_store_insert_with_clear_key(store, KvKey::U32(7), in_v)
        .unwrap();
    bld.output(store).unwrap();
    let circuit_a = bld.build();

    // Circuit B: take a store as input, get with an encrypted key.
    let mut bld = CircuitBuilder::new();
    let store_in = bld
        .input(ValueKind::KVStore {
            key: KvKeyKind::U32,
            value: FheIntKind::Uint(8),
        })
        .unwrap();
    let in_ek = bld.input(ValueKind::FheUint(32)).unwrap();
    let (val, present) = bld.kv_store_get(store_in, in_ek).unwrap();
    bld.output(val).unwrap(); // 0
    bld.output(present).unwrap(); // 1
    let circuit_b = bld.build();

    let (cks, sks) = generate_keys(ConfigBuilder::default());
    let cpu = CpuBackend::new(sks);
    let v: u8 = 42;

    let mut inputs = CpuInputList::new();
    inputs.push(FheUint8::encrypt(v, &cks));
    let outputs = cpu.execute(&circuit_a, inputs).unwrap();

    // Retrieve as a classic HL KVStore between executions.
    let hl_store: crate::KVStore<u32, FheUint8> = outputs.try_get(0).unwrap();
    assert_eq!(hl_store.len(), 1);

    // Wrong-width retrieval is rejected.
    assert!(
        outputs
            .try_get::<crate::KVStore<u32, FheUint32>>(0)
            .is_err(),
        "retrieving an 8-bit store as 32-bit should fail"
    );

    // Feed the store back into circuit B.
    let mut inputs = CpuInputList::new();
    inputs.push(hl_store);
    inputs.push(FheUint32::encrypt(7u32, &cks));
    let outputs = cpu.execute(&circuit_b, inputs).unwrap();

    let got: u8 = outputs.get::<FheUint8>(0).decrypt(&cks);
    let present: bool = outputs.get::<FheBool>(1).decrypt(&cks);
    assert_eq!(
        got, v,
        "value stored in circuit A should be readable in circuit B"
    );
    assert!(present);
}
