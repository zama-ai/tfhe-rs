//! Backend-generic test cases for the dialect executor.
//!
//! Each function builds a circuit, runs it through an `impl ExecutionBackend`
//! (via `execute_cpu_io`), and checks decrypted outputs. They are parameterised
//! over the backend so the same cases can be re-run against any backend (e.g. a
//! future GPU backend) by passing a different `ExecutionBackend` implementation.
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng};

use crate::circuit::backends::cpu::{CpuInputList, RuntimeValue};
use crate::circuit::backends::ExecutionBackend;
use crate::circuit::{
    BuilderError, CircuitBuilder, ClearKind, FheIntKind, FheKind, HlInstructionSet, ValueId,
    ValueKind,
};
use crate::prelude::*;
use crate::{ClientKey, FheBool, FheInt32, FheUint32, Seed};

const NUM_RANDOM_TRIALS: usize = 30;

// Scalars used by the FHE/scalar operation cases.
const SCALAR_U32: u32 = 42;
const SCALAR_MASK_U32: u32 = 0xFF00_FF00;
const SCALAR_SHIFT: u32 = 5;

fn rand_u32(rng: &mut ThreadRng) -> u32 {
    rng.gen()
}

fn rand_u32_nonzero(rng: &mut ThreadRng) -> u32 {
    rng.gen_range(1..=u32::MAX)
}

fn rand_shift_amount(rng: &mut ThreadRng) -> u32 {
    rng.gen_range(0..32)
}

fn rand_i32(rng: &mut ThreadRng) -> i32 {
    rng.gen()
}

fn rand_i32_nonzero(rng: &mut ThreadRng) -> i32 {
    loop {
        let v: i32 = rng.gen();
        if v != 0 {
            return v;
        }
    }
}

// ============================================================
// FheUint32 helpers
// ============================================================

fn check_uint32_binary<B: ExecutionBackend, F, G, R>(
    ck: &ClientKey,
    backend: &B,
    name: &str,
    build: F,
    clear: G,
    edge_cases: &[(u32, u32)],
    rhs_sample: R,
) where
    F: Fn(&mut CircuitBuilder, ValueId, ValueId) -> Result<ValueId, BuilderError>,
    G: Fn(u32, u32) -> u32,
    R: Fn(&mut ThreadRng) -> u32,
{
    let mut rng = thread_rng();
    let mut cases: Vec<(u32, u32)> = edge_cases.to_vec();
    for _ in 0..NUM_RANDOM_TRIALS {
        cases.push((rand_u32(&mut rng), rhs_sample(&mut rng)));
    }

    // Batch all cases into a single wide circuit: one op-instance per case,
    // executed in one go so the backend runs them concurrently.
    let mut b = CircuitBuilder::new();
    let mut inputs = CpuInputList::new();
    for &(a, c) in &cases {
        let lhs = b.input(ValueKind::FheUint(32)).unwrap();
        let rhs = b.input(ValueKind::FheUint(32)).unwrap();
        let r = build(&mut b, lhs, rhs).unwrap();
        b.output(r).unwrap();
        inputs.push(FheUint32::encrypt(a, ck));
        inputs.push(FheUint32::encrypt(c, ck));
    }
    let circuit = b.build();
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();

    for (i, &(a, c)) in cases.iter().enumerate() {
        let dec: u32 = outputs.get::<FheUint32>(i).decrypt(ck);
        let expected = clear(a, c);
        assert_eq!(
            dec, expected,
            "{name}({a}, {c}) = {dec}, expected {expected}"
        );
    }
}

fn check_uint32_compare<B: ExecutionBackend, F, G>(
    ck: &ClientKey,
    backend: &B,
    name: &str,
    build: F,
    clear: G,
    edge_cases: &[(u32, u32)],
) where
    F: Fn(&mut CircuitBuilder, ValueId, ValueId) -> Result<ValueId, BuilderError>,
    G: Fn(u32, u32) -> bool,
{
    let mut rng = thread_rng();
    let mut cases: Vec<(u32, u32)> = edge_cases.to_vec();
    for _ in 0..NUM_RANDOM_TRIALS {
        cases.push((rng.gen(), rng.gen()));
    }

    let mut b = CircuitBuilder::new();
    let mut inputs = CpuInputList::new();
    for &(a, c) in &cases {
        let lhs = b.input(ValueKind::FheUint(32)).unwrap();
        let rhs = b.input(ValueKind::FheUint(32)).unwrap();
        let r = build(&mut b, lhs, rhs).unwrap();
        b.output(r).unwrap();
        inputs.push(FheUint32::encrypt(a, ck));
        inputs.push(FheUint32::encrypt(c, ck));
    }
    let circuit = b.build();
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();

    for (i, &(a, c)) in cases.iter().enumerate() {
        let dec: bool = outputs.get::<FheBool>(i).decrypt(ck);
        let expected = clear(a, c);
        assert_eq!(
            dec, expected,
            "{name}({a}, {c}) = {dec}, expected {expected}"
        );
    }
}

fn check_uint32_unary<B: ExecutionBackend, F, G>(
    ck: &ClientKey,
    backend: &B,
    name: &str,
    build: F,
    clear: G,
    edge_cases: &[u32],
) where
    F: Fn(&mut CircuitBuilder, ValueId) -> Result<ValueId, BuilderError>,
    G: Fn(u32) -> u32,
{
    let mut rng = thread_rng();
    let mut cases: Vec<u32> = edge_cases.to_vec();
    for _ in 0..NUM_RANDOM_TRIALS {
        cases.push(rng.gen());
    }

    let mut b = CircuitBuilder::new();
    let mut inputs = CpuInputList::new();
    for &a in &cases {
        let v = b.input(ValueKind::FheUint(32)).unwrap();
        let r = build(&mut b, v).unwrap();
        b.output(r).unwrap();
        inputs.push(FheUint32::encrypt(a, ck));
    }
    let circuit = b.build();
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();

    for (i, &a) in cases.iter().enumerate() {
        let dec: u32 = outputs.get::<FheUint32>(i).decrypt(ck);
        let expected = clear(a);
        assert_eq!(dec, expected, "{name}({a}) = {dec}, expected {expected}");
    }
}

fn check_uint32_overflowing<B: ExecutionBackend, F, G>(
    ck: &ClientKey,
    backend: &B,
    name: &str,
    build: F,
    clear: G,
    edge_cases: &[(u32, u32)],
) where
    F: Fn(&mut CircuitBuilder, ValueId, ValueId) -> Result<(ValueId, ValueId), BuilderError>,
    G: Fn(u32, u32) -> (u32, bool),
{
    let mut rng = thread_rng();
    let mut cases: Vec<(u32, u32)> = edge_cases.to_vec();
    for _ in 0..NUM_RANDOM_TRIALS {
        cases.push((rng.gen(), rng.gen()));
    }

    // Two outputs per case: result at 2*i, overflow flag at 2*i + 1.
    let mut b = CircuitBuilder::new();
    let mut inputs = CpuInputList::new();
    for &(a, c) in &cases {
        let lhs = b.input(ValueKind::FheUint(32)).unwrap();
        let rhs = b.input(ValueKind::FheUint(32)).unwrap();
        let (val, ovf) = build(&mut b, lhs, rhs).unwrap();
        b.output(val).unwrap();
        b.output(ovf).unwrap();
        inputs.push(FheUint32::encrypt(a, ck));
        inputs.push(FheUint32::encrypt(c, ck));
    }
    let circuit = b.build();
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();

    for (i, &(a, c)) in cases.iter().enumerate() {
        let dec_val: u32 = outputs.get::<FheUint32>(2 * i).decrypt(ck);
        let dec_ovf: bool = outputs.get::<FheBool>(2 * i + 1).decrypt(ck);
        let (exp_val, exp_ovf) = clear(a, c);
        assert_eq!((dec_val, dec_ovf), (exp_val, exp_ovf), "{name}({a}, {c})");
    }
}

/// Single-direction FHE/scalar op `out = build(value, scalar)` or
/// `out = build(scalar, value)`. Builds the circuit once with the closure
/// (which encodes the direction) and the scalar baked in.
fn check_uint32_scalar<B: ExecutionBackend, F, G>(
    ck: &ClientKey,
    backend: &B,
    name: &str,
    build: F,
    clear: G,
    edge_cases: &[u32],
) where
    F: Fn(&mut CircuitBuilder, ValueId) -> Result<ValueId, BuilderError>,
    G: Fn(u32) -> u32,
{
    let mut rng = thread_rng();
    let mut cases: Vec<u32> = edge_cases.to_vec();
    for _ in 0..NUM_RANDOM_TRIALS {
        cases.push(rng.gen());
    }

    let mut b = CircuitBuilder::new();
    let mut inputs = CpuInputList::new();
    for &a in &cases {
        let v = b.input(ValueKind::FheUint(32)).unwrap();
        let r = build(&mut b, v).unwrap();
        b.output(r).unwrap();
        inputs.push(FheUint32::encrypt(a, ck));
    }
    let circuit = b.build();
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();

    for (i, &a) in cases.iter().enumerate() {
        let dec: u32 = outputs.get::<FheUint32>(i).decrypt(ck);
        let expected = clear(a);
        assert_eq!(dec, expected, "{name}({a}) = {dec}, expected {expected}");
    }
}

fn check_uint32_scalar_compare<B: ExecutionBackend, F, G>(
    ck: &ClientKey,
    backend: &B,
    name: &str,
    build: F,
    clear: G,
    edge_cases: &[u32],
) where
    F: Fn(&mut CircuitBuilder, ValueId) -> Result<ValueId, BuilderError>,
    G: Fn(u32) -> bool,
{
    let mut rng = thread_rng();
    let mut cases: Vec<u32> = edge_cases.to_vec();
    for _ in 0..NUM_RANDOM_TRIALS {
        cases.push(rng.gen());
    }

    let mut b = CircuitBuilder::new();
    let mut inputs = CpuInputList::new();
    for &a in &cases {
        let v = b.input(ValueKind::FheUint(32)).unwrap();
        let r = build(&mut b, v).unwrap();
        b.output(r).unwrap();
        inputs.push(FheUint32::encrypt(a, ck));
    }
    let circuit = b.build();
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();

    for (i, &a) in cases.iter().enumerate() {
        let dec: bool = outputs.get::<FheBool>(i).decrypt(ck);
        let expected = clear(a);
        assert_eq!(dec, expected, "{name}({a}) = {dec}, expected {expected}");
    }
}

// ============================================================
// FheInt32 helpers (mirror of FheUint32, signed)
// ============================================================

fn check_int32_binary<B: ExecutionBackend, F, G, R>(
    ck: &ClientKey,
    backend: &B,
    name: &str,
    build: F,
    clear: G,
    edge_cases: &[(i32, i32)],
    rhs_sample: R,
) where
    F: Fn(&mut CircuitBuilder, ValueId, ValueId) -> Result<ValueId, BuilderError>,
    G: Fn(i32, i32) -> i32,
    R: Fn(&mut ThreadRng) -> i32,
{
    let mut rng = thread_rng();
    let mut cases: Vec<(i32, i32)> = edge_cases.to_vec();
    for _ in 0..NUM_RANDOM_TRIALS {
        cases.push((rand_i32(&mut rng), rhs_sample(&mut rng)));
    }

    let mut b = CircuitBuilder::new();
    let mut inputs = CpuInputList::new();
    for &(a, c) in &cases {
        let lhs = b.input(ValueKind::FheInt(32)).unwrap();
        let rhs = b.input(ValueKind::FheInt(32)).unwrap();
        let r = build(&mut b, lhs, rhs).unwrap();
        b.output(r).unwrap();
        inputs.push(FheInt32::encrypt(a, ck));
        inputs.push(FheInt32::encrypt(c, ck));
    }
    let circuit = b.build();
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();

    for (i, &(a, c)) in cases.iter().enumerate() {
        let dec: i32 = outputs.get::<FheInt32>(i).decrypt(ck);
        let expected = clear(a, c);
        assert_eq!(
            dec, expected,
            "{name}({a}, {c}) = {dec}, expected {expected}"
        );
    }
}

fn check_int32_compare<B: ExecutionBackend, F, G>(
    ck: &ClientKey,
    backend: &B,
    name: &str,
    build: F,
    clear: G,
    edge_cases: &[(i32, i32)],
) where
    F: Fn(&mut CircuitBuilder, ValueId, ValueId) -> Result<ValueId, BuilderError>,
    G: Fn(i32, i32) -> bool,
{
    let mut rng = thread_rng();
    let mut cases: Vec<(i32, i32)> = edge_cases.to_vec();
    for _ in 0..NUM_RANDOM_TRIALS {
        cases.push((rng.gen(), rng.gen()));
    }

    let mut b = CircuitBuilder::new();
    let mut inputs = CpuInputList::new();
    for &(a, c) in &cases {
        let lhs = b.input(ValueKind::FheInt(32)).unwrap();
        let rhs = b.input(ValueKind::FheInt(32)).unwrap();
        let r = build(&mut b, lhs, rhs).unwrap();
        b.output(r).unwrap();
        inputs.push(FheInt32::encrypt(a, ck));
        inputs.push(FheInt32::encrypt(c, ck));
    }
    let circuit = b.build();
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();

    for (i, &(a, c)) in cases.iter().enumerate() {
        let dec: bool = outputs.get::<FheBool>(i).decrypt(ck);
        let expected = clear(a, c);
        assert_eq!(
            dec, expected,
            "{name}({a}, {c}) = {dec}, expected {expected}"
        );
    }
}

fn check_int32_unary<B: ExecutionBackend, F, G>(
    ck: &ClientKey,
    backend: &B,
    name: &str,
    build: F,
    clear: G,
    edge_cases: &[i32],
) where
    F: Fn(&mut CircuitBuilder, ValueId) -> Result<ValueId, BuilderError>,
    G: Fn(i32) -> i32,
{
    let mut rng = thread_rng();
    let mut cases: Vec<i32> = edge_cases.to_vec();
    for _ in 0..NUM_RANDOM_TRIALS {
        cases.push(rng.gen());
    }

    let mut b = CircuitBuilder::new();
    let mut inputs = CpuInputList::new();
    for &a in &cases {
        let v = b.input(ValueKind::FheInt(32)).unwrap();
        let r = build(&mut b, v).unwrap();
        b.output(r).unwrap();
        inputs.push(FheInt32::encrypt(a, ck));
    }
    let circuit = b.build();
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();

    for (i, &a) in cases.iter().enumerate() {
        let dec: i32 = outputs.get::<FheInt32>(i).decrypt(ck);
        let expected = clear(a);
        assert_eq!(dec, expected, "{name}({a}) = {dec}, expected {expected}");
    }
}

fn check_int32_overflowing<B: ExecutionBackend, F, G>(
    ck: &ClientKey,
    backend: &B,
    name: &str,
    build: F,
    clear: G,
    edge_cases: &[(i32, i32)],
) where
    F: Fn(&mut CircuitBuilder, ValueId, ValueId) -> Result<(ValueId, ValueId), BuilderError>,
    G: Fn(i32, i32) -> (i32, bool),
{
    let mut rng = thread_rng();
    let mut cases: Vec<(i32, i32)> = edge_cases.to_vec();
    for _ in 0..NUM_RANDOM_TRIALS {
        cases.push((rng.gen(), rng.gen()));
    }

    // Two outputs per case: result at 2*i, overflow flag at 2*i + 1.
    let mut b = CircuitBuilder::new();
    let mut inputs = CpuInputList::new();
    for &(a, c) in &cases {
        let lhs = b.input(ValueKind::FheInt(32)).unwrap();
        let rhs = b.input(ValueKind::FheInt(32)).unwrap();
        let (val, ovf) = build(&mut b, lhs, rhs).unwrap();
        b.output(val).unwrap();
        b.output(ovf).unwrap();
        inputs.push(FheInt32::encrypt(a, ck));
        inputs.push(FheInt32::encrypt(c, ck));
    }
    let circuit = b.build();
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();

    for (i, &(a, c)) in cases.iter().enumerate() {
        let dec_val: i32 = outputs.get::<FheInt32>(2 * i).decrypt(ck);
        let dec_ovf: bool = outputs.get::<FheBool>(2 * i + 1).decrypt(ck);
        let (exp_val, exp_ovf) = clear(a, c);
        assert_eq!((dec_val, dec_ovf), (exp_val, exp_ovf), "{name}({a}, {c})");
    }
}

pub(crate) fn fheuint32_is_even_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let v = b.input(ValueKind::FheUint(32)).unwrap();
    let r = b.fhe_is_even(v).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    for a in [0u32, 1, 2, 3, u32::MAX, 0xDEAD_BEEF] {
        let mut inputs = CpuInputList::new();
        inputs.push(FheUint32::encrypt(a, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: bool = outputs.get::<FheBool>(0).decrypt(ck);
        assert_eq!(dec, a % 2 == 0, "is_even({a}) = {dec}");
    }
}

pub(crate) fn fheuint32_is_odd_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let v = b.input(ValueKind::FheUint(32)).unwrap();
    let r = b.fhe_is_odd(v).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    for a in [0u32, 1, 2, 3, u32::MAX, 0xDEAD_BEEF] {
        let mut inputs = CpuInputList::new();
        inputs.push(FheUint32::encrypt(a, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: bool = outputs.get::<FheBool>(0).decrypt(ck);
        assert_eq!(dec, a % 2 == 1, "is_odd({a}) = {dec}");
    }
}

pub(crate) fn fheuint32_checked_ilog2_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let v = b.input(ValueKind::FheUint(32)).unwrap();
    let (log, present) = b.fhe_checked_ilog2(v).unwrap();
    b.output(log).unwrap();
    b.output(present).unwrap();
    let circuit = b.build();

    // Include 0 — `checked_ilog2(0)` should return present=false.
    for a in [0u32, 1, 2, 3, 7, u32::MAX, 0xDEAD_BEEF] {
        let mut inputs = CpuInputList::new();
        inputs.push(FheUint32::encrypt(a, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec_log: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
        let dec_present: bool = outputs.get::<FheBool>(1).decrypt(ck);
        let expected_present = a > 0;
        assert_eq!(dec_present, expected_present, "checked_ilog2({a}).present");
        if expected_present {
            assert_eq!(dec_log, a.ilog2(), "checked_ilog2({a}).log");
        }
    }
}

pub(crate) fn fheuint32_overflowing_neg_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let v = b.input(ValueKind::FheUint(32)).unwrap();
    let (r, o) = b.fhe_overflowing_neg(v).unwrap();
    b.output(r).unwrap();
    b.output(o).unwrap();
    let circuit = b.build();

    for a in [0u32, 1, u32::MAX, 0xDEAD_BEEF] {
        let mut inputs = CpuInputList::new();
        inputs.push(FheUint32::encrypt(a, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec_val: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
        let dec_ovf: bool = outputs.get::<FheBool>(1).decrypt(ck);
        let (exp_val, exp_ovf) = a.overflowing_neg();
        assert_eq!(
            (dec_val, dec_ovf),
            (exp_val, exp_ovf),
            "overflowing_neg({a})"
        );
    }
}

pub(crate) fn fheint32_overflowing_neg_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let v = b.input(ValueKind::FheInt(32)).unwrap();
    let (r, o) = b.fhe_overflowing_neg(v).unwrap();
    b.output(r).unwrap();
    b.output(o).unwrap();
    let circuit = b.build();

    for a in [0i32, 1, -1, i32::MIN, i32::MAX] {
        let mut inputs = CpuInputList::new();
        inputs.push(FheInt32::encrypt(a, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec_val: i32 = outputs.get::<FheInt32>(0).decrypt(ck);
        let dec_ovf: bool = outputs.get::<FheBool>(1).decrypt(ck);
        let (exp_val, exp_ovf) = a.overflowing_neg();
        assert_eq!(
            (dec_val, dec_ovf),
            (exp_val, exp_ovf),
            "overflowing_neg({a})"
        );
    }
}

pub(crate) fn fheuint32_div_rem_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let l = b.input(ValueKind::FheUint(32)).unwrap();
    let r = b.input(ValueKind::FheUint(32)).unwrap();
    let (q, m) = b.fhe_div_rem(l, r).unwrap();
    b.output(q).unwrap();
    b.output(m).unwrap();
    let circuit = b.build();

    for (a, c) in [(42u32, 5), (100, 7), (u32::MAX, 1), (0, 12345)] {
        let mut inputs = CpuInputList::new();
        inputs.push(FheUint32::encrypt(a, ck));
        inputs.push(FheUint32::encrypt(c, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec_q: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
        let dec_m: u32 = outputs.get::<FheUint32>(1).decrypt(ck);
        assert_eq!(dec_q, a / c, "div_rem({a}, {c}).0");
        assert_eq!(dec_m, a % c, "div_rem({a}, {c}).1");
    }
}

pub(crate) fn fheuint32_scalar_overflowing_add_case<B: ExecutionBackend>(
    ck: &ClientKey,
    backend: &B,
) {
    const S: u32 = 42;
    let mut b = CircuitBuilder::new();
    let v = b.input(ValueKind::FheUint(32)).unwrap();
    let (r, o) = b.fhe_overflowing_add(v, S).unwrap();
    b.output(r).unwrap();
    b.output(o).unwrap();
    let circuit = b.build();

    for a in [0u32, 1, u32::MAX - 10, u32::MAX] {
        let mut inputs = CpuInputList::new();
        inputs.push(FheUint32::encrypt(a, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec_val: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
        let dec_ovf: bool = outputs.get::<FheBool>(1).decrypt(ck);
        let (exp_val, exp_ovf) = a.overflowing_add(S);
        assert_eq!(
            (dec_val, dec_ovf),
            (exp_val, exp_ovf),
            "overflowing_add({a}, {S})"
        );
    }
}

pub(crate) fn fheuint32_scalar_overflowing_sub_case<B: ExecutionBackend>(
    ck: &ClientKey,
    backend: &B,
) {
    const S: u32 = 42;
    let mut b = CircuitBuilder::new();
    let v = b.input(ValueKind::FheUint(32)).unwrap();
    let (r, o) = b.fhe_overflowing_sub(v, S).unwrap();
    b.output(r).unwrap();
    b.output(o).unwrap();
    let circuit = b.build();

    for a in [0u32, 1, S, S + 1, u32::MAX] {
        let mut inputs = CpuInputList::new();
        inputs.push(FheUint32::encrypt(a, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec_val: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
        let dec_ovf: bool = outputs.get::<FheBool>(1).decrypt(ck);
        let (exp_val, exp_ovf) = a.overflowing_sub(S);
        assert_eq!(
            (dec_val, dec_ovf),
            (exp_val, exp_ovf),
            "overflowing_sub({a}, {S})"
        );
    }
}

pub(crate) fn fheuint8_fused_mul_scalar_div_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    use crate::FheUint8;

    // (a * b) / div_scalar with widening; FheUint8 -> wide FheUint16.
    const DIV: u8 = 10;
    let mut b = CircuitBuilder::new();
    let l = b.input(ValueKind::FheUint(8)).unwrap();
    let r = b.input(ValueKind::FheUint(8)).unwrap();
    // ScalarValue::Unsigned holds u128; we feed via u32 (any unsigned works).
    let result = b.fhe_fused_mul_scalar_div(l, r, DIV as u128).unwrap();
    b.output(result).unwrap();
    let circuit = b.build();

    // Widened arithmetic prevents the mul from overflowing u8 before the div.
    for (a, c) in [(7u8, 9u8), (200, 200), (255, 255), (1, 1), (0, 200)] {
        let mut inputs = CpuInputList::new();
        inputs.push(FheUint8::encrypt(a, ck));
        inputs.push(FheUint8::encrypt(c, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: u8 = outputs.get::<FheUint8>(0).decrypt(ck);
        let expected = ((a as u16 * c as u16) / DIV as u16) as u8;
        assert_eq!(dec, expected, "fused_mul_scalar_div({a}, {c}, /{DIV})");
    }
}

pub(crate) fn fheuint8_fused_scalar_mul_scalar_div_case<B: ExecutionBackend>(
    ck: &ClientKey,
    backend: &B,
) {
    use crate::FheUint8;

    // (v * MUL) / DIV with widening; FheUint8 -> FheUint16.
    const MUL: u8 = 7;
    const DIV: u8 = 3;
    let mut b = CircuitBuilder::new();
    let v = b.input(ValueKind::FheUint(8)).unwrap();
    let result = b
        .fhe_fused_scalar_mul_scalar_div(v, MUL as u128, DIV as u128)
        .unwrap();
    b.output(result).unwrap();
    let circuit = b.build();

    for a in [0u8, 1, 100, 200, 255] {
        let mut inputs = CpuInputList::new();
        inputs.push(FheUint8::encrypt(a, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: u8 = outputs.get::<FheUint8>(0).decrypt(ck);
        let expected = ((a as u16 * MUL as u16) / DIV as u16) as u8;
        assert_eq!(
            dec, expected,
            "fused_scalar_mul_scalar_div({a}, *{MUL}, /{DIV})"
        );
    }
}

// ============================================================
// FheInt32 shifts/rotates use FheUint32 rhs
// ============================================================

fn check_int32_shift<B: ExecutionBackend, F, G, R>(
    ck: &ClientKey,
    backend: &B,
    name: &str,
    build: F,
    clear: G,
    edge_cases: &[(i32, u32)],
    rhs_sample: R,
) where
    F: Fn(&mut CircuitBuilder, ValueId, ValueId) -> Result<ValueId, BuilderError>,
    G: Fn(i32, u32) -> i32,
    R: Fn(&mut ThreadRng) -> u32,
{
    let mut rng = thread_rng();
    let mut cases: Vec<(i32, u32)> = edge_cases.to_vec();
    for _ in 0..NUM_RANDOM_TRIALS {
        cases.push((rng.gen(), rhs_sample(&mut rng)));
    }

    let mut b = CircuitBuilder::new();
    let mut inputs = CpuInputList::new();
    for &(a, c) in &cases {
        let lhs = b.input(ValueKind::FheInt(32)).unwrap();
        let rhs = b.input(ValueKind::FheUint(32)).unwrap();
        let r = build(&mut b, lhs, rhs).unwrap();
        b.output(r).unwrap();
        inputs.push(FheInt32::encrypt(a, ck));
        inputs.push(FheUint32::encrypt(c, ck));
    }
    let circuit = b.build();
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();

    for (i, &(a, c)) in cases.iter().enumerate() {
        let dec: i32 = outputs.get::<FheInt32>(i).decrypt(ck);
        let expected = clear(a, c);
        assert_eq!(
            dec, expected,
            "{name}({a}, {c}) = {dec}, expected {expected}"
        );
    }
}

pub(crate) fn cast_fheuint32_to_fheint32_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let v = b.input(ValueKind::FheUint(32)).unwrap();
    let r = b.fhe_cast(v, FheKind::Int(32)).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut rng = thread_rng();
    for _ in 0..NUM_RANDOM_TRIALS {
        let a: u32 = rng.gen();
        let mut inputs = CpuInputList::new();
        inputs.push(FheUint32::encrypt(a, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: i32 = outputs.get::<FheInt32>(0).decrypt(ck);
        assert_eq!(dec, a as i32);
    }
}

pub(crate) fn cast_fheint32_to_fheuint32_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let v = b.input(ValueKind::FheInt(32)).unwrap();
    let r = b.fhe_cast(v, FheKind::Uint(32)).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut rng = thread_rng();
    for _ in 0..NUM_RANDOM_TRIALS {
        let a: i32 = rng.gen();
        let mut inputs = CpuInputList::new();
        inputs.push(FheInt32::encrypt(a, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
        assert_eq!(dec, a as u32);
    }
}

pub(crate) fn cmux_fheuint32_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let cond = b.input(ValueKind::FheBool).unwrap();
    let if_true = b.input(ValueKind::FheUint(32)).unwrap();
    let if_false = b.input(ValueKind::FheUint(32)).unwrap();
    let r = b.fhe_select(cond, if_true, if_false).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut rng = thread_rng();
    for _ in 0..NUM_RANDOM_TRIALS {
        let c: bool = rng.gen();
        let t: u32 = rng.gen();
        let f: u32 = rng.gen();
        let mut inputs = CpuInputList::new();
        inputs.push(FheBool::encrypt(c, ck));
        inputs.push(FheUint32::encrypt(t, ck));
        inputs.push(FheUint32::encrypt(f, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
        assert_eq!(dec, if c { t } else { f });
    }
}

pub(crate) fn oprf_fheuint32_full_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let seed = b.input(ValueKind::Seed).unwrap();
    let r = b.oprf(ValueKind::FheUint(32), seed).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut inputs = CpuInputList::new();
    inputs.push_seed(Seed(0));
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
    let _dec: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
    // No bound to check — any u32 is valid. The fact that decryption succeeds
    // and the value typechecks as u32 is the test.
}

pub(crate) fn oprf_fheuint32_bounded_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let seed = b.input(ValueKind::Seed).unwrap();
    let r = b.oprf_bounded(ValueKind::FheUint(32), seed, 5).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut inputs = CpuInputList::new();
    inputs.push_seed(Seed(42));
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
    let dec: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
    assert!(dec < (1 << 5), "bounded result {dec} must be < 2^5");
}

pub(crate) fn oprf_fheuint32_custom_range_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let upper = std::num::NonZeroU64::new(7).unwrap();
    let mut b = CircuitBuilder::new();
    let seed = b.input(ValueKind::Seed).unwrap();
    let r = b
        .oprf_custom_range(ValueKind::FheUint(32), seed, upper, None)
        .unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut inputs = CpuInputList::new();
    inputs.push_seed(Seed(123));
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
    let dec: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
    assert!(
        (dec as u64) < upper.get(),
        "custom-range result {dec} must be < {upper}"
    );
}

pub(crate) fn oprf_fheint32_full_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let seed = b.input(ValueKind::Seed).unwrap();
    let r = b.oprf(ValueKind::FheInt(32), seed).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut inputs = CpuInputList::new();
    inputs.push_seed(Seed(7));
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
    let _dec: i32 = outputs.get::<FheInt32>(0).decrypt(ck);
    // Any i32 is valid.
}

pub(crate) fn oprf_fheint32_bounded_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let seed = b.input(ValueKind::Seed).unwrap();
    let r = b.oprf_bounded(ValueKind::FheInt(32), seed, 4).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut inputs = CpuInputList::new();
    inputs.push_seed(Seed(99));
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
    let dec: i32 = outputs.get::<FheInt32>(0).decrypt(ck);
    // Signed bounded is uniform in [0, 2^bits).
    assert!(
        (0..(1 << 4)).contains(&dec),
        "signed bounded result {dec} must be in [0, 2^4)"
    );
}

pub(crate) fn oprf_fhebool_full_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let seed = b.input(ValueKind::Seed).unwrap();
    let r = b.oprf(ValueKind::FheBool, seed).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut inputs = CpuInputList::new();
    inputs.push_seed(Seed(13));
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
    let _dec: bool = outputs.get::<FheBool>(0).decrypt(ck);
    // Any bool is valid.
}

pub(crate) fn oprf_is_deterministic_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let build_circuit = || {
        let mut b = CircuitBuilder::new();
        let seed = b.input(ValueKind::Seed).unwrap();
        let r = b.oprf_bounded(ValueKind::FheUint(32), seed, 8).unwrap();
        b.output(r).unwrap();
        b.build()
    };
    let circuit_a = build_circuit();
    let circuit_b = build_circuit();

    let make_inputs = || {
        let mut inputs = CpuInputList::new();
        inputs.push_seed(Seed(2024));
        inputs
    };
    let out_a = backend.execute_cpu_io(&circuit_a, make_inputs()).unwrap();
    let out_b = backend.execute_cpu_io(&circuit_b, make_inputs()).unwrap();

    let dec_a: u32 = out_a.get::<FheUint32>(0).decrypt(ck);
    let dec_b: u32 = out_b.get::<FheUint32>(0).decrypt(ck);
    assert_eq!(dec_a, dec_b, "same seed must yield same OPRF output");
}

pub(crate) fn select_fheuint32_then_fhe_else_scalar_case<B: ExecutionBackend>(
    ck: &ClientKey,
    backend: &B,
) {
    let mut b = CircuitBuilder::new();
    let cond = b.input(ValueKind::FheBool).unwrap();
    let if_true = b.input(ValueKind::FheUint(32)).unwrap();
    const FALSE_SCALAR: u32 = 0xDEAD_BEEF;
    let r = b.fhe_select(cond, if_true, FALSE_SCALAR).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut rng = thread_rng();
    for _ in 0..NUM_RANDOM_TRIALS {
        let c: bool = rng.gen();
        let t: u32 = rng.gen();
        let mut inputs = CpuInputList::new();
        inputs.push(FheBool::encrypt(c, ck));
        inputs.push(FheUint32::encrypt(t, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
        assert_eq!(dec, if c { t } else { FALSE_SCALAR });
    }
}

pub(crate) fn select_fheuint32_then_scalar_else_fhe_case<B: ExecutionBackend>(
    ck: &ClientKey,
    backend: &B,
) {
    let mut b = CircuitBuilder::new();
    let cond = b.input(ValueKind::FheBool).unwrap();
    let if_false = b.input(ValueKind::FheUint(32)).unwrap();
    const TRUE_SCALAR: u32 = 0xCAFE_BABE;
    let r = b.fhe_select(cond, TRUE_SCALAR, if_false).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut rng = thread_rng();
    for _ in 0..NUM_RANDOM_TRIALS {
        let c: bool = rng.gen();
        let f: u32 = rng.gen();
        let mut inputs = CpuInputList::new();
        inputs.push(FheBool::encrypt(c, ck));
        inputs.push(FheUint32::encrypt(f, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
        assert_eq!(dec, if c { TRUE_SCALAR } else { f });
    }
}

pub(crate) fn select_fheuint32_both_scalar_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let cond = b.input(ValueKind::FheBool).unwrap();
    const TRUE_SCALAR: u32 = 0x1234_5678;
    const FALSE_SCALAR: u32 = 0x9ABC_DEF0;
    let r = b
        .fhe_select_const(cond, TRUE_SCALAR, FALSE_SCALAR, FheIntKind::Uint(32))
        .unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut rng = thread_rng();
    for _ in 0..NUM_RANDOM_TRIALS {
        let c: bool = rng.gen();
        let mut inputs = CpuInputList::new();
        inputs.push(FheBool::encrypt(c, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
        assert_eq!(dec, if c { TRUE_SCALAR } else { FALSE_SCALAR });
    }
}

pub(crate) fn select_fheint32_then_fhe_else_scalar_case<B: ExecutionBackend>(
    ck: &ClientKey,
    backend: &B,
) {
    let mut b = CircuitBuilder::new();
    let cond = b.input(ValueKind::FheBool).unwrap();
    let if_true = b.input(ValueKind::FheInt(32)).unwrap();
    const FALSE_SCALAR: i32 = -123_456;
    let r = b.fhe_select(cond, if_true, FALSE_SCALAR).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut rng = thread_rng();
    for _ in 0..NUM_RANDOM_TRIALS {
        let c: bool = rng.gen();
        let t: i32 = rng.gen();
        let mut inputs = CpuInputList::new();
        inputs.push(FheBool::encrypt(c, ck));
        inputs.push(FheInt32::encrypt(t, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: i32 = outputs.get::<FheInt32>(0).decrypt(ck);
        assert_eq!(dec, if c { t } else { FALSE_SCALAR });
    }
}

pub(crate) fn select_fheint32_then_scalar_else_fhe_case<B: ExecutionBackend>(
    ck: &ClientKey,
    backend: &B,
) {
    let mut b = CircuitBuilder::new();
    let cond = b.input(ValueKind::FheBool).unwrap();
    let if_false = b.input(ValueKind::FheInt(32)).unwrap();
    const TRUE_SCALAR: i32 = i32::MAX;
    let r = b.fhe_select(cond, TRUE_SCALAR, if_false).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut rng = thread_rng();
    for _ in 0..NUM_RANDOM_TRIALS {
        let c: bool = rng.gen();
        let f: i32 = rng.gen();
        let mut inputs = CpuInputList::new();
        inputs.push(FheBool::encrypt(c, ck));
        inputs.push(FheInt32::encrypt(f, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: i32 = outputs.get::<FheInt32>(0).decrypt(ck);
        assert_eq!(dec, if c { TRUE_SCALAR } else { f });
    }
}

pub(crate) fn select_fheint32_both_scalar_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let cond = b.input(ValueKind::FheBool).unwrap();
    const TRUE_SCALAR: i32 = i32::MIN;
    const FALSE_SCALAR: i32 = i32::MAX;
    let r = b
        .fhe_select_const(cond, TRUE_SCALAR, FALSE_SCALAR, FheIntKind::Int(32))
        .unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut rng = thread_rng();
    for _ in 0..NUM_RANDOM_TRIALS {
        let c: bool = rng.gen();
        let mut inputs = CpuInputList::new();
        inputs.push(FheBool::encrypt(c, ck));
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: i32 = outputs.get::<FheInt32>(0).decrypt(ck);
        assert_eq!(dec, if c { TRUE_SCALAR } else { FALSE_SCALAR });
    }
}

pub(crate) fn contains_fheuint32_found_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let needle = b.input(ValueKind::FheUint(32)).unwrap();
    let h0 = b.input(ValueKind::FheUint(32)).unwrap();
    let h1 = b.input(ValueKind::FheUint(32)).unwrap();
    let h2 = b.input(ValueKind::FheUint(32)).unwrap();
    let r = b.fhe_contains(&[h0, h1, h2], needle).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut rng = thread_rng();
    for _ in 0..NUM_RANDOM_TRIALS {
        let haystack = [rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>()];
        // Always look for an element that IS in the haystack.
        let needle_val = haystack[rng.gen_range(0..3)];
        let mut inputs = CpuInputList::new();
        inputs.push(FheUint32::encrypt(needle_val, ck));
        for h in haystack {
            inputs.push(FheUint32::encrypt(h, ck));
        }
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: bool = outputs.get::<FheBool>(0).decrypt(ck);
        assert!(dec, "needle {needle_val} should be in {haystack:?}");
    }
}

pub(crate) fn contains_fheuint32_not_found_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let needle = b.input(ValueKind::FheUint(32)).unwrap();
    let h0 = b.input(ValueKind::FheUint(32)).unwrap();
    let h1 = b.input(ValueKind::FheUint(32)).unwrap();
    let r = b.fhe_contains(&[h0, h1], needle).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    // Fixed haystack {10, 20}; query for 30.
    let mut inputs = CpuInputList::new();
    inputs.push(FheUint32::encrypt(30u32, ck));
    inputs.push(FheUint32::encrypt(10u32, ck));
    inputs.push(FheUint32::encrypt(20u32, ck));
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
    let dec: bool = outputs.get::<FheBool>(0).decrypt(ck);
    assert!(!dec, "30 should not be in {{10, 20}}");
}

pub(crate) fn contains_fheint32_found_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    let mut b = CircuitBuilder::new();
    let needle = b.input(ValueKind::FheInt(32)).unwrap();
    let h0 = b.input(ValueKind::FheInt(32)).unwrap();
    let h1 = b.input(ValueKind::FheInt(32)).unwrap();
    let h2 = b.input(ValueKind::FheInt(32)).unwrap();
    let r = b.fhe_contains(&[h0, h1, h2], needle).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut inputs = CpuInputList::new();
    inputs.push(FheInt32::encrypt(-7i32, ck));
    inputs.push(FheInt32::encrypt(1i32, ck));
    inputs.push(FheInt32::encrypt(-7i32, ck));
    inputs.push(FheInt32::encrypt(42i32, ck));
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
    let dec: bool = outputs.get::<FheBool>(0).decrypt(ck);
    assert!(dec, "-7 should be in {{1, -7, 42}}");
}

pub(crate) fn contains_scalar_fheuint32_found_case<B: ExecutionBackend>(
    ck: &ClientKey,
    backend: &B,
) {
    let mut b = CircuitBuilder::new();
    let h0 = b.input(ValueKind::FheUint(32)).unwrap();
    let h1 = b.input(ValueKind::FheUint(32)).unwrap();
    let h2 = b.input(ValueKind::FheUint(32)).unwrap();
    const NEEDLE: u32 = 0xDEAD_BEEF;
    let r = b.fhe_contains(&[h0, h1, h2], NEEDLE).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut inputs = CpuInputList::new();
    inputs.push(FheUint32::encrypt(0u32, ck));
    inputs.push(FheUint32::encrypt(NEEDLE, ck));
    inputs.push(FheUint32::encrypt(0xFFFFu32, ck));
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
    let dec: bool = outputs.get::<FheBool>(0).decrypt(ck);
    assert!(dec, "clear needle 0xDEADBEEF should be in haystack");
}

pub(crate) fn contains_scalar_fheint32_not_found_case<B: ExecutionBackend>(
    ck: &ClientKey,
    backend: &B,
) {
    let mut b = CircuitBuilder::new();
    let h0 = b.input(ValueKind::FheInt(32)).unwrap();
    let h1 = b.input(ValueKind::FheInt(32)).unwrap();
    const NEEDLE: i32 = -99;
    let r = b.fhe_contains(&[h0, h1], NEEDLE).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    let mut inputs = CpuInputList::new();
    inputs.push(FheInt32::encrypt(1i32, ck));
    inputs.push(FheInt32::encrypt(2i32, ck));
    let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
    let dec: bool = outputs.get::<FheBool>(0).decrypt(ck);
    assert!(!dec, "-99 should not be in {{1, 2}}");
}

pub(crate) fn constant_op_round_trip_case<B: ExecutionBackend>(backend: &B) {
    // A standalone Constant op feeds straight into an Output of clear kind.
    // Validates: builder accepts clear-typed Output, executor materializes
    // RuntimeValue::ClearUint, scheduler passes it through unchanged.
    let mut b = CircuitBuilder::new();
    let c = b.constant(42u32, ClearKind::Uint(32)).unwrap();
    b.output(c).unwrap();
    let circuit = b.build();

    let outputs = backend
        .execute_cpu_io(&circuit, CpuInputList::new())
        .unwrap();
    match &outputs.outputs[0] {
        RuntimeValue::ClearUint(v) => assert_eq!(*v, 42),
        other => panic!("expected ClearUint(42), got {other:?}"),
    }
}

pub(crate) fn runtime_clear_input_via_fhe_add_case<B: ExecutionBackend>(
    ck: &ClientKey,
    backend: &B,
) {
    // Circuit with one FHE input + one runtime clear input, fed into
    // fhe_add. The clear value isn't baked into the IR — it flows through
    // the input list at execute time.
    let mut b = CircuitBuilder::new();
    let fhe = b.input(ValueKind::FheUint(32)).unwrap();
    let clear = b.input(ValueKind::Uint(32)).unwrap();
    let r = b.fhe_add(fhe, clear).unwrap();
    b.output(r).unwrap();
    let circuit = b.build();

    // Sanity check: the second arg of the FheScalarAdd op was *not* lowered
    // to a Constant — it must remain an Input-produced value.
    let mut found_scalar_add = false;
    for op_ref in circuit.ir().walk_ops_linear() {
        if let HlInstructionSet::FheScalarAdd { .. } = op_ref.get_instruction() {
            let args = op_ref.get_arg_valids();
            assert_eq!(circuit.clear_value_at(args[1]), None);
            assert!(!circuit.is_compile_time_constant(args[1]));
            found_scalar_add = true;
        }
    }
    assert!(found_scalar_add);

    let mut rng = thread_rng();
    for _ in 0..NUM_RANDOM_TRIALS {
        let a: u32 = rand_u32(&mut rng);
        let c: u32 = rand_u32(&mut rng);
        let mut inputs = CpuInputList::new();
        inputs.push(FheUint32::encrypt(a, ck));
        // `From<u32> for RuntimeValue` → `ClearUint(u128)`.
        inputs.push(c);
        let outputs = backend.execute_cpu_io(&circuit, inputs).unwrap();
        let dec: u32 = outputs.get::<FheUint32>(0).decrypt(ck);
        assert_eq!(dec, a.wrapping_add(c), "fhe_add({a}, {c}) = {dec}");
    }
}

// -----------------------------------------------------------------
// Operation cases delegating to the parametrised `check_*` helpers.
// -----------------------------------------------------------------

pub(crate) fn fheuint32_add_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "add",
        |b, l, r| b.fhe_add(l, r),
        u32::wrapping_add,
        &[(u32::MAX, 1), (0, 0)],
        rand_u32,
    );
}

pub(crate) fn fheuint32_sub_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "sub",
        |b, l, r| b.fhe_sub(l, r),
        u32::wrapping_sub,
        &[(0, 1)],
        rand_u32,
    );
}

pub(crate) fn fheuint32_mul_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "mul",
        |b, l, r| b.fhe_mul(l, r),
        u32::wrapping_mul,
        &[(0, 1234), (1234, 0), (1, 1234)],
        rand_u32,
    );
}

pub(crate) fn fheuint32_div_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "div",
        |b, l, r| b.fhe_div(l, r),
        |a, b| a / b,
        &[(42, 1), (0, 7)],
        rand_u32_nonzero,
    );
}

pub(crate) fn fheuint32_rem_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "rem",
        |b, l, r| b.fhe_rem(l, r),
        |a, b| a % b,
        &[(42, 1), (0, 7)],
        rand_u32_nonzero,
    );
}

pub(crate) fn fheuint32_bitand_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "bitand",
        |b, l, r| b.fhe_bitand(l, r),
        |a, b| a & b,
        &[],
        rand_u32,
    );
}

pub(crate) fn fheuint32_bitor_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "bitor",
        |b, l, r| b.fhe_bitor(l, r),
        |a, b| a | b,
        &[],
        rand_u32,
    );
}

pub(crate) fn fheuint32_bitxor_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "bitxor",
        |b, l, r| b.fhe_bitxor(l, r),
        |a, b| a ^ b,
        &[],
        rand_u32,
    );
}

pub(crate) fn fheuint32_min_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "min",
        |b, l, r| b.fhe_min(l, r),
        u32::min,
        &[(0, u32::MAX), (u32::MAX, 0)],
        rand_u32,
    );
}

pub(crate) fn fheuint32_max_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "max",
        |b, l, r| b.fhe_max(l, r),
        u32::max,
        &[(0, u32::MAX), (u32::MAX, 0)],
        rand_u32,
    );
}

pub(crate) fn fheuint32_shl_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "shl",
        |b, l, r| b.fhe_shl(l, r),
        u32::wrapping_shl,
        &[(0xDEAD_BEEF, 0), (0xDEAD_BEEF, 31)],
        rand_shift_amount,
    );
}

pub(crate) fn fheuint32_shr_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "shr",
        |b, l, r| b.fhe_shr(l, r),
        u32::wrapping_shr,
        &[(0xDEAD_BEEF, 0), (0xDEAD_BEEF, 31)],
        rand_shift_amount,
    );
}

pub(crate) fn fheuint32_rotate_left_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "rotate_left",
        |b, l, r| b.fhe_rotate_left(l, r),
        u32::rotate_left,
        &[(0xDEAD_BEEF, 0), (0xDEAD_BEEF, 31)],
        rand_shift_amount,
    );
}

pub(crate) fn fheuint32_rotate_right_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_binary(
        ck,
        backend,
        "rotate_right",
        |b, l, r| b.fhe_rotate_right(l, r),
        u32::rotate_right,
        &[(0xDEAD_BEEF, 0), (0xDEAD_BEEF, 31)],
        rand_shift_amount,
    );
}

pub(crate) fn fheuint32_eq_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_compare(
        ck,
        backend,
        "eq",
        |b, l, r| b.fhe_eq(l, r),
        |a, b| a == b,
        &[(42, 42), (0, 0), (u32::MAX, u32::MAX)],
    );
}

pub(crate) fn fheuint32_ne_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_compare(
        ck,
        backend,
        "ne",
        |b, l, r| b.fhe_ne(l, r),
        |a, b| a != b,
        &[(42, 42), (0, u32::MAX)],
    );
}

pub(crate) fn fheuint32_lt_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_compare(
        ck,
        backend,
        "lt",
        |b, l, r| b.fhe_lt(l, r),
        |a, b| a < b,
        &[(42, 42), (0, u32::MAX), (u32::MAX, 0)],
    );
}

pub(crate) fn fheuint32_le_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_compare(
        ck,
        backend,
        "le",
        |b, l, r| b.fhe_le(l, r),
        |a, b| a <= b,
        &[(42, 42), (0, u32::MAX), (u32::MAX, 0)],
    );
}

pub(crate) fn fheuint32_gt_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_compare(
        ck,
        backend,
        "gt",
        |b, l, r| b.fhe_gt(l, r),
        |a, b| a > b,
        &[(42, 42), (0, u32::MAX), (u32::MAX, 0)],
    );
}

pub(crate) fn fheuint32_ge_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_compare(
        ck,
        backend,
        "ge",
        |b, l, r| b.fhe_ge(l, r),
        |a, b| a >= b,
        &[(42, 42), (0, u32::MAX), (u32::MAX, 0)],
    );
}

pub(crate) fn fheuint32_not_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_unary(
        ck,
        backend,
        "not",
        |b, v| b.fhe_not(v),
        |a| !a,
        &[0, u32::MAX, 0xDEAD_BEEF],
    );
}

pub(crate) fn fheuint32_leading_zeros_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_unary(
        ck,
        backend,
        "leading_zeros",
        |b, v| b.fhe_leading_zeros(v),
        |a| a.leading_zeros(),
        &[0, 1, u32::MAX, 0xDEAD_BEEF],
    );
}

pub(crate) fn fheuint32_leading_ones_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_unary(
        ck,
        backend,
        "leading_ones",
        |b, v| b.fhe_leading_ones(v),
        |a| a.leading_ones(),
        &[0, u32::MAX, 0xFFFF_0000, 0x8000_0000],
    );
}

pub(crate) fn fheuint32_trailing_zeros_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_unary(
        ck,
        backend,
        "trailing_zeros",
        |b, v| b.fhe_trailing_zeros(v),
        |a| a.trailing_zeros(),
        &[0, 1, u32::MAX, 0x0001_0000],
    );
}

pub(crate) fn fheuint32_trailing_ones_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_unary(
        ck,
        backend,
        "trailing_ones",
        |b, v| b.fhe_trailing_ones(v),
        |a| a.trailing_ones(),
        &[0, 1, u32::MAX, 0x0000_FFFF],
    );
}

pub(crate) fn fheuint32_count_ones_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_unary(
        ck,
        backend,
        "count_ones",
        |b, v| b.fhe_count_ones(v),
        |a| a.count_ones(),
        &[0, 1, u32::MAX, 0xDEAD_BEEF],
    );
}

pub(crate) fn fheuint32_count_zeros_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_unary(
        ck,
        backend,
        "count_zeros",
        |b, v| b.fhe_count_zeros(v),
        |a| a.count_zeros(),
        &[0, 1, u32::MAX, 0xDEAD_BEEF],
    );
}

pub(crate) fn fheuint32_reverse_bits_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_unary(
        ck,
        backend,
        "reverse_bits",
        |b, v| b.fhe_reverse_bits(v),
        |a| a.reverse_bits(),
        &[0, 1, u32::MAX, 0xDEAD_BEEF],
    );
}

pub(crate) fn fheint32_reverse_bits_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_unary(
        ck,
        backend,
        "reverse_bits",
        |b, v| b.fhe_reverse_bits(v),
        |a| (a as u32).reverse_bits() as i32,
        &[0, 1, -1, i32::MIN, i32::MAX],
    );
}

pub(crate) fn fheint32_abs_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_unary(
        ck,
        backend,
        "abs",
        |b, v| b.fhe_abs(v),
        |a| a.wrapping_abs(),
        &[0, 1, -1, i32::MIN, i32::MAX],
    );
}

pub(crate) fn fheuint32_overflowing_add_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_overflowing(
        ck,
        backend,
        "overflowing_add",
        |b, l, r| b.fhe_overflowing_add(l, r),
        u32::overflowing_add,
        &[(u32::MAX, 1), (0, 0), (u32::MAX, u32::MAX)],
    );
}

pub(crate) fn fheuint32_overflowing_sub_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_overflowing(
        ck,
        backend,
        "overflowing_sub",
        |b, l, r| b.fhe_overflowing_sub(l, r),
        u32::overflowing_sub,
        &[(0, 1), (u32::MAX, u32::MAX)],
    );
}

pub(crate) fn fheuint32_overflowing_mul_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_overflowing(
        ck,
        backend,
        "overflowing_mul",
        |b, l, r| b.fhe_overflowing_mul(l, r),
        u32::overflowing_mul,
        &[(u32::MAX, 2), (0, 0), (1, u32::MAX)],
    );
}

pub(crate) fn fheint32_add_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_binary(
        ck,
        backend,
        "add",
        |b, l, r| b.fhe_add(l, r),
        i32::wrapping_add,
        &[(i32::MAX, 1), (0, 0), (i32::MIN, -1)],
        rand_i32,
    );
}

pub(crate) fn fheint32_sub_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_binary(
        ck,
        backend,
        "sub",
        |b, l, r| b.fhe_sub(l, r),
        i32::wrapping_sub,
        &[(i32::MIN, 1), (0, i32::MIN)],
        rand_i32,
    );
}

pub(crate) fn fheint32_mul_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_binary(
        ck,
        backend,
        "mul",
        |b, l, r| b.fhe_mul(l, r),
        i32::wrapping_mul,
        &[(0, 1234), (-1, i32::MIN)],
        rand_i32,
    );
}

pub(crate) fn fheint32_div_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_binary(
        ck,
        backend,
        "div",
        |b, l, r| b.fhe_div(l, r),
        |a, b| a.wrapping_div(b),
        &[(42, 1), (0, 7), (i32::MIN, -1)],
        rand_i32_nonzero,
    );
}

pub(crate) fn fheint32_rem_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_binary(
        ck,
        backend,
        "rem",
        |b, l, r| b.fhe_rem(l, r),
        |a, b| a.wrapping_rem(b),
        &[(42, 1), (0, 7), (i32::MIN, -1)],
        rand_i32_nonzero,
    );
}

pub(crate) fn fheint32_bitand_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_binary(
        ck,
        backend,
        "bitand",
        |b, l, r| b.fhe_bitand(l, r),
        |a, b| a & b,
        &[],
        rand_i32,
    );
}

pub(crate) fn fheint32_bitor_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_binary(
        ck,
        backend,
        "bitor",
        |b, l, r| b.fhe_bitor(l, r),
        |a, b| a | b,
        &[],
        rand_i32,
    );
}

pub(crate) fn fheint32_bitxor_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_binary(
        ck,
        backend,
        "bitxor",
        |b, l, r| b.fhe_bitxor(l, r),
        |a, b| a ^ b,
        &[],
        rand_i32,
    );
}

pub(crate) fn fheint32_min_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_binary(
        ck,
        backend,
        "min",
        |b, l, r| b.fhe_min(l, r),
        i32::min,
        &[(i32::MIN, i32::MAX), (i32::MAX, i32::MIN)],
        rand_i32,
    );
}

pub(crate) fn fheint32_max_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_binary(
        ck,
        backend,
        "max",
        |b, l, r| b.fhe_max(l, r),
        i32::max,
        &[(i32::MIN, i32::MAX), (i32::MAX, i32::MIN)],
        rand_i32,
    );
}

pub(crate) fn fheint32_eq_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_compare(
        ck,
        backend,
        "eq",
        |b, l, r| b.fhe_eq(l, r),
        |a, b| a == b,
        &[(42, 42), (i32::MIN, i32::MIN)],
    );
}

pub(crate) fn fheint32_ne_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_compare(
        ck,
        backend,
        "ne",
        |b, l, r| b.fhe_ne(l, r),
        |a, b| a != b,
        &[(42, 42), (i32::MIN, i32::MAX)],
    );
}

pub(crate) fn fheint32_lt_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_compare(
        ck,
        backend,
        "lt",
        |b, l, r| b.fhe_lt(l, r),
        |a, b| a < b,
        &[(0, 0), (i32::MIN, i32::MAX), (-1, 1)],
    );
}

pub(crate) fn fheint32_le_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_compare(
        ck,
        backend,
        "le",
        |b, l, r| b.fhe_le(l, r),
        |a, b| a <= b,
        &[(0, 0), (i32::MIN, i32::MAX), (1, -1)],
    );
}

pub(crate) fn fheint32_gt_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_compare(
        ck,
        backend,
        "gt",
        |b, l, r| b.fhe_gt(l, r),
        |a, b| a > b,
        &[(0, 0), (i32::MIN, i32::MAX), (1, -1)],
    );
}

pub(crate) fn fheint32_ge_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_compare(
        ck,
        backend,
        "ge",
        |b, l, r| b.fhe_ge(l, r),
        |a, b| a >= b,
        &[(0, 0), (i32::MIN, i32::MAX), (-1, 1)],
    );
}

pub(crate) fn fheint32_not_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_unary(
        ck,
        backend,
        "not",
        |b, v| b.fhe_not(v),
        |a| !a,
        &[0, -1, i32::MIN, i32::MAX],
    );
}

pub(crate) fn fheint32_neg_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_unary(
        ck,
        backend,
        "neg",
        |b, v| b.fhe_neg(v),
        i32::wrapping_neg,
        &[0, 1, -1, i32::MIN, i32::MAX],
    );
}

pub(crate) fn fheint32_overflowing_add_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_overflowing(
        ck,
        backend,
        "overflowing_add",
        |b, l, r| b.fhe_overflowing_add(l, r),
        i32::overflowing_add,
        &[(i32::MAX, 1), (i32::MIN, -1), (0, 0)],
    );
}

pub(crate) fn fheint32_overflowing_sub_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_overflowing(
        ck,
        backend,
        "overflowing_sub",
        |b, l, r| b.fhe_overflowing_sub(l, r),
        i32::overflowing_sub,
        &[(i32::MIN, 1), (i32::MAX, -1), (0, 0)],
    );
}

pub(crate) fn fheint32_overflowing_mul_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_overflowing(
        ck,
        backend,
        "overflowing_mul",
        |b, l, r| b.fhe_overflowing_mul(l, r),
        i32::overflowing_mul,
        &[(i32::MAX, 2), (i32::MIN, -1), (0, 0)],
    );
}

pub(crate) fn fheint32_shl_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_shift(
        ck,
        backend,
        "shl",
        |b, l, r| b.fhe_shl(l, r),
        i32::wrapping_shl,
        &[(0x0DEA_DBEE_i32, 0), (-1, 31)],
        rand_shift_amount,
    );
}

pub(crate) fn fheint32_shr_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_shift(
        ck,
        backend,
        "shr",
        |b, l, r| b.fhe_shr(l, r),
        i32::wrapping_shr,
        &[(-1, 1), (i32::MIN, 1)],
        rand_shift_amount,
    );
}

pub(crate) fn fheint32_rotate_left_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_shift(
        ck,
        backend,
        "rotate_left",
        |b, l, r| b.fhe_rotate_left(l, r),
        i32::rotate_left,
        &[(-1, 1), (i32::MIN, 1)],
        rand_shift_amount,
    );
}

pub(crate) fn fheint32_rotate_right_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_int32_shift(
        ck,
        backend,
        "rotate_right",
        |b, l, r| b.fhe_rotate_right(l, r),
        i32::rotate_right,
        &[(-1, 1), (i32::MIN, 1)],
        rand_shift_amount,
    );
}

pub(crate) fn fheuint32_scalar_add_fhe_lhs_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "add(v, s)",
        |b, v| b.fhe_add(v, SCALAR_U32),
        |a| a.wrapping_add(SCALAR_U32),
        &[0, u32::MAX, SCALAR_U32],
    );
}

pub(crate) fn fheuint32_scalar_add_fhe_rhs_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "add(s, v)",
        |b, v| b.fhe_add(SCALAR_U32, v),
        |a| SCALAR_U32.wrapping_add(a),
        &[0, u32::MAX, SCALAR_U32],
    );
}

pub(crate) fn fheuint32_scalar_sub_fhe_lhs_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "sub(v, s)",
        |b, v| b.fhe_sub(v, SCALAR_U32),
        |a| a.wrapping_sub(SCALAR_U32),
        &[0, SCALAR_U32, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_sub_fhe_rhs_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "sub(s, v)",
        |b, v| b.fhe_sub(SCALAR_U32, v),
        |a| SCALAR_U32.wrapping_sub(a),
        &[0, SCALAR_U32, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_mul_fhe_lhs_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "mul(v, s)",
        |b, v| b.fhe_mul(v, SCALAR_U32),
        |a| a.wrapping_mul(SCALAR_U32),
        &[0, 1, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_mul_fhe_rhs_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "mul(s, v)",
        |b, v| b.fhe_mul(SCALAR_U32, v),
        |a| SCALAR_U32.wrapping_mul(a),
        &[0, 1, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_div_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "div(v, s)",
        |b, v| b.fhe_div(v, SCALAR_U32),
        |a| a / SCALAR_U32,
        &[0, SCALAR_U32, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_rem_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "rem(v, s)",
        |b, v| b.fhe_rem(v, SCALAR_U32),
        |a| a % SCALAR_U32,
        &[0, SCALAR_U32, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_min_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "min(v, s)",
        |b, v| b.fhe_min(v, SCALAR_U32),
        |a| a.min(SCALAR_U32),
        &[0, SCALAR_U32, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_max_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "max(v, s)",
        |b, v| b.fhe_max(v, SCALAR_U32),
        |a| a.max(SCALAR_U32),
        &[0, SCALAR_U32, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_bitand_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "bitand(v, s)",
        |b, v| b.fhe_bitand(v, SCALAR_MASK_U32),
        |a| a & SCALAR_MASK_U32,
        &[0, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_bitor_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "bitor(v, s)",
        |b, v| b.fhe_bitor(v, SCALAR_MASK_U32),
        |a| a | SCALAR_MASK_U32,
        &[0, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_bitxor_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "bitxor(v, s)",
        |b, v| b.fhe_bitxor(v, SCALAR_MASK_U32),
        |a| a ^ SCALAR_MASK_U32,
        &[0, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_eq_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar_compare(
        ck,
        backend,
        "eq(v, s)",
        |b, v| b.fhe_eq(v, SCALAR_U32),
        |a| a == SCALAR_U32,
        &[0, SCALAR_U32, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_ne_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar_compare(
        ck,
        backend,
        "ne(v, s)",
        |b, v| b.fhe_ne(v, SCALAR_U32),
        |a| a != SCALAR_U32,
        &[0, SCALAR_U32, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_lt_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar_compare(
        ck,
        backend,
        "lt(v, s)",
        |b, v| b.fhe_lt(v, SCALAR_U32),
        |a| a < SCALAR_U32,
        &[0, SCALAR_U32, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_le_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar_compare(
        ck,
        backend,
        "le(v, s)",
        |b, v| b.fhe_le(v, SCALAR_U32),
        |a| a <= SCALAR_U32,
        &[0, SCALAR_U32, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_gt_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar_compare(
        ck,
        backend,
        "gt(v, s)",
        |b, v| b.fhe_gt(v, SCALAR_U32),
        |a| a > SCALAR_U32,
        &[0, SCALAR_U32, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_ge_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar_compare(
        ck,
        backend,
        "ge(v, s)",
        |b, v| b.fhe_ge(v, SCALAR_U32),
        |a| a >= SCALAR_U32,
        &[0, SCALAR_U32, u32::MAX],
    );
}

pub(crate) fn fheuint32_scalar_shl_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "shl(v, s)",
        |b, v| b.fhe_shl(v, SCALAR_SHIFT),
        |a| a.wrapping_shl(SCALAR_SHIFT),
        &[0, u32::MAX, 0xDEAD_BEEF],
    );
}

pub(crate) fn fheuint32_scalar_shr_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "shr(v, s)",
        |b, v| b.fhe_shr(v, SCALAR_SHIFT),
        |a| a.wrapping_shr(SCALAR_SHIFT),
        &[0, u32::MAX, 0xDEAD_BEEF],
    );
}

pub(crate) fn fheuint32_scalar_rotate_left_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "rotate_left(v, s)",
        |b, v| b.fhe_rotate_left(v, SCALAR_SHIFT),
        |a| a.rotate_left(SCALAR_SHIFT),
        &[0, u32::MAX, 0xDEAD_BEEF],
    );
}

pub(crate) fn fheuint32_scalar_rotate_right_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    check_uint32_scalar(
        ck,
        backend,
        "rotate_right(v, s)",
        |b, v| b.fhe_rotate_right(v, SCALAR_SHIFT),
        |a| a.rotate_right(SCALAR_SHIFT),
        &[0, u32::MAX, 0xDEAD_BEEF],
    );
}

pub(crate) fn fheuint32_ilog2_case<B: ExecutionBackend>(ck: &ClientKey, backend: &B) {
    // Skip 0: `u32::ilog2(0)` panics in std.
    check_uint32_unary(
        ck,
        backend,
        "ilog2",
        |b, v| b.fhe_ilog2(v),
        |a| a.ilog2(),
        &[1, 2, u32::MAX, 0xDEAD_BEEF],
    );
}
