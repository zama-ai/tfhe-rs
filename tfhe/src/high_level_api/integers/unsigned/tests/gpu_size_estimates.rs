//! GPU-only checks that the `get_*_size_on_gpu` estimates cover the GPU memory actually used.
//!
//! fhevm reserves exactly the estimate before running an operation: an estimate below the real
//! peak can make the CUDA allocation fail (abort) when the GPU is nearly full.
//!
//! The peak is read from the high-water mark of the CUDA default memory pool of the device, so
//! each check must run alone in its process (nextest, as the Makefile does, or
//! `--test-threads=1`).

use crate::core_crypto::gpu::CudaStreams;
use crate::high_level_api::global_state;
use crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN;
use crate::high_level_api::keys::InternalServerKey;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::CudaServerKey;
use crate::integer::U256;
use crate::prelude::*;
use crate::{
    ClientKey, FheBool, FheInt128, FheInt32, FheInt8, FheUint128, FheUint16, FheUint256, FheUint32,
    FheUint64, FheUint8,
};
use std::ffi::c_void;

extern "C" {
    fn cudaDeviceGetDefaultMemPool(pool: *mut *mut c_void, device: i32) -> i32;
    fn cudaMemPoolGetAttribute(pool: *mut c_void, attr: i32, value: *mut c_void) -> i32;
    fn cudaMemPoolSetAttribute(pool: *mut c_void, attr: i32, value: *mut c_void) -> i32;
    fn cudaDeviceSynchronize() -> i32;
}

// cudaMemPoolAttrUsedMemCurrent / cudaMemPoolAttrUsedMemHigh
const USED_MEM_CURRENT: i32 = 7;
const USED_MEM_HIGH: i32 = 8;

fn pool_attr(attr: i32) -> u64 {
    let mut pool: *mut c_void = std::ptr::null_mut();
    let mut value = 0u64;
    unsafe {
        assert_eq!(cudaDeviceGetDefaultMemPool(&raw mut pool, 0), 0);
        assert_eq!(
            cudaMemPoolGetAttribute(pool, attr, (&raw mut value).cast::<c_void>()),
            0
        );
    }
    value
}

fn reset_pool_high_water_mark() {
    let mut pool: *mut c_void = std::ptr::null_mut();
    let mut value = 0u64;
    unsafe {
        assert_eq!(cudaDeviceGetDefaultMemPool(&raw mut pool, 0), 0);
        assert_eq!(
            cudaMemPoolSetAttribute(pool, USED_MEM_HIGH, (&raw mut value).cast::<c_void>()),
            0
        );
    }
}

/// Runs `f` and returns the GPU memory it used at its peak, on top of what was already used
fn gpu_peak_of<R>(f: impl FnOnce() -> R) -> u64 {
    unsafe { assert_eq!(cudaDeviceSynchronize(), 0) };
    let before = pool_attr(USED_MEM_CURRENT);
    reset_pool_high_water_mark();
    let result = f();
    unsafe { assert_eq!(cudaDeviceSynchronize(), 0) };
    let peak = pool_attr(USED_MEM_HIGH).saturating_sub(before);
    drop(result);
    peak
}

static FAILURES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Checks that `estimate` covers the GPU memory used by `f` and that it does not allocate on
/// the GPU; failures are collected and reported at the end of the test
fn check<R>(label: &str, estimate: impl FnOnce() -> u64, f: impl FnOnce() -> R) {
    let mut value = 0;
    let allocated_by_estimate = gpu_peak_of(|| value = estimate());
    let peak = gpu_peak_of(f);
    println!(
        "{label}: estimate {value} peak {peak} peak/estimate {:.4} allocated_by_estimate {allocated_by_estimate}",
        peak as f64 / value.max(1) as f64
    );
    let mut failures = FAILURES.lock().unwrap();
    // Every checked operation returns a new GPU ciphertext, so a zero peak means the memory pool
    // did not see the allocations (e.g. no memory pool support, cudaMalloc fallback) and the
    // peak <= estimate check below would pass without measuring anything
    if peak == 0 {
        failures.push(format!(
            "{label}: no GPU allocation was measured, the memory pool does not track the allocations"
        ));
    }
    if peak > value {
        failures.push(format!(
            "{label}: GPU peak {peak} B is above the estimate {value} B"
        ));
    }
    if allocated_by_estimate != 0 {
        failures.push(format!(
            "{label}: the estimate allocated {allocated_by_estimate} B on the GPU"
        ));
    }
}

fn with_cuda_key<R>(f: impl FnOnce(&CudaServerKey, &CudaStreams) -> R) -> R {
    global_state::with_internal_keys(|key| match key {
        InternalServerKey::Cuda(cuda_key) => f(cuda_key.pbs_key(), &cuda_key.streams),
        InternalServerKey::Cpu(_) => panic!("expected a GPU server key"),
        #[cfg(feature = "hpu")]
        InternalServerKey::Hpu(_) => panic!("expected a GPU server key"),
    })
}

macro_rules! check_unsigned {
    ($ck:expr, $ty:ty, $clear:ty, $max:expr, $bits:expr, $with_rem:expr) => {{
        let ck: &ClientKey = $ck;
        let name = stringify!($ty);
        let max: $clear = $max;
        let one: $clear = <$clear>::from(1u8);
        let three: $clear = <$clear>::from(3u8);
        let zero: $clear = <$clear>::from(0u8);
        let mut a = <$ty>::encrypt(max - three, ck);
        let mut b = <$ty>::encrypt(three, ck);
        a.move_to_current_device();
        b.move_to_current_device();

        for n in [1usize, 3] {
            let mut set: Vec<$ty> = (0..n).map(|_| <$ty>::encrypt(one, ck)).collect();
            for e in set.iter_mut() {
                e.move_to_current_device();
            }
            check(
                &format!("{name} contains n={n}"),
                || <$ty>::get_contains_size_on_gpu(&set, &a),
                || <$ty>::contains(&set, &a),
            );
        }

        check(
            &format!("{name} eq"),
            || a.get_eq_size_on_gpu(&b),
            || a.eq(&b),
        );
        check(
            &format!("{name} ne"),
            || a.get_ne_size_on_gpu(&b),
            || a.ne(&b),
        );
        check(
            &format!("{name} gt"),
            || a.get_gt_size_on_gpu(&b),
            || a.gt(&b),
        );
        check(
            &format!("{name} ge"),
            || a.get_ge_size_on_gpu(&b),
            || a.ge(&b),
        );
        check(
            &format!("{name} lt"),
            || a.get_lt_size_on_gpu(&b),
            || a.lt(&b),
        );
        check(
            &format!("{name} le"),
            || a.get_le_size_on_gpu(&b),
            || a.le(&b),
        );
        check(
            &format!("{name} max"),
            || a.get_max_size_on_gpu(&b),
            || a.max(&b),
        );
        check(
            &format!("{name} min"),
            || a.get_min_size_on_gpu(&b),
            || a.min(&b),
        );
        check(
            &format!("{name} and"),
            || a.get_bitand_size_on_gpu(&b),
            || &a & &b,
        );
        check(
            &format!("{name} or"),
            || a.get_bitor_size_on_gpu(&b),
            || &a | &b,
        );
        check(
            &format!("{name} xor"),
            || a.get_bitxor_size_on_gpu(&b),
            || &a ^ &b,
        );
        check(
            &format!("{name} shl"),
            || a.get_left_shift_size_on_gpu(&b),
            || &a << &b,
        );
        check(
            &format!("{name} shr"),
            || a.get_right_shift_size_on_gpu(&b),
            || &a >> &b,
        );
        check(
            &format!("{name} rotl"),
            || a.get_rotate_left_size_on_gpu(&b),
            || (&a).rotate_left(&b),
        );
        check(
            &format!("{name} rotr"),
            || a.get_rotate_right_size_on_gpu(&b),
            || (&a).rotate_right(&b),
        );
        check(
            &format!("{name} sub"),
            || a.get_sub_size_on_gpu(&b),
            || &a - &b,
        );
        check(
            &format!("{name} not"),
            || a.get_bitnot_size_on_gpu(),
            || !&a,
        );

        for s in [zero, one, three, max] {
            check(
                &format!("{name} scalar eq {s:?}"),
                || a.get_eq_size_on_gpu(s),
                || a.eq(s),
            );
            check(
                &format!("{name} scalar ne {s:?}"),
                || a.get_ne_size_on_gpu(s),
                || a.ne(s),
            );
            check(
                &format!("{name} scalar gt {s:?}"),
                || a.get_gt_size_on_gpu(s),
                || a.gt(s),
            );
            check(
                &format!("{name} scalar ge {s:?}"),
                || a.get_ge_size_on_gpu(s),
                || a.ge(s),
            );
            check(
                &format!("{name} scalar lt {s:?}"),
                || a.get_lt_size_on_gpu(s),
                || a.lt(s),
            );
            check(
                &format!("{name} scalar le {s:?}"),
                || a.get_le_size_on_gpu(s),
                || a.le(s),
            );
            check(
                &format!("{name} scalar max {s:?}"),
                || a.get_max_size_on_gpu(s),
                || a.max(s),
            );
            check(
                &format!("{name} scalar min {s:?}"),
                || a.get_min_size_on_gpu(s),
                || a.min(s),
            );
            check(
                &format!("{name} scalar and {s:?}"),
                || a.get_bitand_size_on_gpu(s),
                || &a & s,
            );
            check(
                &format!("{name} scalar or {s:?}"),
                || a.get_bitor_size_on_gpu(s),
                || &a | s,
            );
            check(
                &format!("{name} scalar xor {s:?}"),
                || a.get_bitxor_size_on_gpu(s),
                || &a ^ s,
            );
            check(
                &format!("{name} scalar sub {s:?}"),
                || a.get_sub_size_on_gpu(s),
                || &a - s,
            );
            check(
                &format!("{name} scalar-left sub {s:?}"),
                || s.get_sub_size_on_gpu(&a),
                || s - &a,
            );
        }
        for s in [0u32, 1, $bits - 1, $bits + 1] {
            check(
                &format!("{name} scalar shl {s:?}"),
                || a.get_left_shift_size_on_gpu(s),
                || &a << s,
            );
            check(
                &format!("{name} scalar shr {s:?}"),
                || a.get_right_shift_size_on_gpu(s),
                || &a >> s,
            );
            check(
                &format!("{name} scalar rotl {s:?}"),
                || a.get_rotate_left_size_on_gpu(s),
                || (&a).rotate_left(s),
            );
            check(
                &format!("{name} scalar rotr {s:?}"),
                || a.get_rotate_right_size_on_gpu(s),
                || (&a).rotate_right(s),
            );
        }
        if $with_rem {
            let top: $clear = one << ($bits - 1);
            for d in [one, <$clear>::from(2u8), top, three] {
                check(
                    &format!("{name} scalar rem {d:?}"),
                    || a.get_rem_size_on_gpu(d),
                    || &a % d,
                );
            }
        }
    }};
}

macro_rules! check_signed {
    ($ck:expr, $ty:ty, $clear:ty, $uty:ty) => {{
        let ck: &ClientKey = $ck;
        let name = stringify!($ty);
        let mut a = <$ty>::encrypt(<$clear>::MIN + 3, ck);
        let mut b = <$ty>::encrypt(-3 as $clear, ck);
        a.move_to_current_device();
        b.move_to_current_device();

        check(
            &format!("{name} ne"),
            || a.get_ne_size_on_gpu(&b),
            || a.ne(&b),
        );
        check(
            &format!("{name} gt"),
            || a.get_gt_size_on_gpu(&b),
            || a.gt(&b),
        );
        check(
            &format!("{name} max"),
            || a.get_max_size_on_gpu(&b),
            || a.max(&b),
        );
        check(
            &format!("{name} sub"),
            || a.get_sub_size_on_gpu(&b),
            || &a - &b,
        );
        let mut amount = <$uty>::encrypt(3u8, ck);
        amount.move_to_current_device();
        check(
            &format!("{name} shr"),
            || a.get_right_shift_size_on_gpu(&amount),
            || &a >> &amount,
        );
        check(
            &format!("{name} scalar shr"),
            || a.get_right_shift_size_on_gpu(3u32),
            || &a >> 3u32,
        );
        check(
            &format!("{name} not"),
            || a.get_bitnot_size_on_gpu(),
            || !&a,
        );
        for s in [0 as $clear, 1, -1, <$clear>::MIN, <$clear>::MAX] {
            check(
                &format!("{name} scalar eq {s:?}"),
                || a.get_eq_size_on_gpu(s),
                || a.eq(s),
            );
            check(
                &format!("{name} scalar ne {s:?}"),
                || a.get_ne_size_on_gpu(s),
                || a.ne(s),
            );
            check(
                &format!("{name} scalar gt {s:?}"),
                || a.get_gt_size_on_gpu(s),
                || a.gt(s),
            );
            check(
                &format!("{name} scalar le {s:?}"),
                || a.get_le_size_on_gpu(s),
                || a.le(s),
            );
            check(
                &format!("{name} scalar max {s:?}"),
                || a.get_max_size_on_gpu(s),
                || a.max(s),
            );
            check(
                &format!("{name} scalar or {s:?}"),
                || a.get_bitor_size_on_gpu(s),
                || &a | s,
            );
            check(
                &format!("{name} scalar sub {s:?}"),
                || a.get_sub_size_on_gpu(s),
                || &a - s,
            );
            check(
                &format!("{name} scalar-left sub {s:?}"),
                || s.get_sub_size_on_gpu(&a),
                || s - &a,
            );
        }
        let set = vec![a.clone(), b.clone()];
        check(
            &format!("{name} contains n=2"),
            || <$ty>::get_contains_size_on_gpu(&set, &b),
            || <$ty>::contains(&set, &b),
        );
    }};
}

/// Integer API with dirty operands (carries not empty): the estimates must count the copies
fn check_dirty_integer(ck: &ClientKey) {
    let clean_8 = FheUint8::encrypt(5u8, ck);
    let clean_64 = FheUint64::encrypt(5u64, ck);
    for clean_hl in [&clean_8.ciphertext, &clean_64.ciphertext] {
        with_cuda_key(|sks, streams| {
            let clean: CudaUnsignedRadixCiphertext = clean_hl.on_gpu(streams).duplicate(streams);
            let num_blocks = clean.as_ref().d_blocks.lwe_ciphertext_count().0;
            let mut dirty = clean.duplicate(streams);
            sks.unchecked_add_assign(&mut dirty, &clean, streams);
            assert!(!dirty.block_carries_are_empty());

            for (label, l, r) in [
                ("clean/dirty", &clean, &dirty),
                ("dirty/clean", &dirty, &clean),
                ("dirty/dirty", &dirty, &dirty),
            ] {
                let label = format!("integer nb={num_blocks} {label}");
                check(
                    &format!("{label} or"),
                    || sks.get_bitor_size_on_gpu(l, r, streams),
                    || sks.bitor(l, r, streams),
                );
                check(
                    &format!("{label} sub"),
                    || sks.get_sub_size_on_gpu(l, r, streams),
                    || sks.sub(l, r, streams),
                );
                check(
                    &format!("{label} gt"),
                    || sks.get_gt_size_on_gpu(l, r, streams),
                    || sks.gt(l, r, streams),
                );
                check(
                    &format!("{label} ne"),
                    || sks.get_ne_size_on_gpu(l, r, streams),
                    || sks.ne(l, r, streams),
                );
                check(
                    &format!("{label} max"),
                    || sks.get_max_size_on_gpu(l, r, streams),
                    || sks.max(l, r, streams),
                );
                check(
                    &format!("{label} shr"),
                    || sks.get_right_shift_size_on_gpu(l, r, streams),
                    || sks.right_shift(l, r, streams),
                );
                check(
                    &format!("{label} rotl"),
                    || sks.get_rotate_left_size_on_gpu(l, r, streams),
                    || sks.rotate_left(l, r, streams),
                );
                let set = [l.duplicate(streams), clean.duplicate(streams)];
                check(
                    &format!("{label} contains"),
                    || sks.get_contains_size_on_gpu(&set, r, streams),
                    || sks.contains(&set, r, streams),
                );
            }

            let label = format!("integer nb={num_blocks} dirty");
            let d = &dirty;
            check(
                &format!("{label} scalar or"),
                || sks.get_scalar_bitor_size_on_gpu(d, streams),
                || sks.scalar_bitor(d, 3u64, streams),
            );
            check(
                &format!("{label} scalar sub"),
                || sks.get_scalar_sub_size_on_gpu(d, streams),
                || sks.scalar_sub(d, 3u64, streams),
            );
            check(
                &format!("{label} scalar gt"),
                || sks.get_scalar_gt_size_on_gpu(d, streams),
                || sks.scalar_gt(d, 3u64, streams),
            );
            check(
                &format!("{label} scalar ne"),
                || sks.get_scalar_ne_size_on_gpu(d, streams),
                || sks.scalar_ne(d, 3u64, streams),
            );
            check(
                &format!("{label} scalar max"),
                || sks.get_scalar_max_size_on_gpu(d, streams),
                || sks.scalar_max(d, 3u64, streams),
            );
            check(
                &format!("{label} scalar shr"),
                || sks.get_scalar_right_shift_size_on_gpu(d, streams),
                || sks.scalar_right_shift(d, 3u32, streams),
            );
            check(
                &format!("{label} not"),
                || sks.get_bitnot_size_on_gpu(d, streams),
                || sks.bitnot(d, streams),
            );
            for divisor in [1u64, 4, 3] {
                check(
                    &format!("{label} scalar rem {divisor}"),
                    || sks.get_scalar_rem_size_on_gpu(d, divisor, streams),
                    || sks.scalar_rem(d, divisor, streams),
                );
            }
        });
    }
}

#[test]
fn test_gpu_size_estimates_cover_peak() {
    for setup_fn in GPU_SETUP_FN {
        let ck = setup_fn();

        check_unsigned!(&ck, FheUint8, u8, u8::MAX, 8u32, true);
        check_unsigned!(&ck, FheUint16, u16, u16::MAX, 16u32, true);
        check_unsigned!(&ck, FheUint32, u32, u32::MAX, 32u32, true);
        check_unsigned!(&ck, FheUint64, u64, u64::MAX, 64u32, true);
        check_unsigned!(&ck, FheUint128, u128, u128::MAX, 128u32, false);
        check_unsigned!(&ck, FheUint256, U256, U256::MAX, 256u32, false);

        check_signed!(&ck, FheInt8, i8, FheUint8);
        check_signed!(&ck, FheInt32, i32, FheUint32);
        check_signed!(&ck, FheInt128, i128, FheUint128);

        let mut t = FheBool::encrypt(true, &ck);
        let mut f = FheBool::encrypt(false, &ck);
        t.move_to_current_device();
        f.move_to_current_device();
        check("FheBool not", || t.get_bitnot_size_on_gpu(), || !&t);
        check("FheBool or", || t.get_bitor_size_on_gpu(&f), || &t | &f);
        check("FheBool and", || t.get_bitand_size_on_gpu(&f), || &t & &f);
        check("FheBool ne", || t.get_ne_size_on_gpu(&f), || t.ne(&f));
        check(
            "FheBool scalar ne",
            || t.get_ne_size_on_gpu(false),
            || t.ne(false),
        );

        check_dirty_integer(&ck);
    }
    let failures = FAILURES.lock().unwrap();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
