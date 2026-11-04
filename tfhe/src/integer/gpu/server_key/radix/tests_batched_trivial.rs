use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::CudaServerKey;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::{ClientKey, IntegerKeyKind, RadixClientKey};
use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use rand::Rng;

fn batched_trivial_num_iterations() -> usize {
    std::env::var("TFHE_RS_GPU_TRIVIAL_BATCHED_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10000)
}

#[test]
fn test_gpu_integer_add_batched_trivial() {
    let (cks, _) = KEY_CACHE.get_from_params(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        IntegerKeyKind::Radix,
    );

    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(&cks, &streams);
    streams.synchronize();

    let mut rng = rand::thread_rng();
    let num_blocks = 4usize;
    let p = cks.parameters().message_modulus().0 as u64;
    let modulus = p.pow(num_blocks as u32);

    for _ in 0..batched_trivial_num_iterations() {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;
        let expected_body = clear_0.wrapping_add(clear_1) % modulus;

        let (ct0, tv0) = cks.encrypt_radix_batched_trivial(clear_0, num_blocks, &mut rng);
        let (ct1, tv1) = cks.encrypt_radix_batched_trivial(clear_1, num_blocks, &mut rng);

        let d_ct0 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct0, &streams);
        let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);

        let d_result = sks.add(&d_ct0, &d_ct1, &streams);
        let result = d_result.to_radix_ciphertext(&streams);

        let expected_slots: Vec<u64> = tv0
            .iter()
            .zip(tv1.iter())
            .map(|(&a, &b)| a.wrapping_add(b) % modulus)
            .collect();

        cks.decrypt_and_check_radix_batched_trivial(
            &result,
            expected_body,
            &expected_slots,
            &[("a", clear_0), ("b", clear_1)],
            &[("a", &tv0), ("b", &tv1)],
        );
    }
}

#[test]
fn test_gpu_integer_sub_batched_trivial() {
    let (cks, _) = KEY_CACHE.get_from_params(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        IntegerKeyKind::Radix,
    );

    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(&cks, &streams);
    streams.synchronize();

    let mut rng = rand::thread_rng();
    let num_blocks = 4usize;
    let p = cks.parameters().message_modulus().0 as u64;
    let modulus = p.pow(num_blocks as u32);

    for _ in 0..batched_trivial_num_iterations() {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;
        let expected_body = clear_0.wrapping_sub(clear_1) % modulus;

        let (ct0, tv0) = cks.encrypt_radix_batched_trivial(clear_0, num_blocks, &mut rng);
        let (ct1, tv1) = cks.encrypt_radix_batched_trivial(clear_1, num_blocks, &mut rng);

        let d_ct0 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct0, &streams);
        let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);

        let d_result = sks.sub(&d_ct0, &d_ct1, &streams);
        let result = d_result.to_radix_ciphertext(&streams);

        let expected_slots: Vec<u64> = tv0
            .iter()
            .zip(tv1.iter())
            .map(|(&a, &b)| a.wrapping_sub(b) % modulus)
            .collect();

        cks.decrypt_and_check_radix_batched_trivial(
            &result,
            expected_body,
            &expected_slots,
            &[("a", clear_0), ("b", clear_1)],
            &[("a", &tv0), ("b", &tv1)],
        );
    }
}

#[test]
fn test_gpu_integer_mul_batched_trivial() {
    let (cks, _) = KEY_CACHE.get_from_params(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        IntegerKeyKind::Radix,
    );

    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(&cks, &streams);
    streams.synchronize();

    let mut rng = rand::thread_rng();
    let num_blocks = 4usize;
    let p = cks.parameters().message_modulus().0 as u64;
    let modulus = p.pow(num_blocks as u32);

    for _ in 0..batched_trivial_num_iterations() {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;
        let expected_body = clear_0.wrapping_mul(clear_1) % modulus;

        let (ct0, tv0) = cks.encrypt_radix_batched_trivial(clear_0, num_blocks, &mut rng);
        let (ct1, tv1) = cks.encrypt_radix_batched_trivial(clear_1, num_blocks, &mut rng);

        let d_ct0 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct0, &streams);
        let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);

        let d_result = sks.mul(&d_ct0, &d_ct1, &streams);
        let result = d_result.to_radix_ciphertext(&streams);

        let expected_slots: Vec<u64> = tv0
            .iter()
            .zip(tv1.iter())
            .map(|(&a, &b)| a.wrapping_mul(b) % modulus)
            .collect();

        cks.decrypt_and_check_radix_batched_trivial(
            &result,
            expected_body,
            &expected_slots,
            &[("a", clear_0), ("b", clear_1)],
            &[("a", &tv0), ("b", &tv1)],
        );
    }
}

#[test]
fn test_gpu_integer_goldschmidt_division_batched_trivial() {
    // goldschmidt_division requires exactly 32 blocks (64-bit) at 2 bits/block.
    const NUM_BLOCKS: usize = 32;
    let cks = RadixClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, NUM_BLOCKS);
    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(&cks, &streams);
    streams.synchronize();
    let cpu_cks = cks.as_ref();
    let mut rng = rand::thread_rng();

    let div_rem_expected = |n: u64, d: u64| -> (u64, u64) {
        n.checked_div(d)
            .zip(n.checked_rem(d))
            .unwrap_or((u64::MAX, n))
    };

    // Division by zero: body quotient = u64::MAX, body remainder = numerator.
    // All slots of the denominator are also zero so that the per-coefficient
    // zero-detection chain fires correctly for every slot.
    {
        let n: u64 = rng.gen();
        let (ct_n, tv_n) = cpu_cks.encrypt_radix_batched_trivial(n, NUM_BLOCKS, &mut rng);
        let (ct_d, tv_d) = cpu_cks.encrypt_radix_batched_trivial_scalar(0u64, NUM_BLOCKS, 0u64);
        let d_n = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_n, &streams);
        let d_d = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_d, &streams);

        let (d_q, d_r) = sks.goldschmidt_division(&d_n, &d_d, &streams);
        let q = d_q.to_radix_ciphertext(&streams);
        let r = d_r.to_radix_ciphertext(&streams);

        let expected_q_slots: Vec<u64> = tv_n
            .iter()
            .zip(tv_d.iter())
            .map(|(&n_v, &d_v)| div_rem_expected(n_v, d_v).0)
            .collect();
        let expected_r_slots: Vec<u64> = tv_n
            .iter()
            .zip(tv_d.iter())
            .map(|(&n_v, &d_v)| div_rem_expected(n_v, d_v).1)
            .collect();
        cpu_cks.decrypt_and_check_radix_batched_trivial(
            &q,
            u64::MAX,
            &expected_q_slots,
            &[("n", n), ("d", 0)],
            &[("n", &tv_n), ("d", &tv_d)],
        );
        cpu_cks.decrypt_and_check_radix_batched_trivial(
            &r,
            n,
            &expected_r_slots,
            &[("n", n), ("d", 0)],
            &[("n", &tv_n), ("d", &tv_d)],
        );
    }

    for iter in 0..batched_trivial_num_iterations() {
        let n: u64 = rng.gen();
        let d: u64 = rng.gen_range(1..=u64::MAX);

        let (ct_n, tv_n) = cpu_cks.encrypt_radix_batched_trivial(n, NUM_BLOCKS, &mut rng);
        let (ct_d, tv_d) = cpu_cks.encrypt_radix_batched_trivial(d, NUM_BLOCKS, &mut rng);
        let d_n = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_n, &streams);
        let d_d = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_d, &streams);

        let (d_q, d_r) = sks.goldschmidt_division(&d_n, &d_d, &streams);
        let q = d_q.to_radix_ciphertext(&streams);
        let r = d_r.to_radix_ciphertext(&streams);

        let expected_q_slots: Vec<u64> = tv_n
            .iter()
            .zip(tv_d.iter())
            .map(|(&n_v, &d_v)| div_rem_expected(n_v, d_v).0)
            .collect();
        let expected_r_slots: Vec<u64> = tv_n
            .iter()
            .zip(tv_d.iter())
            .map(|(&n_v, &d_v)| div_rem_expected(n_v, d_v).1)
            .collect();

        cpu_cks.decrypt_and_check_radix_batched_trivial(
            &q,
            n / d,
            &expected_q_slots,
            &[("n", n), ("d", d)],
            &[("n", &tv_n), ("d", &tv_d)],
        );
        cpu_cks.decrypt_and_check_radix_batched_trivial(
            &r,
            n % d,
            &expected_r_slots,
            &[("n", n), ("d", d)],
            &[("n", &tv_n), ("d", &tv_d)],
        );
    }
}

#[test]
fn test_gpu_integer_div_rem_batched_trivial() {
    let (cks, _) = KEY_CACHE.get_from_params(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        IntegerKeyKind::Radix,
    );

    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(&cks, &streams);
    streams.synchronize();

    let mut rng = rand::thread_rng();
    let num_blocks = 4usize;
    let p = cks.parameters().message_modulus().0 as u64;
    let modulus = p.pow(num_blocks as u32);

    // Division by zero: quotient = modulus - 1, remainder = numerator.
    // All slots of the denominator are also zero so that the per-coefficient
    // zero-detection chain fires correctly for every slot.
    {
        let clear_num = rng.gen::<u64>() % modulus;
        let clear_denom = 0u64;

        let (ct_num, tv_num) = cks.encrypt_radix_batched_trivial(clear_num, num_blocks, &mut rng);
        let (ct_denom, tv_denom) =
            cks.encrypt_radix_batched_trivial_scalar(clear_denom, num_blocks, 0u64);

        let d_num = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_num, &streams);
        let d_denom = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_denom, &streams);

        let (d_q, d_r) = sks.div_rem(&d_num, &d_denom, &streams);
        let q = d_q.to_radix_ciphertext(&streams);
        let r = d_r.to_radix_ciphertext(&streams);

        let expected_q_body = modulus - 1;
        let expected_q_slots: Vec<u64> = tv_num.iter().map(|_| modulus - 1).collect();
        cks.decrypt_and_check_radix_batched_trivial(
            &q,
            expected_q_body,
            &expected_q_slots,
            &[("num", clear_num), ("denom", clear_denom)],
            &[("num", &tv_num), ("denom", &tv_denom)],
        );

        let expected_r_slots: Vec<u64> = tv_num.to_vec();
        cks.decrypt_and_check_radix_batched_trivial(
            &r,
            clear_num,
            &expected_r_slots,
            &[("num", clear_num), ("denom", clear_denom)],
            &[("num", &tv_num), ("denom", &tv_denom)],
        );
    }

    for _ in 0..batched_trivial_num_iterations() {
        let clear_num = rng.gen::<u64>() % modulus;
        let clear_denom = rng.gen::<u64>() % (modulus - 1) + 1; // non-zero

        let expected_q_body = clear_num / clear_denom;
        let expected_r_body = clear_num % clear_denom;

        let (ct_num, tv_num) = cks.encrypt_radix_batched_trivial(clear_num, num_blocks, &mut rng);
        let (ct_denom, tv_denom) =
            cks.encrypt_radix_batched_trivial(clear_denom, num_blocks, &mut rng);

        let d_num = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_num, &streams);
        let d_denom = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_denom, &streams);

        let (d_q, d_r) = sks.div_rem(&d_num, &d_denom, &streams);
        let q = d_q.to_radix_ciphertext(&streams);
        let r = d_r.to_radix_ciphertext(&streams);

        let expected_q_slots: Vec<u64> = tv_num
            .iter()
            .zip(tv_denom.iter())
            .map(|(&n, &d)| if d == 0 { modulus - 1 } else { n / d })
            .collect();
        let expected_r_slots: Vec<u64> = tv_num
            .iter()
            .zip(tv_denom.iter())
            .map(|(&n, &d)| if d == 0 { n } else { n % d })
            .collect();

        cks.decrypt_and_check_radix_batched_trivial(
            &q,
            expected_q_body,
            &expected_q_slots,
            &[("num", clear_num), ("denom", clear_denom)],
            &[("num", &tv_num), ("denom", &tv_denom)],
        );
        cks.decrypt_and_check_radix_batched_trivial(
            &r,
            expected_r_body,
            &expected_r_slots,
            &[("num", clear_num), ("denom", clear_denom)],
            &[("num", &tv_num), ("denom", &tv_denom)],
        );
    }
}

#[test]
fn test_gpu_integer_ilog2_batched_trivial() {
    let (cks, _) = KEY_CACHE.get_from_params(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        IntegerKeyKind::Radix,
    );

    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(&cks, &streams);
    streams.synchronize();

    let mut rng = rand::thread_rng();
    let num_blocks = 4usize;
    let p = cks.parameters().message_modulus().0 as u64;
    let modulus = p.pow(num_blocks as u32);
    let cpu_cks: &ClientKey = cks.as_ref();
    let lwe_dimension = cpu_cks.key.parameters().encryption_lwe_dimension().0;

    // ilog2 is undefined at 0, so sample strictly positive values for both the
    // body and every mask slot.
    let nonzero = |r: &mut rand::rngs::ThreadRng| -> u64 {
        loop {
            let v = r.gen::<u64>() % modulus;
            if v != 0 {
                return v;
            }
        }
    };

    for _ in 0..batched_trivial_num_iterations() {
        let clear = nonzero(&mut rng);
        let tv: Vec<u64> = (0..lwe_dimension).map(|_| nonzero(&mut rng)).collect();
        let (ct, tv) = cks.encrypt_radix_with_test_vectors(clear, num_blocks, tv);

        let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
        let d_result = sks.ilog2(&d_ct, &streams);
        let result = d_result.to_radix_ciphertext(&streams);

        let expected_body = u64::from(clear.ilog2());
        let expected_slots: Vec<u64> = tv.iter().map(|&v| u64::from(v.ilog2())).collect();

        cks.decrypt_and_check_radix_batched_trivial(
            &result,
            expected_body,
            &expected_slots,
            &[("x", clear)],
            &[("x", &tv)],
        );
    }
}

/// Runs each (encrypted, encrypted) comparison variant once per iteration and
/// checks body + per-slot results against the CPU prediction.
#[test]
fn test_gpu_integer_comparison_batched_trivial() {
    let (cks, _) = KEY_CACHE.get_from_params(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        IntegerKeyKind::Radix,
    );

    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(&cks, &streams);
    streams.synchronize();

    let mut rng = rand::thread_rng();
    let num_blocks = 4usize;
    let p = cks.parameters().message_modulus().0 as u64;
    let modulus = p.pow(num_blocks as u32);

    let check = |name: &str,
                 d_bool: CudaBooleanBlock,
                 clear_a: u64,
                 clear_b: u64,
                 tv_a: &[u64],
                 tv_b: &[u64],
                 cpu_op: fn(u64, u64) -> bool| {
        let result = d_bool.0.to_radix_ciphertext(&streams);
        let expected_body = u64::from(cpu_op(clear_a, clear_b));
        let expected_slots: Vec<u64> = tv_a
            .iter()
            .zip(tv_b.iter())
            .map(|(&a, &b)| u64::from(cpu_op(a, b)))
            .collect();
        cks.decrypt_and_check_radix_batched_trivial(
            &result,
            expected_body,
            &expected_slots,
            &[("op", name.len() as u64), ("a", clear_a), ("b", clear_b)],
            &[("a", tv_a), ("b", tv_b)],
        );
    };

    for _ in 0..batched_trivial_num_iterations() {
        let clear_a = rng.gen::<u64>() % modulus;
        let clear_b = rng.gen::<u64>() % modulus;
        let (ct_a, tv_a) = cks.encrypt_radix_batched_trivial(clear_a, num_blocks, &mut rng);
        let (ct_b, tv_b) = cks.encrypt_radix_batched_trivial(clear_b, num_blocks, &mut rng);

        let d_a = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_a, &streams);
        let d_b = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_b, &streams);

        check(
            "eq",
            sks.eq(&d_a, &d_b, &streams),
            clear_a,
            clear_b,
            &tv_a,
            &tv_b,
            |a, b| a == b,
        );
        check(
            "ne",
            sks.ne(&d_a, &d_b, &streams),
            clear_a,
            clear_b,
            &tv_a,
            &tv_b,
            |a, b| a != b,
        );
        check(
            "gt",
            sks.gt(&d_a, &d_b, &streams),
            clear_a,
            clear_b,
            &tv_a,
            &tv_b,
            |a, b| a > b,
        );
        check(
            "ge",
            sks.ge(&d_a, &d_b, &streams),
            clear_a,
            clear_b,
            &tv_a,
            &tv_b,
            |a, b| a >= b,
        );
        check(
            "lt",
            sks.lt(&d_a, &d_b, &streams),
            clear_a,
            clear_b,
            &tv_a,
            &tv_b,
            |a, b| a < b,
        );
        check(
            "le",
            sks.le(&d_a, &d_b, &streams),
            clear_a,
            clear_b,
            &tv_a,
            &tv_b,
            |a, b| a <= b,
        );
    }
}

/// Runs each (encrypted, scalar) comparison variant and checks body + per-slot.
#[test]
fn test_gpu_integer_scalar_comparison_batched_trivial() {
    let (cks, _) = KEY_CACHE.get_from_params(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        IntegerKeyKind::Radix,
    );

    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(&cks, &streams);
    streams.synchronize();

    let mut rng = rand::thread_rng();
    let num_blocks = 4usize;
    let p = cks.parameters().message_modulus().0 as u64;
    let modulus = p.pow(num_blocks as u32);

    let check = |name: &str,
                 d_bool: CudaBooleanBlock,
                 clear_a: u64,
                 scalar: u64,
                 tv_a: &[u64],
                 cpu_op: fn(u64, u64) -> bool| {
        let result = d_bool.0.to_radix_ciphertext(&streams);
        let expected_body = u64::from(cpu_op(clear_a, scalar));
        let expected_slots: Vec<u64> = tv_a.iter().map(|&a| u64::from(cpu_op(a, scalar))).collect();
        cks.decrypt_and_check_radix_batched_trivial(
            &result,
            expected_body,
            &expected_slots,
            &[("op", name.len() as u64), ("a", clear_a), ("s", scalar)],
            &[("a", tv_a)],
        );
    };

    for _ in 0..batched_trivial_num_iterations() {
        let clear_a = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u64>() % modulus;
        let (ct_a, tv_a) = cks.encrypt_radix_batched_trivial(clear_a, num_blocks, &mut rng);
        let d_a = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_a, &streams);

        check(
            "scalar_eq",
            sks.scalar_eq(&d_a, scalar, &streams),
            clear_a,
            scalar,
            &tv_a,
            |a, b| a == b,
        );
        check(
            "scalar_ne",
            sks.scalar_ne(&d_a, scalar, &streams),
            clear_a,
            scalar,
            &tv_a,
            |a, b| a != b,
        );
        check(
            "scalar_gt",
            sks.scalar_gt(&d_a, scalar, &streams),
            clear_a,
            scalar,
            &tv_a,
            |a, b| a > b,
        );
        check(
            "scalar_ge",
            sks.scalar_ge(&d_a, scalar, &streams),
            clear_a,
            scalar,
            &tv_a,
            |a, b| a >= b,
        );
        check(
            "scalar_lt",
            sks.scalar_lt(&d_a, scalar, &streams),
            clear_a,
            scalar,
            &tv_a,
            |a, b| a < b,
        );
        check(
            "scalar_le",
            sks.scalar_le(&d_a, scalar, &streams),
            clear_a,
            scalar,
            &tv_a,
            |a, b| a <= b,
        );
    }
}

/// if_then_else: builds the condition via an `eq` comparison so it is a real
/// per-slot CudaBooleanBlock, then checks that each slot picked the correct
/// branch.
#[test]
fn test_gpu_integer_if_then_else_batched_trivial() {
    let (cks, _) = KEY_CACHE.get_from_params(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        IntegerKeyKind::Radix,
    );

    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(&cks, &streams);
    streams.synchronize();

    let mut rng = rand::thread_rng();
    let num_blocks = 4usize;
    let p = cks.parameters().message_modulus().0 as u64;
    let modulus = p.pow(num_blocks as u32);

    for _ in 0..batched_trivial_num_iterations() {
        // The condition is produced by `eq(a, b)`: it is 1 iff the slot's
        // (a, b) pair is equal. The two `eq` operands are drawn from a tiny
        // range so that equality occasionally fires (otherwise every slot
        // would just pick the false branch).
        let eq_mod: u64 = 4;
        let clear_cond_a = rng.gen::<u64>() % eq_mod;
        let clear_cond_b = rng.gen::<u64>() % eq_mod;
        let cpu_cks: &ClientKey = cks.as_ref();
        let lwe_dimension = cpu_cks.key.parameters().encryption_lwe_dimension().0;
        let tv_cond_a: Vec<u64> = (0..lwe_dimension)
            .map(|_| rng.gen::<u64>() % eq_mod)
            .collect();
        let tv_cond_b: Vec<u64> = (0..lwe_dimension)
            .map(|_| rng.gen::<u64>() % eq_mod)
            .collect();
        let (ct_cond_a, tv_cond_a) =
            cks.encrypt_radix_with_test_vectors(clear_cond_a, num_blocks, tv_cond_a);
        let (ct_cond_b, tv_cond_b) =
            cks.encrypt_radix_with_test_vectors(clear_cond_b, num_blocks, tv_cond_b);

        let d_cond_a = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_cond_a, &streams);
        let d_cond_b = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_cond_b, &streams);
        let d_cond = sks.eq(&d_cond_a, &d_cond_b, &streams);

        let clear_t = rng.gen::<u64>() % modulus;
        let clear_f = rng.gen::<u64>() % modulus;
        let (ct_t, tv_t) = cks.encrypt_radix_batched_trivial(clear_t, num_blocks, &mut rng);
        let (ct_f, tv_f) = cks.encrypt_radix_batched_trivial(clear_f, num_blocks, &mut rng);

        let d_t = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_t, &streams);
        let d_f = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_f, &streams);

        let d_result = sks.if_then_else(&d_cond, &d_t, &d_f, &streams);
        let result = d_result.to_radix_ciphertext(&streams);

        let body_cond = clear_cond_a == clear_cond_b;
        let expected_body = if body_cond { clear_t } else { clear_f };
        let expected_slots: Vec<u64> = tv_cond_a
            .iter()
            .zip(tv_cond_b.iter())
            .zip(tv_t.iter().zip(tv_f.iter()))
            .map(|((&ca, &cb), (&t, &f))| if ca == cb { t } else { f })
            .collect();

        cks.decrypt_and_check_radix_batched_trivial(
            &result,
            expected_body,
            &expected_slots,
            &[
                ("ca", clear_cond_a),
                ("cb", clear_cond_b),
                ("t", clear_t),
                ("f", clear_f),
            ],
            &[
                ("ca", &tv_cond_a),
                ("cb", &tv_cond_b),
                ("t", &tv_t),
                ("f", &tv_f),
            ],
        );
    }
}
