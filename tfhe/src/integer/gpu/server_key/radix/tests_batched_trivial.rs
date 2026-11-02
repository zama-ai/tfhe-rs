use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::CudaServerKey;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::IntegerKeyKind;
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
    let (cks, _) = KEY_CACHE
        .get_from_params(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, IntegerKeyKind::Radix);

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

        cks.decrypt_and_check_radix_batched_trivial(&result, expected_body, &expected_slots);
    }
}

#[test]
fn test_gpu_integer_div_rem_batched_trivial() {
    let (cks, _) = KEY_CACHE
        .get_from_params(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, IntegerKeyKind::Radix);

    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(&cks, &streams);
    streams.synchronize();

    let mut rng = rand::thread_rng();
    let num_blocks = 4usize;
    let p = cks.parameters().message_modulus().0 as u64;
    let modulus = p.pow(num_blocks as u32);

    // Division by zero: quotient = modulus - 1, remainder = numerator.
    {
        let clear_num = rng.gen::<u64>() % modulus;
        let clear_denom = 0u64;

        let (ct_num, tv_num) =
            cks.encrypt_radix_batched_trivial(clear_num, num_blocks, &mut rng);
        let (ct_denom, _tv_denom) =
            cks.encrypt_radix_batched_trivial(clear_denom, num_blocks, &mut rng);

        let d_num = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_num, &streams);
        let d_denom = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_denom, &streams);

        let (d_q, d_r) = sks.div_rem(&d_num, &d_denom, &streams);
        let q = d_q.to_radix_ciphertext(&streams);
        let r = d_r.to_radix_ciphertext(&streams);

        let expected_q_body = modulus - 1;
        let expected_q_slots: Vec<u64> = tv_num.iter().map(|_| modulus - 1).collect();
        cks.decrypt_and_check_radix_batched_trivial(&q, expected_q_body, &expected_q_slots);

        let expected_r_slots: Vec<u64> = tv_num.to_vec();
        cks.decrypt_and_check_radix_batched_trivial(&r, clear_num, &expected_r_slots);
    }

    for _ in 0..batched_trivial_num_iterations() {
        let clear_num = rng.gen::<u64>() % modulus;
        let clear_denom = rng.gen::<u64>() % (modulus - 1) + 1; // non-zero

        let expected_q_body = clear_num / clear_denom;
        let expected_r_body = clear_num % clear_denom;

        let (ct_num, tv_num) =
            cks.encrypt_radix_batched_trivial(clear_num, num_blocks, &mut rng);
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

        cks.decrypt_and_check_radix_batched_trivial(&q, expected_q_body, &expected_q_slots);
        cks.decrypt_and_check_radix_batched_trivial(&r, expected_r_body, &expected_r_slots);
    }
}
