//! Benchmarks for the fixed-point fused multiply-add and the mul-low term sum,
//! driven with the exact shapes a Goldschmidt divider uses on 64-bit operands:
//! a 34-block (68-bit) fixed point, a right operand of 5, 9 then 16 blocks, and
//! a 32x32 mul-low for the remainder.
//!
//! Both operations only exist on the GPU backend, so there is no CPU
//! counterpart to compare against here.

#[cfg(feature = "gpu")]
pub mod cuda {
    use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use benchmark::utilities::{write_to_json_unchecked, OperatorType};
    use criterion::Criterion;
    use std::hint::black_box;
    use tfhe::core_crypto::gpu::CudaStreams;
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::CudaServerKey;
    use tfhe::integer::keycache::KEY_CACHE;
    use tfhe::integer::IntegerKeyKind;
    use tfhe::keycache::NamedParam;
    use tfhe::shortint::AtomicPatternParameters;

    const BITS_PER_BLOCK: u32 = 2;

    /// (label, lhs blocks, rhs blocks, rescaling, precision bits) - the four
    /// multiply-adds of a 64-bit Goldschmidt division.
    fn fixed_point_shapes() -> Vec<(&'static str, usize, usize, u32, u32)> {
        vec![
            ("seed", 34, 5, 0, 10),
            ("iter0", 34, 5, 4, 18),
            ("iter1", 34, 9, 8, 34),
            ("iter2", 34, 16, 16, 64),
        ]
    }

    pub fn cuda_mul_add_fixed_point(c: &mut Criterion) {
        let bench_name = "integer::cuda::mul_add_fixed_point";
        let mut group = c.benchmark_group(bench_name);
        group.sample_size(15);

        let param = BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let atomic_param: AtomicPatternParameters = param.into();
        let param_name = param.name();

        let streams = CudaStreams::new_multi_gpu();
        let (cpu_cks, _) = KEY_CACHE.get_from_params(atomic_param, IntegerKeyKind::Radix);
        let sks = CudaServerKey::new(&cpu_cks, &streams);

        for (label, lhs_blocks, rhs_blocks, rescaling, precision) in fixed_point_shapes() {
            let bench_id =
                format!("{bench_name}::{param_name}::{label}_{lhs_blocks}x{rhs_blocks}blocks");

            // A left operand just under beta^L / 2 and a full-width right one:
            // the worst case for the number of surviving block products, and the
            // regime the divider actually runs in.
            let clear_lhs: u128 = (1u128 << (lhs_blocks as u32 * BITS_PER_BLOCK - 1)) - 1;
            let clear_rhs: u128 = (1u128 << (rhs_blocks as u32 * BITS_PER_BLOCK)) - 1;

            let ct_lhs = cpu_cks.encrypt_radix(clear_lhs, lhs_blocks);
            let ct_rhs = cpu_cks.encrypt_radix(clear_rhs, rhs_blocks);
            let ct_added = cpu_cks.encrypt_radix(clear_lhs, lhs_blocks);
            let d_lhs = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_lhs, &streams);
            let d_rhs = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_rhs, &streams);
            let d_added = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_added, &streams);

            group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    black_box(sks.mul_add_fixed_point_with_rescaling(
                        &d_lhs,
                        &d_rhs,
                        Some(&d_added),
                        rescaling,
                        precision,
                        &streams,
                    ));
                })
            });

            write_to_json_unchecked(
                &bench_id,
                param.name(),
                "mul_add_fixed_point",
                &OperatorType::Atomic,
                lhs_blocks as u32 * BITS_PER_BLOCK,
                vec![atomic_param.message_modulus().0.ilog2(); lhs_blocks],
            );
        }
        group.finish();
    }

    pub fn cuda_mul_low_partial_sum(c: &mut Criterion) {
        let bench_name = "integer::cuda::mul_low_partial_sum";
        let mut group = c.benchmark_group(bench_name);
        group.sample_size(15);

        let param = BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let atomic_param: AtomicPatternParameters = param.into();
        let param_name = param.name();

        let streams = CudaStreams::new_multi_gpu();
        let (cpu_cks, _) = KEY_CACHE.get_from_params(atomic_param, IntegerKeyKind::Radix);
        let sks = CudaServerKey::new(&cpu_cks, &streams);

        // 32 x 32 blocks with the two addends the Goldschmidt remainder needs
        // (bitnot of the numerator, and a trivial one).
        let num_blocks = 32usize;
        let bench_id = format!("{bench_name}::{param_name}::{num_blocks}blocks_2extra");

        let ct_lhs = cpu_cks.encrypt_radix(u64::MAX, num_blocks);
        let ct_rhs = cpu_cks.encrypt_radix(u64::MAX, num_blocks);
        let ct_extra_0 = cpu_cks.encrypt_radix(u64::MAX, num_blocks);
        let ct_extra_1 = cpu_cks.encrypt_radix(1u64, num_blocks);
        let d_lhs = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_lhs, &streams);
        let d_rhs = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_rhs, &streams);
        let d_extras = vec![
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_extra_0, &streams),
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_extra_1, &streams),
        ];

        group.bench_function(&bench_id, |b| {
            b.iter(|| {
                black_box(sks.mul_low_partial_sum(&d_lhs, &d_rhs, &d_extras, false, &streams));
            })
        });

        write_to_json_unchecked(
            &bench_id,
            param.name(),
            "mul_low_partial_sum",
            &OperatorType::Atomic,
            num_blocks as u32 * BITS_PER_BLOCK,
            vec![atomic_param.message_modulus().0.ilog2(); num_blocks],
        );
        group.finish();
    }
}
