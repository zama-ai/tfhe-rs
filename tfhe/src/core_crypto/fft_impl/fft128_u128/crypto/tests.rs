use super::super::super::{fft128, fft128_u128};
use super::super::math::fft::Fft128View;
use super::ggsw::collect_next_term_split_scalar;
use crate::core_crypto::fft_impl::common::tests::{
    gen_keys_or_get_from_cache_if_enabled, generate_keys,
};
use crate::core_crypto::prelude::test::{TestResources, FFT128_U128_PARAMS};
use crate::core_crypto::prelude::*;
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodBuffer, PodStack};

#[test]
fn test_split_external_product() {
    let params = FFT128_U128_PARAMS;

    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let ciphertext_modulus = params.ciphertext_modulus;
    let ciphertext_modulus_split = CiphertextModulus::<u64>::new_native();

    let mut rsc = TestResources::new();

    let mut glwe = GlweCiphertext::new(
        0u128,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    for x in glwe.as_mut() {
        *x = rand::random();
    }

    let mut keys_gen = |params| generate_keys(params, &mut rsc);
    let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
    let std_bootstrapping_key = keys.bsk;

    let mut fourier_bsk = Fourier128LweBootstrapKey::new(
        std_bootstrapping_key.input_lwe_dimension(),
        std_bootstrapping_key.glwe_size(),
        std_bootstrapping_key.polynomial_size(),
        std_bootstrapping_key.decomposition_base_log(),
        std_bootstrapping_key.decomposition_level_count(),
    );

    let fft = Fft128::new(polynomial_size);
    let fft = fft.as_view();
    fourier_bsk.fill_with_forward_fourier(&std_bootstrapping_key, fft);
    let ggsw = fourier_bsk.as_view().into_ggsw_iter().next().unwrap();

    let mut glwe_lo = GlweCiphertext::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus_split,
    );
    let mut glwe_hi = GlweCiphertext::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus_split,
    );

    for ((lo, hi), val) in glwe_lo
        .as_mut()
        .iter_mut()
        .zip(glwe_hi.as_mut())
        .zip(glwe.as_ref())
    {
        *lo = *val as u64;
        *hi = (*val >> 64) as u64;
    }

    let mut out = GlweCiphertext::new(
        0u128,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    fft128::crypto::ggsw::add_external_product_assign(
        &mut out,
        &ggsw,
        &glwe,
        fft,
        PodStack::new(&mut PodBuffer::new(
            fft128::crypto::ggsw::add_external_product_assign_scratch::<u128>(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                fft,
            ),
        )),
    );

    let mut out_lo = GlweCiphertext::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus_split,
    );
    let mut out_hi = GlweCiphertext::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus_split,
    );

    fft128_u128::crypto::ggsw::add_external_product_assign_split(
        &mut out_lo,
        &mut out_hi,
        &ggsw,
        &glwe_lo,
        &glwe_hi,
        fft,
        PodStack::new(&mut PodBuffer::new(
            fft128::crypto::ggsw::add_external_product_assign_scratch::<u128>(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                fft,
            ),
        )),
    );

    for ((lo, hi), val) in out_lo
        .as_ref()
        .iter()
        .zip(out_hi.as_ref())
        .zip(out.as_ref())
    {
        assert_eq!(*val as u64, *lo);
        assert_eq!((*val >> 64) as u64, *hi);
    }
}

#[test]
fn test_split_pbs() {
    let params = FFT128_U128_PARAMS;

    let small_lwe_dimension = params.lwe_dimension;
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let ciphertext_modulus = params.ciphertext_modulus;

    let mut rsc = TestResources::new();

    let mut keys_gen = |params| generate_keys(params, &mut rsc);
    let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
    let std_bootstrapping_key = keys.bsk;

    let mut fourier_bsk = Fourier128LweBootstrapKey::new(
        std_bootstrapping_key.input_lwe_dimension(),
        std_bootstrapping_key.glwe_size(),
        std_bootstrapping_key.polynomial_size(),
        std_bootstrapping_key.decomposition_base_log(),
        std_bootstrapping_key.decomposition_level_count(),
    );

    let fft = Fft128::new(polynomial_size);
    let fft = fft.as_view();
    fourier_bsk.fill_with_forward_fourier(&std_bootstrapping_key, fft);

    let mut lwe_in =
        LweCiphertext::new(0u128, small_lwe_dimension.to_lwe_size(), ciphertext_modulus);
    let mut accumulator = GlweCiphertext::new(
        0u128,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    let mut mem = PodBuffer::new(fft128::crypto::bootstrap::bootstrap_scratch::<u128>(
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        fft,
    ));
    let stack = PodStack::new(&mut mem);

    for _ in 0..20 {
        for x in lwe_in.as_mut() {
            *x = rand::random();
        }
        for x in accumulator.as_mut() {
            *x = rand::random();
        }

        let mut lwe_out_non_split = LweCiphertext::new(
            0u128,
            glwe_dimension
                .to_equivalent_lwe_dimension(polynomial_size)
                .to_lwe_size(),
            ciphertext_modulus,
        );

        // Needed as the basic bootstrap function dispatches to the more efficient split version for
        // u128
        fn blind_rotate_non_split<Scalar: UnsignedTorus + CastInto<usize>>(
            this: Fourier128LweBootstrapKey<&[f64]>,
            mut lwe_out: LweCiphertext<&mut [Scalar]>,
            msed_lwe_in: &impl ModulusSwitchedLweCiphertext<usize>,
            accumulator: GlweCiphertext<&[Scalar]>,
            fft: Fft128View<'_>,
            stack: &mut PodStack,
        ) {
            let (local_accumulator_data, stack) =
                stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
            let mut local_accumulator = GlweCiphertextMutView::from_container(
                &mut *local_accumulator_data,
                accumulator.polynomial_size(),
                accumulator.ciphertext_modulus(),
            );

            this.blind_rotate_assign(
                &mut local_accumulator.as_mut_view(),
                msed_lwe_in,
                fft,
                stack,
            );

            extract_lwe_sample_from_glwe_ciphertext(
                &local_accumulator,
                &mut lwe_out,
                MonomialDegree(0),
            );
        }

        let log_modulus = accumulator
            .polynomial_size()
            .to_blind_rotation_input_modulus_log();

        let lwe_in = lwe_ciphertext_modulus_switch(lwe_in.as_view(), log_modulus);

        blind_rotate_non_split(
            fourier_bsk.as_view(),
            lwe_out_non_split.as_mut_view(),
            &lwe_in,
            accumulator.as_view(),
            fft,
            stack,
        );

        let mut lwe_out_split = LweCiphertext::new(
            0u128,
            glwe_dimension
                .to_equivalent_lwe_dimension(polynomial_size)
                .to_lwe_size(),
            ciphertext_modulus,
        );
        fourier_bsk.blind_rotate_u128(&mut lwe_out_split, &lwe_in, &accumulator, fft, stack);

        assert_eq!(lwe_out_split, lwe_out_non_split);
    }
}

#[test]
fn test_decomposition_edge_case_sign_handling_split_u128() {
    let decomposer = SignedDecomposer::new(DecompositionBaseLog(40), DecompositionLevelCount(3));
    // This value triggers a negative state at the start of the decomposition, invalid code using
    // logic shift will wrongly compute an intermediate value by not keeping the sign of the
    // state on the last level if base_log * (level_count + 1) > Scalar::BITS, the logic shift will
    // shift in 0s instead of the 1s to keep the sign information
    let val = 170141183460604905165246226680529368983u128;
    let base_log = decomposer.base_log;

    let expected = [-421613125320i128, 482008863255, -549755813888];

    let decomp_state = decomposer.init_decomposer_state(val);
    let mut decomp_state_lo = decomp_state as u64;
    let mut decomp_state_hi = (decomp_state >> 64) as u64;

    let mod_b_mask = (1u128 << decomposer.base_log) - 1;
    let mod_b_mask_lo = mod_b_mask as u64;
    let mod_b_mask_hi = (mod_b_mask >> 64) as u64;

    for expect in expected {
        let mut decomp_term_lo = 0u64;
        let mut decomp_term_hi = 0u64;

        collect_next_term_split_scalar(
            core::slice::from_mut(&mut decomp_term_lo),
            core::slice::from_mut(&mut decomp_term_hi),
            core::slice::from_mut(&mut decomp_state_lo),
            core::slice::from_mut(&mut decomp_state_hi),
            mod_b_mask_lo,
            mod_b_mask_hi,
            base_log,
        );

        let term_value_u128 = ((decomp_term_hi as u128) << 64) | decomp_term_lo as u128;
        let term_value_i128 = term_value_u128 as i128;

        assert_eq!(term_value_i128, expect);
    }
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn test_decomposition_edge_case_sign_handling_split_u128_avx2() {
    use super::ggsw::collect_next_term_split_avx2;

    let Some(simd) = pulp::x86::V3::try_new() else {
        return;
    };

    let decomposer = SignedDecomposer::new(DecompositionBaseLog(40), DecompositionLevelCount(3));
    // This value triggers a negative state at the start of the decomposition, invalid code using
    // logic shift will wrongly compute an intermediate value by not keeping the sign of the
    // state on the last level if base_log * (level_count + 1) > Scalar::BITS, the logic shift will
    // shift in 0s instead of the 1s to keep the sign information
    let val = 170141183460604905165246226680529368983u128;
    let base_log = decomposer.base_log;

    let expected = [-421613125320i128, 482008863255, -549755813888];

    let decomp_state = decomposer.init_decomposer_state(val);
    let mut decomp_state_lo = [decomp_state as u64; 4];
    let mut decomp_state_hi = [(decomp_state >> 64) as u64; 4];

    let mod_b_mask = (1u128 << decomposer.base_log) - 1;
    let mod_b_mask_lo = mod_b_mask as u64;
    let mod_b_mask_hi = (mod_b_mask >> 64) as u64;

    for expect in expected {
        let mut decomp_term_lo = [0u64; 4];
        let mut decomp_term_hi = [0u64; 4];

        collect_next_term_split_avx2(
            simd,
            &mut decomp_term_lo,
            &mut decomp_term_hi,
            &mut decomp_state_lo,
            &mut decomp_state_hi,
            mod_b_mask_lo,
            mod_b_mask_hi,
            base_log,
        );

        for (decomp_term_hi, decomp_term_lo) in decomp_term_hi.into_iter().zip(decomp_term_lo) {
            let term_value_u128 = ((decomp_term_hi as u128) << 64) | decomp_term_lo as u128;
            let term_value_i128 = term_value_u128 as i128;

            assert_eq!(term_value_i128, expect);
        }
    }
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "avx512")]
fn test_decomposition_edge_case_sign_handling_split_u128_avx512() {
    use super::ggsw::collect_next_term_split_avx512;

    let Some(simd) = pulp::x86::V4::try_new() else {
        return;
    };

    let decomposer = SignedDecomposer::new(DecompositionBaseLog(40), DecompositionLevelCount(3));
    // This value triggers a negative state at the start of the decomposition, invalid code using
    // logic shift will wrongly compute an intermediate value by not keeping the sign of the
    // state on the last level if base_log * (level_count + 1) > Scalar::BITS, the logic shift will
    // shift in 0s instead of the 1s to keep the sign information
    let val = 170141183460604905165246226680529368983u128;
    let base_log = decomposer.base_log;

    let expected = [-421613125320i128, 482008863255, -549755813888];

    let decomp_state = decomposer.init_decomposer_state(val);
    let mut decomp_state_lo = [decomp_state as u64; 8];
    let mut decomp_state_hi = [(decomp_state >> 64) as u64; 8];

    let mod_b_mask = (1u128 << decomposer.base_log) - 1;
    let mod_b_mask_lo = mod_b_mask as u64;
    let mod_b_mask_hi = (mod_b_mask >> 64) as u64;

    for expect in expected {
        let mut decomp_term_lo = [0u64; 8];
        let mut decomp_term_hi = [0u64; 8];

        collect_next_term_split_avx512(
            simd,
            &mut decomp_term_lo,
            &mut decomp_term_hi,
            &mut decomp_state_lo,
            &mut decomp_state_hi,
            mod_b_mask_lo,
            mod_b_mask_hi,
            base_log,
        );

        for (decomp_term_hi, decomp_term_lo) in decomp_term_hi.into_iter().zip(decomp_term_lo) {
            let term_value_u128 = ((decomp_term_hi as u128) << 64) | decomp_term_lo as u128;
            let term_value_i128 = term_value_u128 as i128;

            assert_eq!(term_value_i128, expect);
        }
    }
}
