//! `u128` (split lo/hi `u64`-limb) path of the "half-rotate" 128-bit FFT bootstrap.
//!
//! Split analog of [`Fourier128LweBootstrapKey::blind_rotate_u128`] for the two-section
//! [`Fourier128HalfRotateLweBootstrapKey`]. See the [`fft128` half-rotate
//! module][crate::core_crypto::fft_impl::fft128::crypto::bootstrap_half_rotate] for the generic
//! (non-`u128`) path and the type definition.

use super::super::math::fft::Fft128View;
use super::bootstrap::{cmux_step_split, polynomial_wrapping_monic_monomial_div_assign_split};
use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, MonomialDegree,
};
use crate::core_crypto::commons::traits::ContiguousEntityContainerMut;
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{Container, ContainerMut, ModulusSwitchedLweCiphertext};
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::PodStack;

impl<Cont> Fourier128HalfRotateLweBootstrapKey<Cont>
where
    Cont: Container<Element = f64>,
{
    /// Blind-rotate the lo/hi (`u64`-limb) split representation of a `u128` accumulator in place,
    /// running the two sections one after the other. Split analog of
    /// [`Self::blind_rotate_assign`][crate::core_crypto::fft_impl::fft128::crypto::bootstrap_half_rotate]
    /// and the half-rotate counterpart of [`Fourier128LweBootstrapKey::blind_rotate_assign_split`].
    pub fn blind_rotate_assign_split<ContLutLo, ContLutHi>(
        &self,
        lut_lo: &mut GlweCiphertext<ContLutLo>,
        lut_hi: &mut GlweCiphertext<ContLutHi>,
        msed_lwe: &impl ModulusSwitchedLweCiphertext<usize>,
        fft: Fft128View<'_>,
        stack: &mut PodStack,
    ) where
        ContLutLo: ContainerMut<Element = u64>,
        ContLutHi: ContainerMut<Element = u64>,
    {
        fn implementation(
            this: Fourier128HalfRotateLweBootstrapKey<&[f64]>,
            mut lut_lo: GlweCiphertext<&mut [u64]>,
            mut lut_hi: GlweCiphertext<&mut [u64]>,
            msed_lwe: &impl ModulusSwitchedLweCiphertext<usize>,
            fft: Fft128View<'_>,
            stack: &mut PodStack,
        ) {
            assert_eq!(
                msed_lwe.lwe_dimension(),
                this.input_lwe_dimension(),
                "The input LWE dimension must match the total input dimension of the two sections"
            );

            let msed_lwe_body = msed_lwe.body();

            // The body rotation is shared by both sections and applied only once.
            for (poly_lo, poly_hi) in izip_eq!(
                lut_lo.as_mut_polynomial_list().iter_mut(),
                lut_hi.as_mut_polynomial_list().iter_mut(),
            ) {
                polynomial_wrapping_monic_monomial_div_assign_split(
                    poly_lo,
                    poly_hi,
                    MonomialDegree(msed_lwe_body),
                );
            }

            // We initialize the ct_0 used for the successive cmuxes.
            let mut ct0_lo = lut_lo;
            let mut ct0_hi = lut_hi;

            // The successive cmuxes over the two sections, the mask being split in the same place
            // as the key.
            let input_lwe_dimension_start = this.input_lwe_dimension_start().0;
            for (bootstrap_key_ggsw, lwe_mask_element) in izip_eq!(
                this.start().as_view().into_ggsw_iter(),
                msed_lwe.mask().take(input_lwe_dimension_start)
            ) {
                cmux_step_split(
                    &mut ct0_lo,
                    &mut ct0_hi,
                    lwe_mask_element,
                    &bootstrap_key_ggsw,
                    fft,
                    stack,
                );
            }
            for (bootstrap_key_ggsw, lwe_mask_element) in izip_eq!(
                this.end().as_view().into_ggsw_iter(),
                msed_lwe.mask().skip(input_lwe_dimension_start)
            ) {
                cmux_step_split(
                    &mut ct0_lo,
                    &mut ct0_hi,
                    lwe_mask_element,
                    &bootstrap_key_ggsw,
                    fft,
                    stack,
                );
            }
        }
        implementation(
            self.as_view(),
            lut_lo.as_mut_view(),
            lut_hi.as_mut_view(),
            msed_lwe,
            fft,
            stack,
        );
    }

    /// `u128` blind rotation over the two sections, using the split (lo/hi `u64`) representation,
    /// as in [`crate::core_crypto::fft_impl::fft128_u128`].
    pub fn blind_rotate_u128<ContLweOut, ContAcc>(
        &self,
        lwe_out: &mut LweCiphertext<ContLweOut>,
        msed_lwe_in: &impl ModulusSwitchedLweCiphertext<usize>,
        accumulator: &GlweCiphertext<ContAcc>,
        fft: Fft128View<'_>,
        stack: &mut PodStack,
    ) where
        ContLweOut: ContainerMut<Element = u128>,
        ContAcc: Container<Element = u128>,
    {
        fn implementation(
            this: Fourier128HalfRotateLweBootstrapKey<&[f64]>,
            mut lwe_out: LweCiphertext<&mut [u128]>,
            msed_lwe_in: &impl ModulusSwitchedLweCiphertext<usize>,
            accumulator: GlweCiphertext<&[u128]>,
            fft: Fft128View<'_>,
            stack: &mut PodStack,
        ) {
            let align = CACHELINE_ALIGN;
            let ciphertext_modulus = accumulator.ciphertext_modulus();

            let (local_accumulator_lo, stack) =
                stack.collect_aligned(align, accumulator.as_ref().iter().map(|i| *i as u64));
            let (local_accumulator_hi, stack) = stack.collect_aligned(
                align,
                accumulator.as_ref().iter().map(|i| (*i >> 64) as u64),
            );

            // Here we split a u128 into two u64 containers and the ciphertext modulus does not
            // match anymore in terms of the underlying Scalar type, so we provide a
            // dummy native modulus.
            let mut local_accumulator_lo = GlweCiphertextMutView::from_container(
                local_accumulator_lo,
                accumulator.polynomial_size(),
                CiphertextModulus::new_native(),
            );
            let mut local_accumulator_hi = GlweCiphertextMutView::from_container(
                local_accumulator_hi,
                accumulator.polynomial_size(),
                CiphertextModulus::new_native(),
            );

            this.blind_rotate_assign_split(
                &mut local_accumulator_lo,
                &mut local_accumulator_hi,
                msed_lwe_in,
                fft,
                stack,
            );

            let (local_accumulator, _) = stack.collect_aligned(
                align,
                izip_eq!(local_accumulator_lo.as_ref(), local_accumulator_hi.as_ref())
                    .map(|(&lo, &hi)| lo as u128 | ((hi as u128) << 64)),
            );
            let mut local_accumulator = GlweCiphertextMutView::from_container(
                local_accumulator,
                accumulator.polynomial_size(),
                accumulator.ciphertext_modulus(),
            );

            assert!(ciphertext_modulus.is_compatible_with_native_modulus());
            if !ciphertext_modulus.is_native_modulus() {
                // See the same block in `Fourier128LweBootstrapKey::blind_rotate_u128`.
                let signed_decomposer = SignedDecomposer::new(
                    DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                    DecompositionLevelCount(1),
                );
                local_accumulator
                    .as_mut()
                    .iter_mut()
                    .for_each(|x| *x = signed_decomposer.closest_representable(*x));
            }

            extract_lwe_sample_from_glwe_ciphertext(
                &local_accumulator,
                &mut lwe_out,
                MonomialDegree(0),
            );
        }

        implementation(
            self.as_view(),
            lwe_out.as_mut_view(),
            msed_lwe_in,
            accumulator.as_view(),
            fft,
            stack,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_crypto::algorithms::lwe_ciphertext_modulus_switch;
    use crate::core_crypto::fft_impl::fft128::crypto::bootstrap_half_rotate::half_rotate_bootstrap_scratch;
    use crate::core_crypto::fft_impl::fft128::math::fft::Fft128;
    use crate::core_crypto::prelude::test::{TestResources, FFT128_U128_PARAMS};
    use crate::core_crypto::prelude::LweDimension;
    use dyn_stack::PodBuffer;

    // The half-rotate `u128` split path (`blind_rotate_u128`) must match the generic (non-split)
    // `blind_rotate_assign` path bit-for-bit, mirroring `test_split_pbs` for the non-half-rotate
    // key.
    #[test]
    fn test_half_rotate_split_pbs() {
        use crate::core_crypto::algorithms::{
            par_allocate_and_convert_standard_half_rotate_lwe_bootstrap_key_to_fourier_128,
            par_allocate_and_generate_new_half_rotate_lwe_bootstrap_key,
        };

        let params = FFT128_U128_PARAMS;

        let small_lwe_dimension = params.lwe_dimension;
        let glwe_dimension = params.glwe_dimension;
        let polynomial_size = params.polynomial_size;
        let ciphertext_modulus = params.ciphertext_modulus;
        let glwe_noise_distribution = params.glwe_noise_distribution;

        // Split the input mask into two sections with distinct decomposition parameters.
        let input_lwe_dimension_start = LweDimension(282);
        let base_log_start = DecompositionBaseLog(32);
        let level_start = DecompositionLevelCount(2);
        let base_log_end = DecompositionBaseLog(24);
        let level_end = DecompositionLevelCount(3);

        let mut rsc = TestResources::new();

        let small_lwe_sk: LweSecretKeyOwned<u128> = LweSecretKey::generate_new_binary(
            small_lwe_dimension,
            &mut rsc.secret_random_generator,
        );
        let glwe_sk: GlweSecretKeyOwned<u128> = GlweSecretKey::generate_new_binary(
            glwe_dimension,
            polynomial_size,
            &mut rsc.secret_random_generator,
        );

        let std_bsk = par_allocate_and_generate_new_half_rotate_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            input_lwe_dimension_start,
            base_log_start,
            level_start,
            base_log_end,
            level_end,
            glwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );
        let fourier_bsk =
            par_allocate_and_convert_standard_half_rotate_lwe_bootstrap_key_to_fourier_128(
                &std_bsk,
            );

        let fft = Fft128::new(polynomial_size);
        let fft = fft.as_view();

        let mut lwe_in =
            LweCiphertext::new(0u128, small_lwe_dimension.to_lwe_size(), ciphertext_modulus);
        let mut accumulator = GlweCiphertext::new(
            0u128,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            ciphertext_modulus,
        );

        let mut mem = PodBuffer::try_new(half_rotate_bootstrap_scratch::<u128>(
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            fft,
        ))
        .unwrap();
        let stack = PodStack::new(&mut mem);

        // Needed as the basic bootstrap function dispatches to the more efficient split version for
        // u128.
        fn blind_rotate_non_split(
            this: Fourier128HalfRotateLweBootstrapKey<&[f64]>,
            mut lwe_out: LweCiphertext<&mut [u128]>,
            msed_lwe_in: &impl ModulusSwitchedLweCiphertext<usize>,
            accumulator: GlweCiphertext<&[u128]>,
            fft: Fft128View<'_>,
            stack: &mut PodStack,
        ) {
            let (local_accumulator_data, stack) =
                stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
            let mut local_accumulator = GlweCiphertextMutView::from_container(
                local_accumulator_data,
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

        for _ in 0..5 {
            for x in lwe_in.as_mut() {
                *x = rand::random();
            }
            for x in accumulator.as_mut() {
                *x = rand::random();
            }

            let out_lwe_size = glwe_dimension
                .to_equivalent_lwe_dimension(polynomial_size)
                .to_lwe_size();

            let log_modulus = accumulator
                .polynomial_size()
                .to_blind_rotation_input_modulus_log();
            let msed_lwe_in = lwe_ciphertext_modulus_switch(lwe_in.as_view(), log_modulus);

            let mut lwe_out_non_split = LweCiphertext::new(0u128, out_lwe_size, ciphertext_modulus);
            blind_rotate_non_split(
                fourier_bsk.as_view(),
                lwe_out_non_split.as_mut_view(),
                &msed_lwe_in,
                accumulator.as_view(),
                fft,
                stack,
            );

            let mut lwe_out_split = LweCiphertext::new(0u128, out_lwe_size, ciphertext_modulus);
            fourier_bsk.blind_rotate_u128(
                &mut lwe_out_split,
                &msed_lwe_in,
                &accumulator,
                fft,
                stack,
            );

            assert_eq!(lwe_out_split, lwe_out_non_split);
        }
    }
}
