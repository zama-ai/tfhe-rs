//! `u128` (split lo/hi `u64`-limb) path of the "half-product" 128-bit FFT bootstrap.
//!
//! Split analog of [`Fourier128LweBootstrapKey::blind_rotate_u128`] for the
//! [`Fourier128HalfProductLweBootstrapKey`]. See the [`fft128` half-product
//! module][crate::core_crypto::fft_impl::fft128::crypto::bootstrap_half_product] for the generic
//! (non-`u128`) path and the type definition.

use super::super::math::fft::Fft128View;
use super::bootstrap::{
    polynomial_wrapping_monic_monomial_div_assign_split,
    polynomial_wrapping_monic_monomial_mul_assign_split,
};
use super::ggsw_half_product::cmux_split_half_product;
use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, MonomialDegree,
};
use crate::core_crypto::commons::traits::ContiguousEntityContainerMut;
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft128::crypto::ggsw_half_product::Fourier128HalfProductGgswCiphertext;
use crate::core_crypto::prelude::{Container, ContainerMut, ModulusSwitchedLweCiphertext};
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::PodStack;

/// One cmux of a `u128` (split lo/hi) half-product blind rotation. A no-op when
/// `lwe_mask_element == 0`.
#[inline]
pub(crate) fn cmux_step_split_half_product<ContGgsw>(
    ct0_lo: &mut GlweCiphertext<&mut [u64]>,
    ct0_hi: &mut GlweCiphertext<&mut [u64]>,
    lwe_mask_element: usize,
    ggsw: &Fourier128HalfProductGgswCiphertext<ContGgsw>,
    fft: Fft128View<'_>,
    stack: &mut PodStack,
) where
    ContGgsw: Container<Element = f64>,
{
    if lwe_mask_element == 0 {
        return;
    }

    // We copy ct_0 to ct_1
    let (ct1_lo, stack) = stack.collect_aligned(CACHELINE_ALIGN, ct0_lo.as_ref().iter().copied());
    let (ct1_hi, stack) = stack.collect_aligned(CACHELINE_ALIGN, ct0_hi.as_ref().iter().copied());
    let mut ct1_lo = GlweCiphertextMutView::from_container(
        ct1_lo,
        ct0_lo.polynomial_size(),
        ct0_lo.ciphertext_modulus(),
    );
    let mut ct1_hi = GlweCiphertextMutView::from_container(
        ct1_hi,
        ct0_lo.polynomial_size(),
        ct0_lo.ciphertext_modulus(),
    );

    // We rotate ct_1 by performing ct_1 <- ct_1 * X^{lwe_mask_element}
    for (poly_lo, poly_hi) in izip_eq!(
        ct1_lo.as_mut_polynomial_list().iter_mut(),
        ct1_hi.as_mut_polynomial_list().iter_mut(),
    ) {
        polynomial_wrapping_monic_monomial_mul_assign_split(
            poly_lo,
            poly_hi,
            MonomialDegree(lwe_mask_element),
        );
    }

    cmux_split_half_product(ct0_lo, ct0_hi, &mut ct1_lo, &mut ct1_hi, ggsw, fft, stack);
}

impl<Cont> Fourier128HalfProductLweBootstrapKey<Cont>
where
    Cont: Container<Element = f64>,
{
    /// Blind-rotate the lo/hi (`u64`-limb) split representation of a `u128` accumulator in place.
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
            this: Fourier128HalfProductLweBootstrapKey<&[f64]>,
            mut lut_lo: GlweCiphertext<&mut [u64]>,
            mut lut_hi: GlweCiphertext<&mut [u64]>,
            msed_lwe: &impl ModulusSwitchedLweCiphertext<usize>,
            fft: Fft128View<'_>,
            stack: &mut PodStack,
        ) {
            assert_eq!(
                msed_lwe.lwe_dimension(),
                this.input_lwe_dimension(),
                "The input LWE dimension must match the input dimension of the key"
            );

            let msed_lwe_mask = msed_lwe.mask();
            let msed_lwe_body = msed_lwe.body();

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

            for (lwe_mask_element, bootstrap_key_ggsw) in
                izip_eq!(msed_lwe_mask, this.into_ggsw_iter())
            {
                cmux_step_split_half_product(
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

    /// `u128` blind rotation using the split (lo/hi `u64`) representation, as in
    /// [`crate::core_crypto::fft_impl::fft128_u128`].
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
            this: Fourier128HalfProductLweBootstrapKey<&[f64]>,
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
    use crate::core_crypto::fft_impl::fft128::crypto::bootstrap_half_product::half_product_bootstrap_scratch;
    use crate::core_crypto::fft_impl::fft128::math::fft::Fft128;
    use crate::core_crypto::prelude::test::{TestResources, FFT128_U128_PARAMS};
    use dyn_stack::PodBuffer;

    // The half-product `u128` split path (`blind_rotate_u128`) must match the generic (non-split)
    // `blind_rotate_assign` path bit-for-bit, mirroring `test_split_pbs` for the classic key.
    #[test]
    fn test_half_product_split_pbs() {
        use crate::core_crypto::algorithms::{
            par_allocate_and_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128,
            par_allocate_and_generate_new_half_product_lwe_bootstrap_key,
        };

        let params = FFT128_U128_PARAMS;

        let small_lwe_dimension = params.lwe_dimension;
        let glwe_dimension = params.glwe_dimension;
        let polynomial_size = params.polynomial_size;
        let ciphertext_modulus = params.ciphertext_modulus;
        let glwe_noise_distribution = params.glwe_noise_distribution;

        // Fewer body levels than mask levels: this is what makes the key a half-product one.
        let base_log_mask = DecompositionBaseLog(24);
        let level_mask = DecompositionLevelCount(3);
        let base_log_body = DecompositionBaseLog(31);
        let level_body = DecompositionLevelCount(2);

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

        let std_bsk = par_allocate_and_generate_new_half_product_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            base_log_mask,
            level_mask,
            base_log_body,
            level_body,
            glwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );
        let fourier_bsk =
            par_allocate_and_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128(
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

        let mut mem = PodBuffer::try_new(half_product_bootstrap_scratch::<u128>(
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            fft,
        ))
        .unwrap();
        let stack = PodStack::new(&mut mem);

        // Needed as the basic bootstrap function dispatches to the more efficient split version for
        // u128.
        fn blind_rotate_non_split(
            this: Fourier128HalfProductLweBootstrapKey<&[f64]>,
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
