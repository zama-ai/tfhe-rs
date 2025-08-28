use super::super::math::fft::{wrapping_neg, Fft128View};
use super::ggsw::cmux_split;
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

pub fn polynomial_wrapping_monic_monomial_mul_assign_split(
    output_lo: Polynomial<&mut [u64]>,
    output_hi: Polynomial<&mut [u64]>,
    monomial_degree: MonomialDegree,
) {
    let output_lo = output_lo.into_container();
    let output_hi = output_hi.into_container();
    let full_cycles_count = monomial_degree.0 / output_lo.container_len();
    if full_cycles_count % 2 != 0 {
        izip_eq!(&mut *output_lo, &mut *output_hi)
            .for_each(|(lo, hi)| (*lo, *hi) = wrapping_neg((*lo, *hi)));
    }
    let remaining_degree = monomial_degree.0 % output_lo.container_len();
    output_lo.rotate_right(remaining_degree);
    output_hi.rotate_right(remaining_degree);
    izip_eq!(output_lo, output_hi)
        .take(remaining_degree)
        .for_each(|(lo, hi)| (*lo, *hi) = wrapping_neg((*lo, *hi)));
}

pub fn polynomial_wrapping_monic_monomial_div_assign_split(
    output_lo: Polynomial<&mut [u64]>,
    output_hi: Polynomial<&mut [u64]>,
    monomial_degree: MonomialDegree,
) {
    let output_lo = output_lo.into_container();
    let output_hi = output_hi.into_container();
    let full_cycles_count = monomial_degree.0 / output_lo.container_len();
    if full_cycles_count % 2 != 0 {
        izip_eq!(&mut *output_lo, &mut *output_hi)
            .for_each(|(lo, hi)| (*lo, *hi) = wrapping_neg((*lo, *hi)));
    }
    let remaining_degree = monomial_degree.0 % output_lo.container_len();
    output_lo.rotate_left(remaining_degree);
    output_hi.rotate_left(remaining_degree);
    izip_eq!(output_lo, output_hi)
        .rev()
        .take(remaining_degree)
        .for_each(|(lo, hi)| (*lo, *hi) = wrapping_neg((*lo, *hi)));
}

impl<Cont> Fourier128LweBootstrapKey<Cont>
where
    Cont: Container<Element = f64>,
{
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
            this: Fourier128LweBootstrapKey<&[f64]>,
            mut lut_lo: GlweCiphertext<&mut [u64]>,
            mut lut_hi: GlweCiphertext<&mut [u64]>,
            msed_lwe: &impl ModulusSwitchedLweCiphertext<usize>,
            fft: Fft128View<'_>,
            stack: &mut PodStack,
        ) {
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

            // We initialize the ct_0 used for the successive cmuxes
            let mut ct0_lo = lut_lo;
            let mut ct0_hi = lut_hi;

            for (lwe_mask_element, bootstrap_key_ggsw) in
                izip_eq!(msed_lwe_mask, this.into_ggsw_iter())
            {
                if lwe_mask_element != 0 {
                    let stack = &mut *stack;
                    // We copy ct_0 to ct_1
                    let (ct1_lo, stack) =
                        stack.collect_aligned(CACHELINE_ALIGN, ct0_lo.as_ref().iter().copied());
                    let (ct1_hi, stack) =
                        stack.collect_aligned(CACHELINE_ALIGN, ct0_hi.as_ref().iter().copied());
                    let mut ct1_lo = GlweCiphertextMutView::from_container(
                        &mut *ct1_lo,
                        ct0_lo.polynomial_size(),
                        ct0_lo.ciphertext_modulus(),
                    );
                    let mut ct1_hi = GlweCiphertextMutView::from_container(
                        &mut *ct1_hi,
                        ct0_lo.polynomial_size(),
                        ct0_lo.ciphertext_modulus(),
                    );

                    // We rotate ct_1 by performing ct_1 <- ct_1 * X^{a_hat}
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

                    cmux_split(
                        &mut ct0_lo,
                        &mut ct0_hi,
                        &mut ct1_lo,
                        &mut ct1_hi,
                        &bootstrap_key_ggsw,
                        fft,
                        stack,
                    );
                }
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
            this: Fourier128LweBootstrapKey<&[f64]>,
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

            let mut local_accumulator_lo = GlweCiphertextMutView::from_container(
                &mut *local_accumulator_lo,
                accumulator.polynomial_size(),
                // Here we split a u128 to two u64 containers and the ciphertext modulus does not
                // match anymore in terms of the underlying Scalar type, so we'll provide a dummy
                // native modulus
                CiphertextModulus::new_native(),
            );
            let mut local_accumulator_hi = GlweCiphertextMutView::from_container(
                &mut *local_accumulator_hi,
                accumulator.polynomial_size(),
                // Here we split a u128 to two u64 containers and the ciphertext modulus does not
                // match anymore in terms of the underlying Scalar type, so we'll provide a dummy
                // native modulus
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
                &mut *local_accumulator,
                accumulator.polynomial_size(),
                accumulator.ciphertext_modulus(),
            );

            assert!(ciphertext_modulus.is_compatible_with_native_modulus());
            if !ciphertext_modulus.is_native_modulus() {
                // When we convert back from the fourier domain, integer values will contain up to
                // about 100 MSBs with information. In our representation of power of 2
                // moduli < native modulus we fill the MSBs and leave the LSBs
                // empty, this usage of the signed decomposer allows to round while
                // keeping the data in the MSBs
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
