use super::fourier_ggsw_ciphertext::FourierGgswCiphertext;
use super::fourier_polynomial_list::FourierPolynomialList;
use super::lwe_bootstrap_key::LweBootstrapKey;
use crate::core_crypto::algorithms::ggsw_conversion::convert_standard_ggsw_ciphertext_to_fourier_mem_optimized;
use crate::core_crypto::commons::math::fft64::{par_convert_polynomials_list_to_fourier, FftView};
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
};
use crate::core_crypto::commons::traits::contiguous_entity_container::{
    ContiguousEntityContainer, ContiguousEntityContainerMut,
};
use crate::core_crypto::commons::traits::{Container, ContainerMut, Split};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::fft_impl::common::pbs_modulus_switch;
use crate::core_crypto::prelude::polynomial_algorithms::{
    polynomial_wrapping_monic_monomial_div, polynomial_wrapping_monic_monomial_mul_and_subtract,
};
use crate::core_crypto::prelude::{
    add_external_product_assign_mem_optimized, extract_lwe_sample_from_glwe_ciphertext, CastInto,
    GlweCiphertextMutView, GlweCiphertextView, IntoContainerOwned, LutCountLog,
    LweCiphertextMutView, LweCiphertextView, ModulusSwitchOffset, MonomialDegree, Polynomial,
    SignedDecomposer, UnsignedTorus,
};
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
use concrete_fft::c64;
use dyn_stack::{PodStack, ReborrowMut};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
pub struct FourierLweBootstrapKey<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

pub type FourierLweBootstrapKeyView<'a> = FourierLweBootstrapKey<&'a [c64]>;
pub type FourierLweBootstrapKeyMutView<'a> = FourierLweBootstrapKey<&'a mut [c64]>;
pub type FourierLweBootstrapKeyOwned = FourierLweBootstrapKey<ABox<[c64]>>;

impl<C: Container<Element = c64>> FourierLweBootstrapKey<C> {
    pub fn from_container(
        data: C,
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            input_lwe_dimension.0
                * polynomial_size.to_fourier_polynomial_size().0
                * decomposition_level_count.0
                * glwe_size.0
                * glwe_size.0
        );
        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            input_lwe_dimension,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
        }
    }

    /// Return an iterator over the GGSW ciphertexts composing the key.
    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = FourierGgswCiphertext<C>>
    where
        C: Split,
    {
        self.fourier
            .data
            .split_into(self.input_lwe_dimension.0)
            .map(move |slice| {
                FourierGgswCiphertext::from_container(
                    slice,
                    self.glwe_size,
                    self.fourier.polynomial_size,
                    self.decomposition_base_log,
                    self.decomposition_level_count,
                )
            })
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.glwe_size
            .to_glwe_dimension()
            .to_equivalent_lwe_dimension(self.polynomial_size())
    }

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn as_view(&self) -> FourierLweBootstrapKeyView<'_> {
        FourierLweBootstrapKeyView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierLweBootstrapKeyMutView<'_>
    where
        C: ContainerMut<Element = c64>,
    {
        FourierLweBootstrapKeyMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }
}

impl FourierLweBootstrapKeyOwned {
    pub fn new(
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> FourierLweBootstrapKey<ABox<[c64]>> {
        let boxed = avec![
            c64::default();
            polynomial_size.to_fourier_polynomial_size().0
                * input_lwe_dimension.0
                * decomposition_level_count.0
                * glwe_size.0
                * glwe_size.0
        ]
        .into_boxed_slice();

        FourierLweBootstrapKey::from_container(
            boxed,
            input_lwe_dimension,
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }
}

impl<'a> FourierLweBootstrapKeyMutView<'a> {
    /// Fill a bootstrapping key with the Fourier transform of a bootstrapping key in the standard
    /// domain.
    pub fn fill_with_forward_fourier<Scalar: UnsignedTorus>(
        mut self,
        coef_bsk: LweBootstrapKey<&'_ [Scalar]>,
        fft: FftView<'_>,
        mut stack: PodStack<'_>,
    ) {
        for (mut fourier_ggsw, standard_ggsw) in
            izip!(self.as_mut_view().into_ggsw_iter(), coef_bsk.iter())
        {
            convert_standard_ggsw_ciphertext_to_fourier_mem_optimized(
                &standard_ggsw,
                &mut fourier_ggsw,
                fft,
                stack.rb_mut(),
            );
        }
    }
    /// Fill a bootstrapping key with the Fourier transform of a bootstrapping key in the standard
    /// domain.
    pub fn par_fill_with_forward_fourier<Scalar: UnsignedTorus>(
        self,
        coef_bsk: LweBootstrapKey<&'_ [Scalar]>,
        fft: FftView<'_>,
    ) {
        let polynomial_size = self.polynomial_size();
        par_convert_polynomials_list_to_fourier(
            self.data(),
            coef_bsk.into_container(),
            polynomial_size,
            fft,
        );
    }
}

impl<'a> FourierLweBootstrapKeyView<'a> {
    // CastInto required for PBS modulus switch which returns a usize
    pub fn blind_rotate_assign<Scalar: UnsignedTorus + CastInto<usize>>(
        self,
        mut lut: GlweCiphertextMutView<'_, Scalar>,
        lwe: &[Scalar],
        fft: FftView<'_>,
        mut stack: PodStack<'_>,
    ) {
        let (lwe_body, lwe_mask) = lwe.split_last().unwrap();

        let lut_poly_size = lut.polynomial_size();
        let ciphertext_modulus = lut.ciphertext_modulus();
        assert!(ciphertext_modulus.is_compatible_with_native_modulus());
        let monomial_degree = MonomialDegree(pbs_modulus_switch(
            *lwe_body,
            lut_poly_size,
            ModulusSwitchOffset(0),
            LutCountLog(0),
        ));

        lut.as_mut_polynomial_list()
            .iter_mut()
            .for_each(|mut poly| {
                let (mut tmp_poly, _) = stack
                    .rb_mut()
                    .make_aligned_raw(poly.as_ref().len(), CACHELINE_ALIGN);

                let mut tmp_poly = Polynomial::from_container(&mut *tmp_poly);
                tmp_poly.as_mut().copy_from_slice(poly.as_ref());
                polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, monomial_degree)
            });

        // We initialize the ct_0 used for the successive cmuxes
        let mut ct0 = lut;
        let (mut ct1, mut stack) = stack.make_aligned_raw(ct0.as_ref().len(), CACHELINE_ALIGN);
        let mut ct1 =
            GlweCiphertextMutView::from_container(&mut *ct1, lut_poly_size, ciphertext_modulus);

        for (lwe_mask_element, bootstrap_key_ggsw) in izip!(lwe_mask.iter(), self.into_ggsw_iter())
        {
            if *lwe_mask_element != Scalar::ZERO {
                let monomial_degree = MonomialDegree(pbs_modulus_switch(
                    *lwe_mask_element,
                    lut_poly_size,
                    ModulusSwitchOffset(0),
                    LutCountLog(0),
                ));

                // we effectively inline the body of cmux here, merging the initial subtraction
                // operation with the monic polynomial multiplication, then performing the external
                // product manually

                // We rotate ct_1 and subtract ct_0 (first step of cmux) by performing
                // ct_1 <- (ct_0 * X^{a_hat}) - ct_0
                for (mut ct1_poly, ct0_poly) in izip!(
                    ct1.as_mut_polynomial_list().iter_mut(),
                    ct0.as_polynomial_list().iter(),
                ) {
                    polynomial_wrapping_monic_monomial_mul_and_subtract(
                        &mut ct1_poly,
                        &ct0_poly,
                        monomial_degree,
                    );
                }

                // second step of cmux
                add_external_product_assign_mem_optimized(
                    &mut ct0,
                    &bootstrap_key_ggsw,
                    &ct1,
                    fft,
                    stack.rb_mut(),
                );
            }
        }

        if !ciphertext_modulus.is_native_modulus() {
            // When we convert back from the fourier domain, integer values will contain up to 53
            // MSBs with information. In our representation of power of 2 moduli < native modulus we
            // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
            // round while keeping the data in the MSBs
            let signed_decomposer = SignedDecomposer::new(
                DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                DecompositionLevelCount(1),
            );
            ct0.as_mut()
                .iter_mut()
                .for_each(|x| *x = signed_decomposer.closest_representable(*x));
        }
    }

    pub fn bootstrap<Scalar>(
        self,
        mut lwe_out: LweCiphertextMutView<'_, Scalar>,
        lwe_in: LweCiphertextView<'_, Scalar>,
        accumulator: GlweCiphertextView<'_, Scalar>,
        fft: FftView<'_>,
        stack: PodStack<'_>,
    ) where
        // CastInto required for PBS modulus switch which returns a usize
        Scalar: UnsignedTorus + CastInto<usize>,
    {
        debug_assert_eq!(lwe_out.ciphertext_modulus(), lwe_in.ciphertext_modulus());
        debug_assert_eq!(
            lwe_in.ciphertext_modulus(),
            accumulator.ciphertext_modulus()
        );

        let (mut local_accumulator_data, stack) =
            stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
        let mut local_accumulator = GlweCiphertextMutView::from_container(
            &mut *local_accumulator_data,
            accumulator.polynomial_size(),
            accumulator.ciphertext_modulus(),
        );
        self.blind_rotate_assign(local_accumulator.as_mut_view(), lwe_in.as_ref(), fft, stack);

        extract_lwe_sample_from_glwe_ciphertext(
            &local_accumulator,
            &mut lwe_out,
            MonomialDegree(0),
        );
    }
}
