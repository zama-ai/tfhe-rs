use super::super::math::fft::{FftView, FourierPolynomialList};
use super::cm_ggsw::{
    cm_add_external_product_assign_scratch, cm_cmux_scratch, FourierCmGgswCiphertext,
};
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::parameters::{
    CmDimension, DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension,
    MonomialDegree, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, ContiguousEntityContainerMut, IntoContainerOwned, Split,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::fft_impl::fft64::crypto::cm_ggsw::cm_add_external_product_assign;
use crate::core_crypto::fft_impl::fft64::math::fft::par_convert_polynomials_list_to_fourier;
use crate::core_crypto::prelude::extract_lwe_sample_from_cm_glwe_ciphertext;
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use itertools::Itertools;
use tfhe_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
pub struct FourierCmLweBootstrapKey<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    input_lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

pub type FourierCmLweBootstrapKeyView<'a> = FourierCmLweBootstrapKey<&'a [c64]>;
pub type FourierCmLweBootstrapKeyMutView<'a> = FourierCmLweBootstrapKey<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierCmLweBootstrapKey<C> {
    pub fn from_container(
        data: C,
        input_lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            input_lwe_dimension.0
                * polynomial_size.to_fourier_polynomial_size().0
                * decomposition_level_count.0
                * (glwe_dimension.0 + cm_dimension.0)
                * (glwe_dimension.0 + cm_dimension.0)
        );
        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            input_lwe_dimension,
            glwe_dimension,
            cm_dimension,
            decomposition_base_log,
            decomposition_level_count,
        }
    }

    /// Return an iterator over the GGSW ciphertexts composing the key.
    pub fn into_cm_ggsw_iter(self) -> impl DoubleEndedIterator<Item = FourierCmGgswCiphertext<C>>
    where
        C: Split,
    {
        self.fourier
            .data
            .split_into(self.input_lwe_dimension.0)
            .map(move |slice| {
                FourierCmGgswCiphertext::from_container(
                    slice,
                    self.glwe_dimension,
                    self.cm_dimension,
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

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub fn cm_dimension(&self) -> CmDimension {
        self.cm_dimension
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.glwe_dimension
            .to_equivalent_lwe_dimension(self.polynomial_size())
    }

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn as_view(&self) -> FourierCmLweBootstrapKeyView<'_> {
        FourierCmLweBootstrapKeyView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierCmLweBootstrapKeyMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierCmLweBootstrapKeyMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }
}

pub type FourierCmLweBootstrapKeyOwned = FourierCmLweBootstrapKey<ABox<[c64]>>;

impl FourierCmLweBootstrapKey<ABox<[c64]>> {
    pub fn new(
        input_lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        let boxed = avec![
            c64::default();
            polynomial_size.to_fourier_polynomial_size().0
                * input_lwe_dimension.0
                * decomposition_level_count.0
                * (glwe_dimension.0 + cm_dimension.0)
                * (glwe_dimension.0 + cm_dimension.0)
        ]
        .into_boxed_slice();

        FourierCmLweBootstrapKey::from_container(
            boxed,
            input_lwe_dimension,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }
}

/// Return the required memory for [`FourierCmLweBootstrapKeyMutView::fill_with_forward_fourier`].
pub fn fill_with_forward_fourier_scratch(fft: FftView<'_>) -> Result<StackReq, SizeOverflow> {
    fft.forward_scratch()
}

impl FourierCmLweBootstrapKeyMutView<'_> {
    /// Fill a bootstrapping key with the Fourier transform of a bootstrapping key in the standard
    /// domain.
    pub fn fill_with_forward_fourier<Scalar: UnsignedTorus>(
        mut self,
        coef_bsk: CmLweBootstrapKey<&'_ [Scalar]>,
        fft: FftView<'_>,
        stack: &mut PodStack,
    ) {
        for (fourier_ggsw, standard_ggsw) in
            izip!(self.as_mut_view().into_cm_ggsw_iter(), coef_bsk.iter())
        {
            fourier_ggsw.fill_with_forward_fourier(standard_ggsw, fft, stack);
        }
    }
    /// Fill a bootstrapping key with the Fourier transform of a bootstrapping key in the standard
    /// domain.
    pub fn par_fill_with_forward_fourier<Scalar: UnsignedTorus>(
        self,
        coef_bsk: CmLweBootstrapKey<&'_ [Scalar]>,
        fft: FftView<'_>,
    ) {
        let polynomial_size = self.fourier.polynomial_size;
        par_convert_polynomials_list_to_fourier(
            self.data(),
            coef_bsk.into_container(),
            polynomial_size,
            fft,
        );
    }
}

/// Return the required memory for [`FourierCmLweBootstrapKeyView::cm_blind_rotate_assign`].
pub fn blind_rotate_scratch<Scalar>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_any_of([
        // tmp_poly allocation
        StackReq::try_new_aligned::<Scalar>(polynomial_size.0, CACHELINE_ALIGN)?,
        StackReq::try_all_of([
            // ct1 allocation
            StackReq::try_new_aligned::<Scalar>(
                (glwe_dimension.0 + cm_dimension.0) * polynomial_size.0,
                CACHELINE_ALIGN,
            )?,
            // external product
            cm_add_external_product_assign_scratch::<Scalar>(
                glwe_dimension,
                cm_dimension,
                polynomial_size,
                fft,
            )?,
        ])?,
    ])
}

/// Return the required memory for [`FourierCmLweBootstrapKeyView::cm_bootstrap`].
pub fn cm_bootstrap_scratch<Scalar>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    blind_rotate_scratch::<Scalar>(glwe_dimension, cm_dimension, polynomial_size, fft)?.try_and(
        StackReq::try_new_aligned::<Scalar>(
            (glwe_dimension.0 + cm_dimension.0) * polynomial_size.0,
            CACHELINE_ALIGN,
        )?,
    )
}

pub fn cm_blind_rotate_assign_scratch<Scalar>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_all_of([
        StackReq::try_new_aligned::<Scalar>(
            polynomial_size.0 * (glwe_dimension.0 + cm_dimension.0),
            CACHELINE_ALIGN,
        )?,
        cm_cmux_scratch::<Scalar>(glwe_dimension, cm_dimension, polynomial_size, fft)?,
    ])
}

impl FourierCmLweBootstrapKeyView<'_> {
    // CastInto required for PBS modulus switch which returns a usize
    pub fn cm_blind_rotate_assign<InputScalar, OutputScalar>(
        self,
        mut luts: CmGlweCiphertextMutView<'_, OutputScalar>,
        lwe: CmLweCiphertextView<'_, InputScalar>,
        fft: FftView<'_>,
        stack: &mut PodStack,
    ) where
        InputScalar: UnsignedTorus + CastInto<usize>,
        OutputScalar: UnsignedTorus,
    {
        let mask = lwe.get_mask();
        let bodies = lwe.get_bodies();

        let lut_poly_size = luts.polynomial_size();
        let ciphertext_modulus = luts.ciphertext_modulus();
        assert!(ciphertext_modulus.is_compatible_with_native_modulus());

        let log_modulus = lut_poly_size.to_blind_rotation_input_modulus_log();

        luts.get_mut_bodies()
            .as_mut_polynomial_list()
            .iter_mut()
            .zip_eq(bodies.iter())
            .for_each(|(mut poly, body)| {
                let monomial_degree =
                    MonomialDegree(modulus_switch((*body.data).cast_into(), log_modulus));

                let (tmp_poly, _) = stack.make_aligned_raw(poly.as_ref().len(), CACHELINE_ALIGN);

                let mut tmp_poly = Polynomial::from_container(&mut *tmp_poly);
                tmp_poly.as_mut().copy_from_slice(poly.as_ref());
                polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, monomial_degree);
            });

        // We initialize the ct_0 used for the successive cmuxes
        let mut ct0 = luts;
        let (ct1, stack) = stack.make_aligned_raw(ct0.as_ref().len(), CACHELINE_ALIGN);
        let mut ct1 = CmGlweCiphertextMutView::from_container(
            &mut *ct1,
            self.glwe_dimension,
            self.cm_dimension,
            lut_poly_size,
            ciphertext_modulus,
        );

        for (lwe_mask_element, bootstrap_key_ggsw) in
            izip!(mask.as_ref().iter(), self.into_cm_ggsw_iter())
        {
            if *lwe_mask_element != InputScalar::ZERO {
                let monomial_degree =
                    MonomialDegree(modulus_switch((*lwe_mask_element).cast_into(), log_modulus));

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

                // as_mut_view is required to keep borrow rules consistent
                // second step of cmux
                cm_add_external_product_assign(
                    ct0.as_mut_view(),
                    bootstrap_key_ggsw,
                    ct1.as_view(),
                    fft,
                    stack,
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

    pub fn cm_bootstrap<InputScalar, OutputScalar>(
        self,
        mut lwe_out: CmLweCiphertextMutView<'_, OutputScalar>,
        lwe_in: CmLweCiphertextView<'_, InputScalar>,
        accumulator: CmGlweCiphertextView<'_, OutputScalar>,
        fft: FftView<'_>,
        stack: &mut PodStack,
    ) where
        // CastInto required for PBS modulus switch which returns a usize
        InputScalar: UnsignedTorus + CastInto<usize>,
        OutputScalar: UnsignedTorus,
    {
        assert!(lwe_in.ciphertext_modulus().is_power_of_two());
        assert!(lwe_out.ciphertext_modulus().is_power_of_two());
        assert_eq!(
            lwe_out.ciphertext_modulus(),
            accumulator.ciphertext_modulus()
        );

        let (local_accumulator_data, stack) =
            stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
        let mut local_accumulator = CmGlweCiphertextMutView::from_container(
            &mut *local_accumulator_data,
            accumulator.glwe_dimension(),
            accumulator.cm_dimension(),
            accumulator.polynomial_size(),
            accumulator.ciphertext_modulus(),
        );

        // for i in local_accumulator.get_bodies().iter() {
        //     for j in i.as_polynomial().into_container() {
        //         print!("{:.2}, ", j.into_torus());
        //     }
        //     println!();

        //     println!();
        // }

        // println!();

        self.cm_blind_rotate_assign(
            local_accumulator.as_mut_view(),
            lwe_in.as_view(),
            fft,
            stack,
        );

        // for i in local_accumulator.get_bodies().iter() {
        //     for j in i.as_polynomial().into_container() {
        //         print!("{:.2}, ", j.into_torus());
        //     }
        //     println!();
        //     println!();
        // }

        // println!();

        extract_lwe_sample_from_cm_glwe_ciphertext(
            &local_accumulator,
            &mut lwe_out,
            MonomialDegree(0),
        );
    }
}
