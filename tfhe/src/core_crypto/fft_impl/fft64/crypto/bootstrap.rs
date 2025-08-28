use super::super::math::fft::{Fft, FftView, FourierPolynomialList};
use super::ggsw::*;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::backward_compatibility::fft_impl::FourierLweBootstrapKeyVersions;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::{CastInto, UnsignedInteger};
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, MonomialDegree,
    PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, ContiguousEntityContainerMut, IntoContainerOwned, Split,
};
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::common::FourierBootstrapKey;
use crate::core_crypto::fft_impl::fft64::math::fft::par_convert_polynomials_list_to_fourier;
use crate::core_crypto::prelude::{
    lwe_ciphertext_modulus_switch, CiphertextCount, CiphertextModulus, ContainerMut,
    ModulusSwitchedLweCiphertext,
};
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;
use tfhe_versionable::Versionize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
#[versionize(FourierLweBootstrapKeyVersions)]
pub struct FourierLweBootstrapKey<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

pub type FourierLweBootstrapKeyView<'a> = FourierLweBootstrapKey<&'a [c64]>;
pub type FourierLweBootstrapKeyMutView<'a> = FourierLweBootstrapKey<&'a mut [c64]>;

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
                * fourier_ggsw_ciphertext_size(
                    glwe_size,
                    polynomial_size.to_fourier_polynomial_size(),
                    decomposition_level_count,
                )
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
    pub fn into_ggsw_iter(
        self,
    ) -> impl DoubleEndedIterator<Item = FourierGgswCiphertext<C>>
           + ExactSizeIterator<Item = FourierGgswCiphertext<C>>
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
        C: AsMut<[c64]>,
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

pub type FourierLweBootstrapKeyOwned = FourierLweBootstrapKey<ABox<[c64]>>;

impl FourierLweBootstrapKey<ABox<[c64]>> {
    pub fn new(
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        let boxed = avec![
            c64::default();
            input_lwe_dimension.0
                * fourier_ggsw_ciphertext_size(
                    glwe_size,
                    polynomial_size.to_fourier_polynomial_size(),
                    decomposition_level_count,
                )
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

/// Return the required memory for [`FourierLweBootstrapKeyMutView::fill_with_forward_fourier`].
pub fn fill_with_forward_fourier_scratch(fft: FftView<'_>) -> Result<StackReq, SizeOverflow> {
    fft.forward_scratch()
}

impl FourierLweBootstrapKeyMutView<'_> {
    /// Fill a bootstrapping key with the Fourier transform of a bootstrapping key in the standard
    /// domain.
    ///
    /// # Panics
    /// This will panic if self and coeff_bsk are not of the same size
    pub fn fill_with_forward_fourier<Scalar: UnsignedTorus>(
        mut self,
        coef_bsk: LweBootstrapKey<&'_ [Scalar]>,
        fft: FftView<'_>,
        stack: &mut PodStack,
    ) {
        for (fourier_ggsw, standard_ggsw) in
            izip_eq!(self.as_mut_view().into_ggsw_iter(), coef_bsk.iter())
        {
            fourier_ggsw.fill_with_forward_fourier(standard_ggsw, fft, stack);
        }
    }
    /// Fill a bootstrapping key with the Fourier transform of a bootstrapping key in the standard
    /// domain.
    pub fn par_fill_with_forward_fourier<Scalar: UnsignedTorus>(
        self,
        coef_bsk: LweBootstrapKey<&'_ [Scalar]>,
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

/// Return the required memory for [`FourierLweBootstrapKeyView::blind_rotate_assign`].
pub fn blind_rotate_assign_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_any_of([
        // tmp_poly allocation
        StackReq::try_new_aligned::<Scalar>(polynomial_size.0, CACHELINE_ALIGN)?,
        StackReq::try_all_of([
            // ct1 allocation
            StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?,
            // external product
            add_external_product_assign_scratch::<Scalar>(glwe_size, polynomial_size, fft)?,
        ])?,
    ])
}

/// Return the required memory for [`FourierLweBootstrapKeyView::bootstrap`].
pub fn bootstrap_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    blind_rotate_assign_scratch::<Scalar>(glwe_size, polynomial_size, fft)?.try_and(
        StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?,
    )
}

/// Return the required memory for [`FourierLweBootstrapKeyView::batch_blind_rotate_assign`].
pub fn batch_blind_rotate_assign_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ciphertext_count: CiphertextCount,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_any_of([
        // tmp_poly allocation
        StackReq::try_new_aligned::<Scalar>(polynomial_size.0, CACHELINE_ALIGN)?,
        StackReq::try_all_of([
            // ct1 allocation
            StackReq::try_new_aligned::<Scalar>(
                glwe_ciphertext_size(glwe_size, polynomial_size) * ciphertext_count.0,
                CACHELINE_ALIGN,
            )?,
            // external product
            add_external_product_assign_scratch::<Scalar>(glwe_size, polynomial_size, fft)?,
        ])?,
    ])
}

/// Return the required memory for [`FourierLweBootstrapKeyView::batch_bootstrap`].
pub fn batch_bootstrap_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ciphertext_count: CiphertextCount,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    batch_blind_rotate_assign_scratch::<Scalar>(glwe_size, polynomial_size, ciphertext_count, fft)?
        .try_and(StackReq::try_new_aligned::<Scalar>(
            glwe_ciphertext_size(glwe_size, polynomial_size) * ciphertext_count.0,
            CACHELINE_ALIGN,
        )?)
}

impl FourierLweBootstrapKeyView<'_> {
    pub fn blind_rotate_assign<OutputScalar>(
        self,
        mut lut: GlweCiphertextMutView<'_, OutputScalar>,
        msed_lwe: &impl ModulusSwitchedLweCiphertext<usize>,
        fft: FftView<'_>,
        stack: &mut PodStack,
    ) where
        OutputScalar: UnsignedTorus,
    {
        let lut_poly_size = lut.polynomial_size();
        let ciphertext_modulus = lut.ciphertext_modulus();
        assert!(ciphertext_modulus.is_compatible_with_native_modulus());

        assert_eq!(
            msed_lwe.log_modulus(),
            lut_poly_size.to_blind_rotation_input_modulus_log()
        );

        let msed_lwe_mask = msed_lwe.mask();

        let msed_lwe_body = msed_lwe.body();

        let monomial_degree = MonomialDegree(msed_lwe_body.cast_into());

        lut.as_mut_polynomial_list()
            .iter_mut()
            .for_each(|mut poly| {
                let (tmp_poly, _) = stack.make_aligned_raw(poly.as_ref().len(), CACHELINE_ALIGN);

                let mut tmp_poly = Polynomial::from_container(&mut *tmp_poly);
                tmp_poly.as_mut().copy_from_slice(poly.as_ref());
                polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, monomial_degree);
            });

        // We initialize the ct_0 used for the successive cmuxes
        let mut ct0 = lut;
        let (ct1, stack) = stack.make_aligned_raw(ct0.as_ref().len(), CACHELINE_ALIGN);
        let mut ct1 =
            GlweCiphertextMutView::from_container(&mut *ct1, lut_poly_size, ciphertext_modulus);

        for (lwe_mask_element, bootstrap_key_ggsw) in izip_eq!(msed_lwe_mask, self.into_ggsw_iter())
        {
            if lwe_mask_element != 0 {
                let monomial_degree = MonomialDegree(lwe_mask_element);

                // we effectively inline the body of cmux here, merging the initial subtraction
                // operation with the monic polynomial multiplication, then performing the external
                // product manually

                // We rotate ct_1 and subtract ct_0 (first step of cmux) by performing
                // ct_1 <- (ct_0 * X^{a_hat}) - ct_0
                for (mut ct1_poly, ct0_poly) in izip_eq!(
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
                add_external_product_assign(
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

    pub fn batch_blind_rotate_assign<OutputScalar>(
        self,
        mut lut_list: GlweCiphertextListMutView<'_, OutputScalar>,
        msed_lwe_list: &[impl ModulusSwitchedLweCiphertext<usize>],
        fft: FftView<'_>,
        stack: &mut PodStack,
    ) where
        OutputScalar: UnsignedTorus,
    {
        let lut_poly_size = lut_list.polynomial_size();
        let ciphertext_modulus = lut_list.ciphertext_modulus();
        assert!(ciphertext_modulus.is_compatible_with_native_modulus());

        for (mut lut, lwe) in izip_eq!(lut_list.as_mut_view().iter_mut(), msed_lwe_list.iter()) {
            let msed_lwe_body = lwe.body();

            let monomial_degree = MonomialDegree(msed_lwe_body.cast_into());

            lut.as_mut_polynomial_list()
                .iter_mut()
                .for_each(|mut poly| {
                    let (tmp_poly, _) =
                        stack.make_aligned_raw(poly.as_ref().len(), CACHELINE_ALIGN);

                    let mut tmp_poly = Polynomial::from_container(&mut *tmp_poly);
                    tmp_poly.as_mut().copy_from_slice(poly.as_ref());
                    polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, monomial_degree);
                });
        }

        // We initialize the ct_0 used for the successive cmuxes
        let mut ct0_list = lut_list;
        let (ct1_list, stack) = stack.make_aligned_raw(ct0_list.as_ref().len(), CACHELINE_ALIGN);
        let mut ct1_list = GlweCiphertextListMutView::from_container(
            &mut *ct1_list,
            ct0_list.glwe_size(),
            lut_poly_size,
            ciphertext_modulus,
        );

        for (idx, bootstrap_key_ggsw) in self.into_ggsw_iter().enumerate() {
            for (mut ct0, mut ct1, msed_lwe) in izip_eq!(
                ct0_list.as_mut_view().iter_mut(),
                ct1_list.as_mut_view().iter_mut(),
                msed_lwe_list.iter()
            ) {
                let mut msed_lwe_mask = msed_lwe.mask();
                let msed_lwe_mask_element = msed_lwe_mask.nth(idx).unwrap();

                if msed_lwe_mask_element != 0 {
                    let monomial_degree = MonomialDegree(msed_lwe_mask_element.cast_into());

                    // we effectively inline the body of cmux here, merging the initial subtraction
                    // operation with the monic polynomial multiplication, then performing the
                    // external product manually

                    // We rotate ct_1 and subtract ct_0 (first step of cmux) by performing
                    // ct_1 <- (ct_0 * X^{a_hat}) - ct_0
                    for (mut ct1_poly, ct0_poly) in izip_eq!(
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
                    add_external_product_assign(
                        ct0.as_mut_view(),
                        bootstrap_key_ggsw,
                        ct1.as_view(),
                        fft,
                        stack,
                    );
                }
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
            ct0_list
                .as_mut()
                .iter_mut()
                .for_each(|x| *x = signed_decomposer.closest_representable(*x));
        }
    }

    pub fn bootstrap<InputScalar, OutputScalar>(
        self,
        mut lwe_out: LweCiphertextMutView<'_, OutputScalar>,
        lwe_in: LweCiphertextView<'_, InputScalar>,
        accumulator: GlweCiphertextView<'_, OutputScalar>,
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
        let mut local_accumulator = GlweCiphertextMutView::from_container(
            &mut *local_accumulator_data,
            accumulator.polynomial_size(),
            accumulator.ciphertext_modulus(),
        );

        let log_modulus = accumulator
            .polynomial_size()
            .to_blind_rotation_input_modulus_log();

        let msed = lwe_ciphertext_modulus_switch(lwe_in.as_view(), log_modulus);

        self.blind_rotate_assign(local_accumulator.as_mut_view(), &msed, fft, stack);

        extract_lwe_sample_from_glwe_ciphertext(
            &local_accumulator,
            &mut lwe_out,
            MonomialDegree(0),
        );
    }

    pub fn batch_bootstrap<InputScalar, OutputScalar>(
        self,
        mut lwe_out: LweCiphertextListMutView<'_, OutputScalar>,
        lwes_in: LweCiphertextListView<'_, InputScalar>,
        accumulator: &GlweCiphertextListView<'_, OutputScalar>,
        fft: FftView<'_>,
        stack: &mut PodStack,
    ) where
        // CastInto required for PBS modulus switch which returns a usize
        InputScalar: UnsignedTorus + CastInto<usize>,
        OutputScalar: UnsignedTorus,
    {
        assert!(lwe_out.ciphertext_modulus().is_power_of_two());
        assert_eq!(
            lwe_out.ciphertext_modulus(),
            accumulator.ciphertext_modulus()
        );

        let (local_accumulator_data, stack) =
            stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
        let mut local_accumulator = GlweCiphertextListMutView::from_container(
            &mut *local_accumulator_data,
            accumulator.glwe_size(),
            accumulator.polynomial_size(),
            accumulator.ciphertext_modulus(),
        );

        let log_modulus = accumulator
            .polynomial_size()
            .to_blind_rotation_input_modulus_log();

        let lwe_in_msed: Vec<_> = lwes_in
            .iter()
            .map(|lwe_in| lwe_ciphertext_modulus_switch(lwe_in, log_modulus))
            .collect();

        self.batch_blind_rotate_assign(local_accumulator.as_mut_view(), &lwe_in_msed, fft, stack);

        for (mut lwe_out, local_accumulator) in
            izip_eq!(lwe_out.iter_mut(), local_accumulator.iter())
        {
            extract_lwe_sample_from_glwe_ciphertext(
                &local_accumulator,
                &mut lwe_out,
                MonomialDegree(0),
            );
        }
    }
}

impl<Scalar> FourierBootstrapKey<Scalar> for FourierLweBootstrapKeyOwned
where
    Scalar: UnsignedTorus + CastInto<usize>,
{
    type Fft = Fft;

    fn new_fft(polynomial_size: PolynomialSize) -> Self::Fft {
        Fft::new(polynomial_size)
    }

    fn new(
        input_lwe_dimension: LweDimension,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        Self::new(
            input_lwe_dimension,
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }

    fn fill_with_forward_fourier_scratch(fft: &Self::Fft) -> Result<StackReq, SizeOverflow> {
        fill_with_forward_fourier_scratch(fft.as_view())
    }

    fn fill_with_forward_fourier<ContBsk>(
        &mut self,
        coef_bsk: &LweBootstrapKey<ContBsk>,
        fft: &Self::Fft,
        stack: &mut PodStack,
    ) where
        ContBsk: Container<Element = Scalar>,
    {
        self.as_mut_view()
            .fill_with_forward_fourier(coef_bsk.as_view(), fft.as_view(), stack);
    }

    fn bootstrap_scratch(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        fft: &Self::Fft,
    ) -> Result<StackReq, SizeOverflow> {
        bootstrap_scratch::<Scalar>(glwe_size, polynomial_size, fft.as_view())
    }

    fn bootstrap<ContLweOut, ContLweIn, ContAcc>(
        &self,
        lwe_out: &mut LweCiphertext<ContLweOut>,
        lwe_in: &LweCiphertext<ContLweIn>,
        accumulator: &GlweCiphertext<ContAcc>,
        fft: &Self::Fft,
        stack: &mut PodStack,
    ) where
        ContLweOut: ContainerMut<Element = Scalar>,
        ContLweIn: Container<Element = Scalar>,
        ContAcc: Container<Element = Scalar>,
    {
        self.as_view().bootstrap(
            lwe_out.as_mut_view(),
            lwe_in.as_view(),
            accumulator.as_view(),
            fft.as_view(),
            stack,
        );
    }
}

#[derive(Clone, Copy)]
pub struct LweBootstrapKeyConformanceParams<Scalar: UnsignedInteger> {
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub input_lwe_dimension: LweDimension,
    pub output_glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<C: Container<Element = c64>> ParameterSetConformant for FourierLweBootstrapKey<C> {
    type ParameterSet = LweBootstrapKeyConformanceParams<u64>;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            fourier:
                FourierPolynomialList {
                    data,
                    polynomial_size,
                },
            input_lwe_dimension,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
        } = self;

        let LweBootstrapKeyConformanceParams {
            decomp_base_log: expected_decomp_base_log,
            decomp_level_count: expected_decomp_level_count,
            input_lwe_dimension: expected_input_lwe_dimension,
            output_glwe_size: expected_output_glwe_size,
            polynomial_size: expected_polynomial_size,
            ciphertext_modulus: _expected_ciphertext_modulus,
        } = parameter_set;

        data.container_len()
            == input_lwe_dimension.0
                * fourier_ggsw_ciphertext_size(
                    *glwe_size,
                    polynomial_size.to_fourier_polynomial_size(),
                    *decomposition_level_count,
                )
            && decomposition_base_log == expected_decomp_base_log
            && decomposition_level_count == expected_decomp_level_count
            && input_lwe_dimension == expected_input_lwe_dimension
            && glwe_size == expected_output_glwe_size
            && polynomial_size == expected_polynomial_size
    }
}
