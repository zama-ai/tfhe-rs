use super::super::math::fft::{Fft, FftView, FourierPolynomialList};
use super::ggsw::*;
use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::backward_compatibility::fft_impl::{
    FourierLweBootstrapKeyVersioned, FourierLweBootstrapKeyVersionedOwned,
    FourierPolynomialListVersioned, FourierPolynomialListVersionedOwned,
};
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, MonomialDegree,
    PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, ContiguousEntityContainerMut, IntoContainerOwned, Split,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::common::{pbs_modulus_switch, FourierBootstrapKey};
use crate::core_crypto::fft_impl::fft64::math::fft::par_convert_polynomials_list_to_fourier;
use crate::core_crypto::prelude::ContainerMut;
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
use concrete_fft::c64;
use dyn_stack::{PodStack, ReborrowMut, SizeOverflow, StackReq};
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
pub struct FourierLweBootstrapKey<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

#[derive(serde::Serialize)]
pub struct FourierLweBootstrapKeyVersion<'vers> {
    fourier: FourierPolynomialListVersioned<'vers>,
    input_lwe_dimension: <LweDimension as Versionize>::Versioned<'vers>,
    glwe_size: <GlweSize as Versionize>::Versioned<'vers>,
    decomposition_base_log: <DecompositionBaseLog as Versionize>::Versioned<'vers>,
    decomposition_level_count: <DecompositionLevelCount as Versionize>::Versioned<'vers>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct FourierLweBootstrapKeyVersionOwned {
    fourier: FourierPolynomialListVersionedOwned,
    input_lwe_dimension: <LweDimension as Versionize>::VersionedOwned,
    glwe_size: <GlweSize as Versionize>::VersionedOwned,
    decomposition_base_log: <DecompositionBaseLog as Versionize>::VersionedOwned,
    decomposition_level_count: <DecompositionLevelCount as Versionize>::VersionedOwned,
}

impl<'vers, C: Container<Element = c64>> From<&'vers FourierLweBootstrapKey<C>>
    for FourierLweBootstrapKeyVersion<'vers>
{
    fn from(value: &'vers FourierLweBootstrapKey<C>) -> Self {
        Self {
            fourier: value.fourier.versionize(),
            input_lwe_dimension: value.input_lwe_dimension.versionize(),
            glwe_size: value.glwe_size.versionize(),
            decomposition_base_log: value.decomposition_base_log.versionize(),
            decomposition_level_count: value.decomposition_level_count.versionize(),
        }
    }
}

impl<C: Container<Element = c64>> From<&FourierLweBootstrapKey<C>>
    for FourierLweBootstrapKeyVersionOwned
{
    fn from(value: &FourierLweBootstrapKey<C>) -> Self {
        Self {
            fourier: value.fourier.versionize_owned(),
            input_lwe_dimension: value.input_lwe_dimension.versionize_owned(),
            glwe_size: value.glwe_size.versionize_owned(),
            decomposition_base_log: value.decomposition_base_log.versionize_owned(),
            decomposition_level_count: value.decomposition_level_count.versionize_owned(),
        }
    }
}

impl<C: IntoContainerOwned<Element = c64>> TryFrom<FourierLweBootstrapKeyVersionOwned>
    for FourierLweBootstrapKey<C>
{
    type Error = UnversionizeError;
    fn try_from(value: FourierLweBootstrapKeyVersionOwned) -> Result<Self, Self::Error> {
        Ok(Self {
            fourier: FourierPolynomialList::unversionize(value.fourier)?,
            input_lwe_dimension: LweDimension::unversionize(value.input_lwe_dimension)?,
            glwe_size: GlweSize::unversionize(value.glwe_size)?,
            decomposition_base_log: DecompositionBaseLog::unversionize(
                value.decomposition_base_log,
            )?,
            decomposition_level_count: DecompositionLevelCount::unversionize(
                value.decomposition_level_count,
            )?,
        })
    }
}

impl<C: Container<Element = c64>> Versionize for FourierLweBootstrapKey<C> {
    type Versioned<'vers> = FourierLweBootstrapKeyVersioned<'vers> where C: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.into()
    }

    type VersionedOwned = FourierLweBootstrapKeyVersionedOwned;

    fn versionize_owned(&self) -> Self::VersionedOwned {
        self.into()
    }
}

impl<C: IntoContainerOwned<Element = c64>> Unversionize for FourierLweBootstrapKey<C> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Self::try_from(versioned)
    }
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
        LweDimension((self.glwe_size.0 - 1) * self.polynomial_size().0)
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

/// Return the required memory for [`FourierLweBootstrapKeyMutView::fill_with_forward_fourier`].
pub fn fill_with_forward_fourier_scratch(fft: FftView<'_>) -> Result<StackReq, SizeOverflow> {
    fft.forward_scratch()
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
        for (fourier_ggsw, standard_ggsw) in
            izip!(self.as_mut_view().into_ggsw_iter(), coef_bsk.iter())
        {
            fourier_ggsw.fill_with_forward_fourier(standard_ggsw, fft, stack.rb_mut());
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
pub fn blind_rotate_scratch<Scalar>(
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
    blind_rotate_scratch::<Scalar>(glwe_size, polynomial_size, fft)?.try_and(
        StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?,
    )
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
        let monomial_degree = MonomialDegree(pbs_modulus_switch(*lwe_body, lut_poly_size));

        lut.as_mut_polynomial_list()
            .iter_mut()
            .for_each(|mut poly| {
                let (mut tmp_poly, _) = stack
                    .rb_mut()
                    .make_aligned_raw(poly.as_ref().len(), CACHELINE_ALIGN);

                let mut tmp_poly = Polynomial::from_container(&mut *tmp_poly);
                tmp_poly.as_mut().copy_from_slice(poly.as_ref());
                polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, monomial_degree);
            });

        // We initialize the ct_0 used for the successive cmuxes
        let mut ct0 = lut;
        let (mut ct1, mut stack) = stack.make_aligned_raw(ct0.as_ref().len(), CACHELINE_ALIGN);
        let mut ct1 =
            GlweCiphertextMutView::from_container(&mut *ct1, lut_poly_size, ciphertext_modulus);

        for (lwe_mask_element, bootstrap_key_ggsw) in izip!(lwe_mask.iter(), self.into_ggsw_iter())
        {
            if *lwe_mask_element != Scalar::ZERO {
                let monomial_degree =
                    MonomialDegree(pbs_modulus_switch(*lwe_mask_element, lut_poly_size));

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
                add_external_product_assign(
                    ct0.as_mut_view(),
                    bootstrap_key_ggsw,
                    ct1.as_view(),
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
        stack: PodStack<'_>,
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
        stack: PodStack<'_>,
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
