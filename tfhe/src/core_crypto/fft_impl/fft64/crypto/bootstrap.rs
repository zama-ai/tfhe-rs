use super::super::math::fft::{Fft, FftView, FourierPolynomialList};
use super::ggsw::*;
use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::glwe_linear_algebra::glwe_ciphertext_sub_assign;
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::backward_compatibility::fft_impl::{
    FourierLweBootstrapKeyVersioned, FourierLweBootstrapKeyVersionedOwned,
    FourierPolynomialListVersioned, FourierPolynomialListVersionedOwned,
};
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, Ly23ExtensionFactor,
    Ly23ShortcutCoeffCount, MonomialDegree, PolynomialSize,
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
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

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
#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]
pub struct FourierLweBootstrapKeyVersion<'vers> {
    fourier: FourierPolynomialListVersioned<'vers>,
    input_lwe_dimension: <LweDimension as Versionize>::Versioned<'vers>,
    glwe_size: <GlweSize as Versionize>::Versioned<'vers>,
    decomposition_base_log: <DecompositionBaseLog as Versionize>::Versioned<'vers>,
    decomposition_level_count: <DecompositionLevelCount as Versionize>::Versioned<'vers>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]
pub struct FourierLweBootstrapKeyVersionOwned {
    fourier: FourierPolynomialListVersionedOwned,
    input_lwe_dimension: <LweDimension as VersionizeOwned>::VersionedOwned,
    glwe_size: <GlweSize as VersionizeOwned>::VersionedOwned,
    decomposition_base_log: <DecompositionBaseLog as VersionizeOwned>::VersionedOwned,
    decomposition_level_count: <DecompositionLevelCount as VersionizeOwned>::VersionedOwned,
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

impl<C: Container<Element = c64>> From<FourierLweBootstrapKey<C>>
    for FourierLweBootstrapKeyVersionOwned
{
    fn from(value: FourierLweBootstrapKey<C>) -> Self {
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
}

impl<C: Container<Element = c64>> VersionizeOwned for FourierLweBootstrapKey<C> {
    type VersionedOwned = FourierLweBootstrapKeyVersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
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

/// Return the required memory for [`FourierLweBootstrapKeyView::blind_rotate_assign_ly23`].
pub fn blind_rotate_ly23_scratch<Scalar>(
    glwe_size: GlweSize,
    small_polynomial_size: PolynomialSize,
    extension_factor: Ly23ExtensionFactor,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    // split ct0 allocation
    // we need (k + 1) * N * 2^nu
    let split_ct0_req_iter = std::iter::repeat(StackReq::try_new_aligned::<Scalar>(
        glwe_size.0 * small_polynomial_size.0 * extension_factor.0,
        CACHELINE_ALIGN,
    )?)
    .take(extension_factor.0);

    // split ct1 allocation
    // we need (k + 1) * N * 2^nu
    let split_ct1_req_iter = std::iter::repeat(StackReq::try_new_aligned::<Scalar>(
        glwe_size.0 * small_polynomial_size.0 * extension_factor.0,
        CACHELINE_ALIGN,
    )?)
    .take(extension_factor.0);

    StackReq::try_any_of([
        // tmp_poly allocation
        StackReq::try_new_aligned::<Scalar>(
            small_polynomial_size.0 * extension_factor.0,
            CACHELINE_ALIGN,
        )?,
        StackReq::try_all_of(split_ct0_req_iter.chain(split_ct1_req_iter).chain([
            // diff_buffer allocation
            // we need (k + 1) * N
            StackReq::try_new_aligned::<Scalar>(
                glwe_size.0 * small_polynomial_size.0,
                CACHELINE_ALIGN,
            )?,
            // external product
            add_external_product_assign_scratch::<Scalar>(glwe_size, small_polynomial_size, fft)?,
        ]))?,
    ])
}

/// Return the required memory for [`FourierLweBootstrapKeyView::bootstrap_ly23`].
pub fn bootstrap_ly23_scratch<Scalar>(
    glwe_size: GlweSize,
    small_polynomial_size: PolynomialSize,
    extension_factor: Ly23ExtensionFactor,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    blind_rotate_ly23_scratch::<Scalar>(glwe_size, small_polynomial_size, extension_factor, fft)?
        .try_and(StackReq::try_new_aligned::<Scalar>(
            glwe_size.0 * small_polynomial_size.0 * extension_factor.0,
            CACHELINE_ALIGN,
        )?)
}

use std::cell::UnsafeCell;

#[derive(Copy, Clone)]
pub struct UnsafeSlice<'a, T> {
    slice: &'a [UnsafeCell<T>],
}
unsafe impl<'a, T: Send + Sync> Send for UnsafeSlice<'a, T> {}
unsafe impl<'a, T: Send + Sync> Sync for UnsafeSlice<'a, T> {}

impl<'a, T> UnsafeSlice<'a, T> {
    pub fn new(slice: &'a mut [T]) -> Self {
        let ptr = std::ptr::from_mut::<[T]>(slice) as *const [UnsafeCell<T>];
        Self {
            slice: unsafe { &*ptr },
        }
    }

    // /// SAFETY: It is UB if two threads write to the same index without
    // /// synchronization.
    // pub unsafe fn write(&self, i: usize, value: T) {
    //     let ptr = self.slice[i].get();
    //     *ptr = value;
    // }

    pub unsafe fn read(&self, idx: usize) -> &T {
        let ptr = self.slice[idx].get();
        &*ptr
    }

    pub unsafe fn write(&self, idx: usize) -> *mut T {
        self.slice[idx].get()
    }
}

impl<'a> FourierLweBootstrapKeyView<'a> {
    // CastInto required for PBS modulus switch which returns a usize
    pub fn blind_rotate_assign<InputScalar, OutputScalar>(
        self,
        mut lut: GlweCiphertextMutView<'_, OutputScalar>,
        lwe: &[InputScalar],
        fft: FftView<'_>,
        mut stack: PodStack<'_>,
    ) where
        InputScalar: UnsignedTorus + CastInto<usize>,
        OutputScalar: UnsignedTorus,
    {
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
            if *lwe_mask_element != InputScalar::ZERO {
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

    // The clippy "fix" actually makes the thread spawning fail because of map being lazy evaled
    #[allow(clippy::needless_collect)]
    pub fn blind_rotate_assign_ly23_parallelized<Scalar: UnsignedTorus + CastInto<usize>>(
        self,
        mut lut: GlweCiphertextMutView<'_, Scalar>,
        lwe: &[Scalar],
        extension_factor: Ly23ExtensionFactor,
        fft: FftView<'_>,
        mut stack: PodStack<'_>,
        thread_stacks: &mut [PodStack<'_>],
    ) -> GlweCiphertextOwned<Scalar> {
        assert_eq!(thread_stacks.len(), extension_factor.0);

        let (lwe_body, lwe_mask) = lwe.split_last().unwrap();

        let lut_poly_size = lut.polynomial_size();
        let ciphertext_modulus = lut.ciphertext_modulus();
        assert!(ciphertext_modulus.is_compatible_with_native_modulus());
        assert_eq!(
            self.polynomial_size().0 * extension_factor.0,
            lut_poly_size.0
        );
        let monomial_degree = MonomialDegree(pbs_modulus_switch(
            *lwe_body,
            // This one should be the extended polynomial size
            lut_poly_size,
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

        let ct0 = lut;

        let mut split_ct0 = Vec::with_capacity(extension_factor.0);

        let mut split_ct1 = Vec::with_capacity(extension_factor.0);

        let substack0 = {
            let mut current_stack = stack;
            for _ in 0..extension_factor.0 {
                let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                    self.glwe_size.0 * self.polynomial_size().0,
                    CACHELINE_ALIGN,
                );
                split_ct0.push(GlweCiphertext::from_container(
                    glwe_cont,
                    self.polynomial_size(),
                    ct0.ciphertext_modulus(),
                ));
                current_stack = substack;
            }
            current_stack
        };

        let _substack1 = {
            let mut current_stack = substack0;
            for _ in 0..extension_factor.0 {
                let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                    self.glwe_size.0 * self.polynomial_size().0,
                    CACHELINE_ALIGN,
                );
                split_ct1.push(GlweCiphertext::from_container(
                    glwe_cont,
                    self.polynomial_size(),
                    ct0.ciphertext_modulus(),
                ));
                current_stack = substack;
            }
            current_stack
        };

        // Split the LUT into small LUTs
        for (idx, coeff) in ct0.as_ref().iter().copied().enumerate() {
            let dst_lut = &mut split_ct0[idx % extension_factor.0];
            dst_lut.as_mut()[idx / extension_factor.0] = coeff;
        }

        // let split_ct0 = split_ct0
        //     .into_iter()
        //     .map(std::sync::RwLock::new)
        //     .collect::<Vec<_>>();
        // let split_ct1 = split_ct1
        //     .into_iter()
        //     .map(std::sync::RwLock::new)
        //     .collect::<Vec<_>>();

        let thread_split_ct0 = UnsafeSlice::new(&mut split_ct0);
        let thread_split_ct1 = UnsafeSlice::new(&mut split_ct1);

        use std::sync::Barrier;
        let barrier = Barrier::new(extension_factor.0);

        std::thread::scope(|s| {
            let thread_processing = |id: usize, stack: &mut PodStack<'_>| {
                let ct_dst_idx = id;
                let extension_factor_log2 = extension_factor.0.ilog2();
                let extension_factor_rem_mask = extension_factor.0 - 1;

                let (mut diff_dyn_array, mut stack) = stack.rb_mut().make_aligned_raw::<Scalar>(
                    self.glwe_size().0 * self.polynomial_size().0,
                    CACHELINE_ALIGN,
                );

                let mut diff_buffer = GlweCiphertext::from_container(
                    &mut *diff_dyn_array,
                    self.polynomial_size(),
                    ct0.ciphertext_modulus(),
                );

                for (mask_idx, (mask_element, ggsw)) in lwe_mask
                    .iter()
                    .zip(self.as_view().into_ggsw_iter())
                    .enumerate()
                {
                    let monomial_degree =
                        MonomialDegree(pbs_modulus_switch(*mask_element, lut_poly_size));
                    // Update the lut we look at simulating the rotation in the larger lut
                    let ct_src_idx =
                        (ct_dst_idx.wrapping_sub(monomial_degree.0)) & extension_factor_rem_mask;

                    // Compute the end of the rotation
                    // N' = 2^nu * N
                    // new_lut_idx = (ai + old_lut_idx) % 2^nu
                    // (2^nu + (ai % 2N') - 1 - new_lut_idx)/2^nu a l'air de marcher pour x
                    // X^ai monomial degree = mod switch(ai)
                    // already % 2N'
                    let small_monomial_degree = MonomialDegree(
                        (extension_factor.0 + monomial_degree.0 - 1 - ct_dst_idx)
                            >> extension_factor_log2,
                    );

                    let rotated_buffer = {
                        let (src_to_rotate, dst_rotated, src_unrotated) = if (mask_idx % 2) == 0 {
                            unsafe {
                                (
                                    thread_split_ct0.read(ct_src_idx),
                                    &mut *thread_split_ct1.write(ct_dst_idx),
                                    thread_split_ct0.read(ct_dst_idx),
                                )
                            }
                        } else {
                            unsafe {
                                (
                                    thread_split_ct1.read(ct_src_idx),
                                    &mut *thread_split_ct0.write(ct_dst_idx),
                                    thread_split_ct1.read(ct_dst_idx),
                                )
                            }
                        };

                        // Prepare the destination for the ext prod by copying the unrotated
                        // accumulator there
                        dst_rotated.as_mut().copy_from_slice(src_unrotated.as_ref());

                        for (mut diff_poly, src_to_rotate_poly) in izip!(
                            diff_buffer.as_mut_polynomial_list().iter_mut(),
                            src_to_rotate.as_polynomial_list().iter(),
                        ) {
                            // Rotate the lut that ends up in our slot and add to the
                            // destination
                            // This is computing Rot(ACCj)
                            polynomial_wrapping_monic_monomial_mul(
                                &mut diff_poly,
                                &src_to_rotate_poly,
                                small_monomial_degree,
                            );
                        }

                        // This is computing Rot(ACCj) - ACCj
                        glwe_ciphertext_sub_assign(&mut diff_buffer, src_unrotated);

                        dst_rotated
                    };

                    // ACCj ← BSKi x (Rot(ACCj) - ACCj) + ACCj
                    add_external_product_assign(
                        rotated_buffer.as_mut_view(),
                        ggsw,
                        diff_buffer.as_view(),
                        fft,
                        stack.rb_mut(),
                    );

                    let _ = barrier.wait();
                }
            };

            let threads: Vec<_> = thread_stacks
                .iter_mut()
                .enumerate()
                .map(|(id, stack)| s.spawn(move || thread_processing(id, stack)))
                .collect();

            threads.into_iter().for_each(|t| t.join().unwrap());
        });

        let lwe_dimension = self.input_lwe_dimension.0;
        let buffer_to_use = if lwe_dimension % 2 == 0 {
            split_ct0
        } else {
            split_ct1
        };

        let mut lut_0 = buffer_to_use.into_iter().next().unwrap();

        if !ciphertext_modulus.is_native_modulus() {
            // When we convert back from the fourier domain, integer values will contain up to 53
            // MSBs with information. In our representation of power of 2 moduli < native modulus we
            // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
            // round while keeping the data in the MSBs
            let signed_decomposer = SignedDecomposer::new(
                DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                DecompositionLevelCount(1),
            );
            lut_0
                .as_mut()
                .iter_mut()
                .for_each(|x| *x = signed_decomposer.closest_representable(*x));
        }

        GlweCiphertext::from_container(
            lut_0.as_ref().to_vec(),
            lut_0.polynomial_size(),
            lut_0.ciphertext_modulus(),
        )
    }

    #[allow(clippy::needless_collect)]
    #[allow(clippy::too_many_arguments)]
    pub fn sorted_blind_rotate_assign_ly23_parallelized<Scalar: UnsignedTorus + CastInto<usize>>(
        self,
        mut lut: GlweCiphertextMutView<'_, Scalar>,
        lwe: &[Scalar],
        extension_factor: Ly23ExtensionFactor,
        shortcut_coeff_count: Ly23ShortcutCoeffCount,
        fft: FftView<'_>,
        mut stack: PodStack<'_>,
        thread_stacks: &mut [PodStack<'_>],
    ) -> GlweCiphertextOwned<Scalar> {
        assert_eq!(thread_stacks.len(), extension_factor.0);

        let (lwe_body, lwe_mask) = lwe.split_last().unwrap();

        let lut_poly_size = lut.polynomial_size();
        let ciphertext_modulus = lut.ciphertext_modulus();
        assert!(ciphertext_modulus.is_compatible_with_native_modulus());
        assert_eq!(
            self.polynomial_size().0 * extension_factor.0,
            lut_poly_size.0
        );
        let monomial_degree = MonomialDegree(pbs_modulus_switch(
            *lwe_body,
            // This one should be the extended polynomial size
            lut_poly_size,
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

        let ct0 = lut;

        let mut split_ct0 = Vec::with_capacity(extension_factor.0);

        let mut split_ct1 = Vec::with_capacity(extension_factor.0);

        let substack0 = {
            let mut current_stack = stack;
            for _ in 0..extension_factor.0 {
                let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                    self.glwe_size.0 * self.polynomial_size().0,
                    CACHELINE_ALIGN,
                );
                split_ct0.push(GlweCiphertext::from_container(
                    glwe_cont,
                    self.polynomial_size(),
                    ct0.ciphertext_modulus(),
                ));
                current_stack = substack;
            }
            current_stack
        };

        let _substack1 = {
            let mut current_stack = substack0;
            for _ in 0..extension_factor.0 {
                let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                    self.glwe_size.0 * self.polynomial_size().0,
                    CACHELINE_ALIGN,
                );
                split_ct1.push(GlweCiphertext::from_container(
                    glwe_cont,
                    self.polynomial_size(),
                    ct0.ciphertext_modulus(),
                ));
                current_stack = substack;
            }
            current_stack
        };

        // Split the LUT into small LUTs
        for (idx, coeff) in ct0.as_ref().iter().copied().enumerate() {
            let dst_lut = &mut split_ct0[idx % extension_factor.0];
            dst_lut.as_mut()[idx / extension_factor.0] = coeff;
        }

        // let split_ct0 = split_ct0
        //     .into_iter()
        //     .map(std::sync::RwLock::new)
        //     .collect::<Vec<_>>();
        // let split_ct1 = split_ct1
        //     .into_iter()
        //     .map(std::sync::RwLock::new)
        //     .collect::<Vec<_>>();

        let thread_split_ct0 = UnsafeSlice::new(&mut split_ct0);
        let thread_split_ct1 = UnsafeSlice::new(&mut split_ct1);

        use std::sync::Barrier;
        let extension_factor_log2 = extension_factor.0.ilog2();
        let extension_factor_rem_mask = extension_factor.0 - 1;
        let congruence_classes_count = extension_factor_log2 as usize + 1;
        let mut congruence_classes: Vec<_> = (0..congruence_classes_count)
            .map(|idx| (vec![], Barrier::new(extension_factor.0 / (1 << idx))))
            .collect();

        let mut shortcut_destinations = vec![vec![]; congruence_classes_count];

        'outer: for (mask_idx, &mask_element) in lwe_mask.iter().enumerate() {
            let mod_switched = pbs_modulus_switch(mask_element, lut_poly_size);

            if mod_switched % 2 == 1 {
                let modulus_switch_log = (lut_poly_size.0 * 2).ilog2() as usize;
                let rounding_bit =
                    (mask_element >> (Scalar::BITS - modulus_switch_log)) & Scalar::ONE;
                let altered_mod_switch = if rounding_bit == Scalar::ZERO {
                    mod_switched.wrapping_add(1) % (1 << modulus_switch_log)
                } else {
                    mod_switched.wrapping_sub(1) % (1 << modulus_switch_log)
                };
                // for mod_idx in 1..congruence_classes.len() - 1
                for (mod_idx, shortcut_dest) in shortcut_destinations
                    .iter_mut()
                    .enumerate()
                    .take(congruence_classes.len() - 1)
                    .skip(1)
                {
                    let mod_power = mod_idx + 1;
                    let modulus: usize = (Scalar::ONE << mod_power).cast_into();
                    let expected_remainder = modulus >> 1;

                    if altered_mod_switch % modulus == expected_remainder {
                        shortcut_dest.push((mask_idx, (mod_switched, altered_mod_switch)));
                        continue 'outer;
                    }
                }
                shortcut_destinations[congruence_classes_count - 1]
                    .push((mask_idx, (mod_switched, altered_mod_switch)));
                continue;
            }

            // println!();
            // println!("{mod_switched:064b}");

            for mod_idx in 1..congruence_classes.len() - 1 {
                let mod_power = mod_idx + 1;
                let modulus: usize = (Scalar::ONE << mod_power).cast_into();
                // println!("modulus={modulus}");
                let expected_remainder = modulus >> 1;
                // println!("expected_remainder={expected_remainder}");

                if mod_switched % modulus == expected_remainder {
                    // println!("In class {expected_remainder}");
                    congruence_classes[mod_idx].0.push((mask_idx, mod_switched));
                    continue 'outer;
                }
            }
            // println!("In other class");
            congruence_classes[congruence_classes_count - 1]
                .0
                .push((mask_idx, mod_switched));
        }

        let mut shortcut_remaining = shortcut_coeff_count.0;

        for (shortcut_class_idx, shortcut_class) in shortcut_destinations.iter().enumerate().rev() {
            for (mask_idx, (mod_switched, altered_mod_switch)) in shortcut_class.iter().copied() {
                if shortcut_remaining > 0 {
                    shortcut_remaining -= 1;
                    congruence_classes[shortcut_class_idx]
                        .0
                        .push((mask_idx, altered_mod_switch));
                } else {
                    congruence_classes[0].0.push((mask_idx, mod_switched));
                }
            }
        }

        let gathered_dim = congruence_classes.iter().map(|x| x.0.len()).sum::<usize>();
        assert_eq!(gathered_dim, lwe_mask.len());

        std::thread::scope(|s| {
            let thread_processing = |id: usize, stack: &mut PodStack<'_>| {
                let (mut diff_dyn_array, mut stack) = stack.rb_mut().make_aligned_raw::<Scalar>(
                    self.glwe_size().0 * self.polynomial_size().0,
                    CACHELINE_ALIGN,
                );

                let mut diff_buffer = GlweCiphertext::from_container(
                    &mut *diff_dyn_array,
                    self.polynomial_size(),
                    ct0.ciphertext_modulus(),
                );

                let ggsw_vec = self.as_view().into_ggsw_iter().collect::<Vec<_>>();

                // let mut skipped = 0;

                let mut overall_loop_idx = 0;

                for (congruence_class_idx, (mask_indices, barrier)) in
                    congruence_classes.iter().enumerate()
                {
                    let ct_dst_idx = id;
                    let should_process = (ct_dst_idx % (1 << congruence_class_idx)) == 0;
                    if !should_process {
                        return;
                    }
                    //todo!("get correct barrier to wait");
                    for (mask_idx, monomial_degree) in mask_indices.iter().copied() {
                        // println!("mask_element: {mask_element:064b}");
                        let ggsw = ggsw_vec[mask_idx];
                        let monomial_degree = MonomialDegree(monomial_degree);

                        //todo use id of thread
                        // Update the lut we look at simulating the rotation in the larger lut
                        let ct_src_idx = (ct_dst_idx.wrapping_sub(monomial_degree.0))
                            & extension_factor_rem_mask;
                        // Compute the end of the rotation
                        // N' = 2^nu * N
                        // new_lut_idx = (ai + old_lut_idx) % 2^nu
                        // (2^nu + (ai % 2N') - 1 - new_lut_idx)/2^nu a l'air de marcher pour x X^ai
                        // monomial degree = mod switch(ai) already % 2N'
                        let small_monomial_degree = MonomialDegree(
                            (extension_factor.0 + monomial_degree.0 - 1 - ct_dst_idx)
                                >> extension_factor_log2,
                        );
                        let rotated_buffer = {
                            let (src_to_rotate, dst_rotated, src_unrotated) =
                                if (overall_loop_idx % 2) == 0 {
                                    unsafe {
                                        (
                                            thread_split_ct0.read(ct_src_idx),
                                            &mut *thread_split_ct1.write(ct_dst_idx),
                                            thread_split_ct0.read(ct_dst_idx),
                                        )
                                    }
                                } else {
                                    unsafe {
                                        (
                                            thread_split_ct1.read(ct_src_idx),
                                            &mut *thread_split_ct0.write(ct_dst_idx),
                                            thread_split_ct1.read(ct_dst_idx),
                                        )
                                    }
                                };
                            // Prepare the destination for the ext prod by copying the unrotated
                            // accumulator there
                            dst_rotated.as_mut().copy_from_slice(src_unrotated.as_ref());
                            for (mut diff_poly, src_to_rotate_poly) in izip!(
                                diff_buffer.as_mut_polynomial_list().iter_mut(),
                                src_to_rotate.as_polynomial_list().iter(),
                            ) {
                                // Rotate the lut that ends up in our slot and add to the
                                // destination This is computing
                                // Rot(ACCj)
                                polynomial_wrapping_monic_monomial_mul(
                                    &mut diff_poly,
                                    &src_to_rotate_poly,
                                    small_monomial_degree,
                                );
                            }

                            // This is computing Rot(ACCj) - ACCj
                            glwe_ciphertext_sub_assign(&mut diff_buffer, src_unrotated);

                            dst_rotated
                        };

                        // ACCj ← BSKi x (Rot(ACCj) - ACCj) + ACCj
                        add_external_product_assign(
                            rotated_buffer.as_mut_view(),
                            ggsw,
                            diff_buffer.as_view(),
                            fft,
                            stack.rb_mut(),
                        );
                        let _ = barrier.wait();
                        overall_loop_idx += 1;
                    }
                }
            };

            let threads: Vec<_> = thread_stacks
                .iter_mut()
                .enumerate()
                .map(|(id, stack)| s.spawn(move || thread_processing(id, stack)))
                .collect();
            threads.into_iter().for_each(|t| t.join().unwrap());
        });

        let lwe_dimension = self.input_lwe_dimension.0;
        let buffer_to_use = if lwe_dimension % 2 == 0 {
            split_ct0
        } else {
            split_ct1
        };

        let mut lut_0 = buffer_to_use.into_iter().next().unwrap();

        if !ciphertext_modulus.is_native_modulus() {
            // When we convert back from the fourier domain, integer values will contain up to 53
            // MSBs with information. In our representation of power of 2 moduli < native modulus we
            // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
            // round while keeping the data in the MSBs
            let signed_decomposer = SignedDecomposer::new(
                DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                DecompositionLevelCount(1),
            );
            lut_0
                .as_mut()
                .iter_mut()
                .for_each(|x| *x = signed_decomposer.closest_representable(*x));
        }

        GlweCiphertext::from_container(
            lut_0.as_ref().to_vec(),
            lut_0.polynomial_size(),
            lut_0.ciphertext_modulus(),
        )
    }

    pub fn bootstrap<InputScalar, OutputScalar>(
        self,
        mut lwe_out: LweCiphertextMutView<'_, OutputScalar>,
        lwe_in: LweCiphertextView<'_, InputScalar>,
        accumulator: GlweCiphertextView<'_, OutputScalar>,
        fft: FftView<'_>,
        stack: PodStack<'_>,
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

    #[allow(clippy::too_many_arguments)]
    pub fn bootstrap_ly23_parallelized<Scalar>(
        self,
        mut lwe_out: LweCiphertextMutView<'_, Scalar>,
        lwe_in: LweCiphertextView<'_, Scalar>,
        accumulator: GlweCiphertextView<'_, Scalar>,
        extension_factor: Ly23ExtensionFactor,
        fft: FftView<'_>,
        stack: PodStack<'_>,
        thread_buffers: &mut [PodStack<'_>],
    ) where
        // CastInto required for PBS modulus switch which returns a usize
        Scalar: UnsignedTorus + CastInto<usize>,
    {
        // extension factor == 1 means classic bootstrap which is already optimized
        if extension_factor.0 == 1 {
            return self.bootstrap(lwe_out, lwe_in, accumulator, fft, stack);
        }

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
        // TODO use only the split accumulator
        let split_accumulator = self.blind_rotate_assign_ly23_parallelized(
            local_accumulator.as_mut_view(),
            lwe_in.as_ref(),
            extension_factor,
            fft,
            stack,
            thread_buffers,
        );

        extract_lwe_sample_from_glwe_ciphertext(
            &split_accumulator,
            &mut lwe_out,
            MonomialDegree(0),
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bootstrap_ly23_parallelized_sorted<Scalar>(
        self,
        mut lwe_out: LweCiphertextMutView<'_, Scalar>,
        lwe_in: LweCiphertextView<'_, Scalar>,
        accumulator: GlweCiphertextView<'_, Scalar>,
        extension_factor: Ly23ExtensionFactor,
        shortcut_coeff_count: Ly23ShortcutCoeffCount,
        fft: FftView<'_>,
        stack: PodStack<'_>,
        thread_buffers: &mut [PodStack<'_>],
    ) where
        // CastInto required for PBS modulus switch which returns a usize
        Scalar: UnsignedTorus + CastInto<usize>,
    {
        // extension factor == 1 means classic bootstrap which is already optimized
        if extension_factor.0 == 1 {
            return self.bootstrap(lwe_out, lwe_in, accumulator, fft, stack);
        }

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
        // TODO use only the split accumulator
        let split_accumulator = self.sorted_blind_rotate_assign_ly23_parallelized(
            local_accumulator.as_mut_view(),
            lwe_in.as_ref(),
            extension_factor,
            shortcut_coeff_count,
            fft,
            stack,
            thread_buffers,
        );

        extract_lwe_sample_from_glwe_ciphertext(
            &split_accumulator,
            &mut lwe_out,
            MonomialDegree(0),
        );
    }

    // The clippy "fix" actually makes the thread spawning fail because of map being lazy evaled
    #[allow(clippy::needless_collect)]
    pub fn blind_rotate_assign_bergerat24<Scalar: UnsignedTorus + CastInto<usize>>(
        self,
        mut lut: GlweCiphertextMutView<'_, Scalar>,
        lwe: &[Scalar],
        extension_factor: Ly23ExtensionFactor,
        shortcut_coeff_count: Ly23ShortcutCoeffCount,
        fft: FftView<'_>,
        mut stack: PodStack<'_>,
    ) -> GlweCiphertextOwned<Scalar> {
        let (lwe_body, lwe_mask) = lwe.split_last().unwrap();

        let lut_poly_size = lut.polynomial_size();
        let ciphertext_modulus = lut.ciphertext_modulus();
        assert!(ciphertext_modulus.is_compatible_with_native_modulus());
        assert_eq!(
            self.polynomial_size().0 * extension_factor.0,
            lut_poly_size.0
        );
        let monomial_degree = MonomialDegree(pbs_modulus_switch(
            *lwe_body,
            // This one should be the extended polynomial size
            lut_poly_size,
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

        let ct0 = lut;

        let mut split_ct0 = Vec::with_capacity(extension_factor.0);

        let mut split_ct1 = Vec::with_capacity(extension_factor.0);

        let substack0 = {
            let mut current_stack = stack;
            for _ in 0..extension_factor.0 {
                let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                    self.glwe_size.0 * self.polynomial_size().0,
                    CACHELINE_ALIGN,
                );
                split_ct0.push(GlweCiphertext::from_container(
                    glwe_cont,
                    self.polynomial_size(),
                    ct0.ciphertext_modulus(),
                ));
                current_stack = substack;
            }
            current_stack
        };

        let substack1 = {
            let mut current_stack = substack0;
            for _ in 0..extension_factor.0 {
                let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                    self.glwe_size.0 * self.polynomial_size().0,
                    CACHELINE_ALIGN,
                );
                split_ct1.push(GlweCiphertext::from_container(
                    glwe_cont,
                    self.polynomial_size(),
                    ct0.ciphertext_modulus(),
                ));
                current_stack = substack;
            }
            current_stack
        };

        // Split the LUT into small LUTs
        for (idx, coeff) in ct0.as_ref().iter().copied().enumerate() {
            let dst_lut = &mut split_ct0[idx % extension_factor.0];
            dst_lut.as_mut()[idx / extension_factor.0] = coeff;
        }

        let extension_factor_log2 = extension_factor.0.ilog2();
        let extension_factor_rem_mask = extension_factor.0 - 1;

        let (mut diff_dyn_array, mut substack2) = substack1.make_aligned_raw::<Scalar>(
            self.glwe_size().0 * self.polynomial_size().0,
            CACHELINE_ALIGN,
        );

        let mut diff_buffer = GlweCiphertext::from_container(
            &mut *diff_dyn_array,
            self.polynomial_size(),
            ct0.ciphertext_modulus(),
        );

        let congruence_classes_count = extension_factor_log2 as usize + 1;
        let mut congruence_classes = vec![Vec::new(); congruence_classes_count];

        let mut shortcut_destinations = vec![vec![]; congruence_classes_count];

        'outer: for (mask_idx, &mask_element) in lwe_mask.iter().enumerate() {
            let mod_switched = pbs_modulus_switch(mask_element, lut_poly_size);

            if mod_switched % 2 == 1 {
                let modulus_switch_log = (lut_poly_size.0 * 2).ilog2() as usize;
                let rounding_bit =
                    (mask_element >> (Scalar::BITS - modulus_switch_log)) & Scalar::ONE;
                let altered_mod_switch = if rounding_bit == Scalar::ZERO {
                    mod_switched.wrapping_add(1) % (1 << modulus_switch_log)
                } else {
                    mod_switched.wrapping_sub(1) % (1 << modulus_switch_log)
                };
                // for mod_idx in 1..congruence_classes.len() - 1 {
                for (mod_idx, shortcut_dest) in shortcut_destinations
                    .iter_mut()
                    .enumerate()
                    .take(congruence_classes.len() - 1)
                    .skip(1)
                {
                    let mod_power = mod_idx + 1;
                    let modulus: usize = (Scalar::ONE << mod_power).cast_into();
                    let expected_remainder = modulus >> 1;

                    if altered_mod_switch % modulus == expected_remainder {
                        shortcut_dest.push((mask_idx, (mod_switched, altered_mod_switch)));
                        continue 'outer;
                    }
                }
                shortcut_destinations[congruence_classes_count - 1]
                    .push((mask_idx, (mod_switched, altered_mod_switch)));
                continue;
            }

            // println!();
            // println!("{mod_switched:064b}");

            for mod_idx in 1..congruence_classes.len() - 1 {
                let mod_power = mod_idx + 1;
                let modulus: usize = (Scalar::ONE << mod_power).cast_into();
                // println!("modulus={modulus}");
                let expected_remainder = modulus >> 1;
                // println!("expected_remainder={expected_remainder}");

                if mod_switched % modulus == expected_remainder {
                    // println!("In class {expected_remainder}");
                    congruence_classes[mod_idx].push((mask_idx, mod_switched));
                    continue 'outer;
                }
            }
            // println!("In other class");
            congruence_classes[congruence_classes_count - 1].push((mask_idx, mod_switched));
        }

        let mut shortcut_remaining = shortcut_coeff_count.0;

        for (shortcut_class_idx, shortcut_class) in shortcut_destinations.iter().enumerate().rev() {
            for (mask_idx, (mod_switched, altered_mod_switch)) in shortcut_class.iter().copied() {
                if shortcut_remaining > 0 {
                    shortcut_remaining -= 1;
                    congruence_classes[shortcut_class_idx].push((mask_idx, altered_mod_switch));
                } else {
                    congruence_classes[0].push((mask_idx, mod_switched));
                }
            }
        }

        let gathered_dim = congruence_classes.iter().map(Vec::len).sum::<usize>();
        assert_eq!(gathered_dim, lwe_mask.len());

        let ggsw_vec = self.as_view().into_ggsw_iter().collect::<Vec<_>>();

        // let mut skipped = 0;

        let mut overall_loop_idx = 0;
        for (congruence_class_idx, mask_indices) in congruence_classes.iter().enumerate() {
            // println!("congruence_class_idx={congruence_class_idx}");
            // println!("mask_indices {}", mask_indices.len());
            for (mask_idx, monomial_degree) in mask_indices.iter().copied() {
                // println!("mask_element: {mask_element:064b}");
                let ggsw = ggsw_vec[mask_idx];

                let monomial_degree = MonomialDegree(monomial_degree);

                for ct_dst_idx in (0..extension_factor.0).step_by(1 << congruence_class_idx) {
                    // Update the lut we look at simulating the rotation in the larger lut
                    let ct_src_idx =
                        (ct_dst_idx.wrapping_sub(monomial_degree.0)) & extension_factor_rem_mask;

                    // Compute the end of the rotation
                    // N' = 2^nu * N
                    // new_lut_idx = (ai + old_lut_idx) % 2^nu
                    // (2^nu + (ai % 2N') - 1 - new_lut_idx)/2^nu a l'air de marcher pour x X^ai
                    // monomial degree = mod switch(ai) already % 2N'
                    let small_monomial_degree = MonomialDegree(
                        (extension_factor.0 + monomial_degree.0 - 1 - ct_dst_idx)
                            >> extension_factor_log2,
                    );

                    let rotated_buffer = {
                        let (src_to_rotate, dst_rotated, src_unrotated) =
                            if (overall_loop_idx % 2) == 0 {
                                (
                                    &split_ct0[ct_src_idx],
                                    &mut split_ct1[ct_dst_idx],
                                    &split_ct0[ct_dst_idx],
                                )
                            } else {
                                (
                                    &split_ct1[ct_src_idx],
                                    &mut split_ct0[ct_dst_idx],
                                    &split_ct1[ct_dst_idx],
                                )
                            };

                        // Prepare the destination for the ext prod by copying the unrotated
                        // accumulator there
                        dst_rotated.as_mut().copy_from_slice(src_unrotated.as_ref());

                        for (mut diff_poly, src_to_rotate_poly) in izip!(
                            diff_buffer.as_mut_polynomial_list().iter_mut(),
                            src_to_rotate.as_polynomial_list().iter(),
                        ) {
                            // Rotate the lut that ends up in our slot and add to the destination
                            // This is computing Rot(ACCj)
                            polynomial_wrapping_monic_monomial_mul(
                                &mut diff_poly,
                                &src_to_rotate_poly,
                                small_monomial_degree,
                            );
                        }

                        // This is computing Rot(ACCj) - ACCj
                        glwe_ciphertext_sub_assign(&mut diff_buffer, src_unrotated);

                        dst_rotated
                    };

                    // ACCj ← BSKi x (Rot(ACCj) - ACCj) + ACCj
                    add_external_product_assign(
                        rotated_buffer.as_mut_view(),
                        ggsw,
                        diff_buffer.as_view(),
                        fft,
                        substack2.rb_mut(),
                    );
                }

                overall_loop_idx += 1;
            }
        }

        // panic!("skipped={skipped}");

        let lwe_dimension = self.input_lwe_dimension.0;
        let buffer_to_use = if lwe_dimension % 2 == 0 {
            split_ct0
        } else {
            split_ct1
        };

        let mut lut_0 = buffer_to_use.into_iter().next().unwrap();

        if !ciphertext_modulus.is_native_modulus() {
            // When we convert back from the fourier domain, integer values will contain up to 53
            // MSBs with information. In our representation of power of 2 moduli < native modulus we
            // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
            // round while keeping the data in the MSBs
            let signed_decomposer = SignedDecomposer::new(
                DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                DecompositionLevelCount(1),
            );
            lut_0
                .as_mut()
                .iter_mut()
                .for_each(|x| *x = signed_decomposer.closest_representable(*x));
        }

        GlweCiphertext::from_container(
            lut_0.as_ref().to_vec(),
            lut_0.polynomial_size(),
            lut_0.ciphertext_modulus(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bootstrap_bergerat24<Scalar>(
        self,
        mut lwe_out: LweCiphertextMutView<'_, Scalar>,
        lwe_in: LweCiphertextView<'_, Scalar>,
        accumulator: GlweCiphertextView<'_, Scalar>,
        extension_factor: Ly23ExtensionFactor,
        shortcut_coeff_count: Ly23ShortcutCoeffCount,
        fft: FftView<'_>,
        stack: PodStack<'_>,
    ) where
        // CastInto required for PBS modulus switch which returns a usize
        Scalar: UnsignedTorus + CastInto<usize>,
    {
        // extension factor == 1 means classic bootstrap which is already optimized
        if extension_factor.0 == 1 {
            return self.bootstrap(lwe_out, lwe_in, accumulator, fft, stack);
        }

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
        // TODO use only the split accumulator
        let split_accumulator = self.blind_rotate_assign_bergerat24(
            local_accumulator.as_mut_view(),
            lwe_in.as_ref(),
            extension_factor,
            shortcut_coeff_count,
            fft,
            stack,
        );

        extract_lwe_sample_from_glwe_ciphertext(
            &split_accumulator,
            &mut lwe_out,
            MonomialDegree(0),
        );
    }

    pub fn blind_rotate_assign_ly23<Scalar: UnsignedTorus + CastInto<usize>>(
        self,
        mut lut: GlweCiphertextMutView<'_, Scalar>,
        lwe: &[Scalar],
        extension_factor: Ly23ExtensionFactor,
        fft: FftView<'_>,
        mut stack: PodStack<'_>,
    ) -> GlweCiphertextOwned<Scalar> {
        let (lwe_body, lwe_mask) = lwe.split_last().unwrap();

        let lut_poly_size = lut.polynomial_size();
        let ciphertext_modulus = lut.ciphertext_modulus();
        assert!(ciphertext_modulus.is_compatible_with_native_modulus());
        assert_eq!(
            self.polynomial_size().0 * extension_factor.0,
            lut_poly_size.0
        );
        let monomial_degree = MonomialDegree(pbs_modulus_switch(
            *lwe_body,
            // This one should be the extended polynomial size
            lut_poly_size,
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

        let ct0 = lut;

        let mut split_ct0 = Vec::with_capacity(extension_factor.0);

        let mut split_ct1 = Vec::with_capacity(extension_factor.0);

        let substack0 = {
            let mut current_stack = stack;
            for _ in 0..extension_factor.0 {
                let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                    self.glwe_size.0 * self.polynomial_size().0,
                    CACHELINE_ALIGN,
                );
                split_ct0.push(GlweCiphertext::from_container(
                    glwe_cont,
                    self.polynomial_size(),
                    ct0.ciphertext_modulus(),
                ));
                current_stack = substack;
            }
            current_stack
        };

        let substack1 = {
            let mut current_stack = substack0;
            for _ in 0..extension_factor.0 {
                let (glwe_cont, substack) = current_stack.make_aligned_raw::<Scalar>(
                    self.glwe_size.0 * self.polynomial_size().0,
                    CACHELINE_ALIGN,
                );
                split_ct1.push(GlweCiphertext::from_container(
                    glwe_cont,
                    self.polynomial_size(),
                    ct0.ciphertext_modulus(),
                ));
                current_stack = substack;
            }
            current_stack
        };

        // Split the LUT into small LUTs
        for (idx, coeff) in ct0.as_ref().iter().copied().enumerate() {
            let dst_lut = &mut split_ct0[idx % extension_factor.0];
            dst_lut.as_mut()[idx / extension_factor.0] = coeff;
        }

        let extension_factor_log2 = extension_factor.0.ilog2();
        let extension_factor_rem_mask = extension_factor.0 - 1;

        let (mut diff_dyn_array, mut substack2) = substack1.make_aligned_raw::<Scalar>(
            self.glwe_size().0 * self.polynomial_size().0,
            CACHELINE_ALIGN,
        );

        let mut diff_buffer = GlweCiphertext::from_container(
            &mut *diff_dyn_array,
            self.polynomial_size(),
            ct0.ciphertext_modulus(),
        );

        for (mask_idx, (mask_element, ggsw)) in lwe_mask
            .iter()
            .zip(self.as_view().into_ggsw_iter())
            .enumerate()
        {
            let monomial_degree = MonomialDegree(pbs_modulus_switch(*mask_element, lut_poly_size));
            for ct_dst_idx in 0..extension_factor.0 {
                // Update the lut we look at simulating the rotation in the larger lut
                let ct_src_idx =
                    (ct_dst_idx.wrapping_sub(monomial_degree.0)) & extension_factor_rem_mask;

                // Compute the end of the rotation
                // N' = 2^nu * N
                // new_lut_idx = (ai + old_lut_idx) % 2^nu
                // (2^nu + (ai % 2N') - 1 - new_lut_idx)/2^nu a l'air de marcher pour x X^ai
                // monomial degree = mod switch(ai) already % 2N'
                let small_monomial_degree = MonomialDegree(
                    (extension_factor.0 + monomial_degree.0 - 1 - ct_dst_idx)
                        >> extension_factor_log2,
                );

                let rotated_buffer = {
                    let (src_to_rotate, dst_rotated, src_unrotated) = if (mask_idx % 2) == 0 {
                        (
                            &split_ct0[ct_src_idx],
                            &mut split_ct1[ct_dst_idx],
                            &split_ct0[ct_dst_idx],
                        )
                    } else {
                        (
                            &split_ct1[ct_src_idx],
                            &mut split_ct0[ct_dst_idx],
                            &split_ct1[ct_dst_idx],
                        )
                    };

                    // Prepare the destination for the ext prod by copying the unrotated
                    // accumulator there
                    dst_rotated.as_mut().copy_from_slice(src_unrotated.as_ref());

                    for (mut diff_poly, src_to_rotate_poly) in izip!(
                        diff_buffer.as_mut_polynomial_list().iter_mut(),
                        src_to_rotate.as_polynomial_list().iter(),
                    ) {
                        // Rotate the lut that ends up in our slot and add to the destination
                        // This is computing Rot(ACCj)
                        polynomial_wrapping_monic_monomial_mul(
                            &mut diff_poly,
                            &src_to_rotate_poly,
                            small_monomial_degree,
                        );
                    }

                    // This is computing Rot(ACCj) - ACCj
                    glwe_ciphertext_sub_assign(&mut diff_buffer, src_unrotated);

                    dst_rotated
                };

                // ACCj ← BSKi x (Rot(ACCj) - ACCj) + ACCj
                add_external_product_assign(
                    rotated_buffer.as_mut_view(),
                    ggsw,
                    diff_buffer.as_view(),
                    fft,
                    substack2.rb_mut(),
                );
            }
        }

        // panic!("skipped={skipped}");

        let lwe_dimension = self.input_lwe_dimension.0;
        let buffer_to_use = if lwe_dimension % 2 == 0 {
            split_ct0
        } else {
            split_ct1
        };

        let mut lut_0 = buffer_to_use.into_iter().next().unwrap();

        if !ciphertext_modulus.is_native_modulus() {
            // When we convert back from the fourier domain, integer values will contain up to 53
            // MSBs with information. In our representation of power of 2 moduli < native modulus we
            // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
            // round while keeping the data in the MSBs
            let signed_decomposer = SignedDecomposer::new(
                DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                DecompositionLevelCount(1),
            );
            lut_0
                .as_mut()
                .iter_mut()
                .for_each(|x| *x = signed_decomposer.closest_representable(*x));
        }

        GlweCiphertext::from_container(
            lut_0.as_ref().to_vec(),
            lut_0.polynomial_size(),
            lut_0.ciphertext_modulus(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bootstrap_ly23<Scalar>(
        self,
        mut lwe_out: LweCiphertextMutView<'_, Scalar>,
        lwe_in: LweCiphertextView<'_, Scalar>,
        accumulator: GlweCiphertextView<'_, Scalar>,
        extension_factor: Ly23ExtensionFactor,
        fft: FftView<'_>,
        stack: PodStack<'_>,
    ) where
        // CastInto required for PBS modulus switch which returns a usize
        Scalar: UnsignedTorus + CastInto<usize>,
    {
        // extension factor == 1 means classic bootstrap which is already optimized
        if extension_factor.0 == 1 {
            return self.bootstrap(lwe_out, lwe_in, accumulator, fft, stack);
        }

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
        // TODO use only the split accumulator
        let split_accumulator = self.blind_rotate_assign_ly23(
            local_accumulator.as_mut_view(),
            lwe_in.as_ref(),
            extension_factor,
            fft,
            stack,
        );

        extract_lwe_sample_from_glwe_ciphertext(
            &split_accumulator,
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
