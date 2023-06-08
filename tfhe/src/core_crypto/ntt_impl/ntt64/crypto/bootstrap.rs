use super::super::math::ntt::{Ntt, NttView};
use super::ggsw::*;
use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LutCountLog, LweDimension,
    ModulusSwitchOffset, MonomialDegree, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, ContiguousEntityContainerMut, Split,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::common::{fast_pbs_modulus_switch, FourierBootstrapKey};
use crate::core_crypto::prelude::{CiphertextModulus, ContainerMut};
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
use dyn_stack::{PodStack, ReborrowMut, SizeOverflow, StackReq};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NttLweBootstrapKey<C: Container<Element = u64>> {
    data: C,
    polynomial_size: PolynomialSize,
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

pub type NttLweBootstrapKeyView<'a> = NttLweBootstrapKey<&'a [u64]>;
pub type NttLweBootstrapKeyMutView<'a> = NttLweBootstrapKey<&'a mut [u64]>;

impl<C: Container<Element = u64>> NttLweBootstrapKey<C> {
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
                * polynomial_size.0
                * decomposition_level_count.0
                * glwe_size.0
                * glwe_size.0
        );
        Self {
            data,
            polynomial_size,
            input_lwe_dimension,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
        }
    }

    /// Return an iterator over the GGSW ciphertexts composing the key.
    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = NttGgswCiphertext<C>>
    where
        C: Split,
    {
        self.data
            .split_into(self.input_lwe_dimension.0)
            .map(move |slice| {
                NttGgswCiphertext::from_container(
                    slice,
                    self.glwe_size,
                    self.polynomial_size,
                    self.decomposition_base_log,
                    self.decomposition_level_count,
                )
            })
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
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
        self.data
    }

    pub fn as_view(&self) -> NttLweBootstrapKeyView<'_> {
        NttLweBootstrapKeyView {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(&mut self) -> NttLweBootstrapKeyMutView<'_>
    where
        C: AsMut<[u64]>,
    {
        NttLweBootstrapKeyMutView {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }
}

pub type NttLweBootstrapKeyOwned = NttLweBootstrapKey<ABox<[u64]>>;

impl NttLweBootstrapKey<ABox<[u64]>> {
    pub fn new(
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        let boxed = avec![
            u64::default();
            polynomial_size.0
                * input_lwe_dimension.0
                * decomposition_level_count.0
                * glwe_size.0
                * glwe_size.0
        ]
        .into_boxed_slice();

        NttLweBootstrapKey::from_container(
            boxed,
            input_lwe_dimension,
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }
}

impl<'a> NttLweBootstrapKeyMutView<'a> {
    /// Fill a bootstrapping key with the Ntt transform of a bootstrapping key in the standard
    /// domain.
    pub fn fill_with_forward_ntt(mut self, coef_bsk: LweBootstrapKey<&'_ [u64]>, ntt: NttView<'_>) {
        for (ntt_ggsw, standard_ggsw) in izip!(self.as_mut_view().into_ggsw_iter(), coef_bsk.iter())
        {
            ntt_ggsw.fill_with_forward_ntt(standard_ggsw, ntt);
        }
    }
}

/// Return the required memory for [`NttLweBootstrapKeyView::blind_rotate_assign`].
pub fn blind_rotate_scratch(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ntt: NttView<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_new_aligned::<u64>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?
        .try_and(cmux_scratch(glwe_size, polynomial_size, ntt)?)
}

/// Return the required memory for [`NttLweBootstrapKeyView::bootstrap`].
pub fn bootstrap_scratch(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ntt: NttView<'_>,
) -> Result<StackReq, SizeOverflow> {
    blind_rotate_scratch(glwe_size, polynomial_size, ntt)?.try_and(
        StackReq::try_new_aligned::<u64>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?,
    )
}

impl<'a> NttLweBootstrapKeyView<'a> {
    // CastInto required for PBS modulus switch which returns a usize
    pub fn blind_rotate_assign(
        self,
        mut lut: GlweCiphertextMutView<'_, u64>,
        lwe: &[u64],
        ntt: NttView<'_>,
        mut stack: PodStack<'_>,
    ) {
        let (lwe_body, lwe_mask) = lwe.split_last().unwrap();
        let modulus = ntt.custom_modulus();

        let lut_poly_size = lut.polynomial_size();
        let ciphertext_modulus = lut.ciphertext_modulus();
        let monomial_degree = fast_pbs_modulus_switch(
            *lwe_body,
            lut_poly_size,
            ModulusSwitchOffset(0),
            LutCountLog(0),
        );

        lut.as_mut_polynomial_list()
            .iter_mut()
            .for_each(|mut poly| {
                polynomial_wrapping_monic_monomial_div_assign_custom_modulus(
                    &mut poly,
                    MonomialDegree(monomial_degree),
                    modulus,
                )
            });

        // We initialize the ct_0 used for the successive cmuxes
        let mut ct0 = lut;

        for (lwe_mask_element, bootstrap_key_ggsw) in izip!(lwe_mask.iter(), self.into_ggsw_iter())
        {
            if *lwe_mask_element != 0u64 {
                let stack = stack.rb_mut();
                // We copy ct_0 to ct_1
                let (mut ct1, stack) =
                    stack.collect_aligned(CACHELINE_ALIGN, ct0.as_ref().iter().copied());
                let mut ct1 = GlweCiphertextMutView::from_container(
                    &mut *ct1,
                    lut_poly_size,
                    ciphertext_modulus,
                );

                // We rotate ct_1 by performing ct_1 <- ct_1 * X^{a_hat}
                for mut poly in ct1.as_mut_polynomial_list().iter_mut() {
                    polynomial_wrapping_monic_monomial_mul_assign_custom_modulus(
                        &mut poly,
                        MonomialDegree(fast_pbs_modulus_switch(
                            *lwe_mask_element,
                            lut_poly_size,
                            ModulusSwitchOffset(0),
                            LutCountLog(0),
                        )),
                        modulus,
                    );
                }

                // ct1 is re-created each loop it can be moved, ct0 is already a view, but
                // as_mut_view is required to keep borrow rules consistent
                cmux(ct0.as_mut_view(), ct1, bootstrap_key_ggsw, ntt, stack);
            }
        }
    }

    pub fn bootstrap(
        self,
        mut lwe_out: LweCiphertextMutView<'_, u64>,
        lwe_in: LweCiphertextView<'_, u64>,
        accumulator: GlweCiphertextView<'_, u64>,
        ntt: NttView<'_>,
        stack: PodStack<'_>,
    ) {
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
        self.blind_rotate_assign(local_accumulator.as_mut_view(), lwe_in.as_ref(), ntt, stack);

        extract_lwe_sample_from_glwe_ciphertext(
            &local_accumulator,
            &mut lwe_out,
            MonomialDegree(0),
        );
    }
}

impl FourierBootstrapKey<u64> for NttLweBootstrapKeyOwned {
    type Fft = Ntt;

    fn new_fft(polynomial_size: PolynomialSize) -> Self::Fft {
        Ntt::new(
            CiphertextModulus::try_new((1u128 << 64) - (1u128 << 32) + 1).unwrap(),
            polynomial_size,
        )
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

    fn fill_with_forward_fourier_scratch(_fft: &Self::Fft) -> Result<StackReq, SizeOverflow> {
        Ok(StackReq::empty())
    }

    fn fill_with_forward_fourier<ContBsk>(
        &mut self,
        coef_bsk: &LweBootstrapKey<ContBsk>,
        fft: &Self::Fft,
        _stack: PodStack<'_>,
    ) where
        ContBsk: Container<Element = u64>,
    {
        self.as_mut_view()
            .fill_with_forward_ntt(coef_bsk.as_view(), fft.as_view());
    }

    fn bootstrap_scratch(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        fft: &Self::Fft,
    ) -> Result<StackReq, SizeOverflow> {
        bootstrap_scratch(glwe_size, polynomial_size, fft.as_view())
    }

    fn bootstrap<ContLweOut, ContLweIn, ContAcc>(
        &self,
        lwe_out: &mut LweCiphertext<ContLweOut>,
        lwe_in: &LweCiphertext<ContLweIn>,
        accumulator: &GlweCiphertext<ContAcc>,
        fft: &Self::Fft,
        stack: PodStack<'_>,
    ) where
        ContLweOut: ContainerMut<Element = u64>,
        ContLweIn: Container<Element = u64>,
        ContAcc: Container<Element = u64>,
    {
        self.as_view().bootstrap(
            lwe_out.as_mut_view(),
            lwe_in.as_view(),
            accumulator.as_view(),
            fft.as_view(),
            stack,
        )
    }
}
