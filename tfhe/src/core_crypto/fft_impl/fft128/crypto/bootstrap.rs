use super::super::math::fft::{Fft128, Fft128View};
use super::ggsw::{cmux, cmux_scratch};
use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::backward_compatibility::fft_impl::Fourier128LweBootstrapKeyVersions;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, MonomialDegree,
    PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, ContiguousEntityContainerMut, Split,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::common::{pbs_modulus_switch, FourierBootstrapKey};
use crate::core_crypto::prelude::ContainerMut;
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
use core::any::TypeId;
use core::mem::transmute;
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_versionable::Versionize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(Fourier128LweBootstrapKeyVersions)]
pub struct Fourier128LweBootstrapKey<C: Container<Element = f64>> {
    data_re0: C,
    data_re1: C,
    data_im0: C,
    data_im1: C,
    polynomial_size: PolynomialSize,
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

impl<C: Container<Element = f64>> Fourier128LweBootstrapKey<C> {
    pub fn from_container(
        data_re0: C,
        data_re1: C,
        data_im0: C,
        data_im1: C,
        polynomial_size: PolynomialSize,
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(polynomial_size.0 % 2, 0);
        let container_len = input_lwe_dimension.0
            * polynomial_size.to_fourier_polynomial_size().0
            * decomposition_level_count.0
            * glwe_size.0
            * glwe_size.0;
        assert_eq!(data_re0.container_len(), container_len);
        assert_eq!(data_re1.container_len(), container_len);
        assert_eq!(data_im0.container_len(), container_len);
        assert_eq!(data_im1.container_len(), container_len);
        Self {
            data_re0,
            data_re1,
            data_im0,
            data_im1,
            polynomial_size,
            input_lwe_dimension,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
        }
    }

    /// Return an iterator over the GGSW ciphertexts composing the key.
    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = Fourier128GgswCiphertext<C>>
    where
        C: Split,
    {
        izip!(
            self.data_re0.split_into(self.input_lwe_dimension.0),
            self.data_re1.split_into(self.input_lwe_dimension.0),
            self.data_im0.split_into(self.input_lwe_dimension.0),
            self.data_im1.split_into(self.input_lwe_dimension.0),
        )
        .map(move |(data_re0, data_re1, data_im0, data_im1)| {
            Fourier128GgswCiphertext::from_container(
                data_re0,
                data_re1,
                data_im0,
                data_im1,
                self.polynomial_size,
                self.glwe_size,
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

    pub fn data(self) -> (C, C, C, C) {
        (self.data_re0, self.data_re1, self.data_im0, self.data_im1)
    }

    pub fn as_view(&self) -> Fourier128LweBootstrapKey<&[C::Element]> {
        Fourier128LweBootstrapKey {
            data_re0: self.data_re0.as_ref(),
            data_re1: self.data_re1.as_ref(),
            data_im0: self.data_im0.as_ref(),
            data_im1: self.data_im1.as_ref(),
            polynomial_size: self.polynomial_size,
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(&mut self) -> Fourier128LweBootstrapKey<&mut [C::Element]>
    where
        C: AsMut<[C::Element]>,
    {
        Fourier128LweBootstrapKey {
            data_re0: self.data_re0.as_mut(),
            data_re1: self.data_re1.as_mut(),
            data_im0: self.data_im0.as_mut(),
            data_im1: self.data_im1.as_mut(),
            polynomial_size: self.polynomial_size,
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }
}

pub type Fourier128LweBootstrapKeyOwned = Fourier128LweBootstrapKey<ABox<[f64]>>;

impl Fourier128LweBootstrapKey<ABox<[f64]>> {
    pub fn new(
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        let container_len = polynomial_size.to_fourier_polynomial_size().0
            * input_lwe_dimension.0
            * decomposition_level_count.0
            * glwe_size.0
            * glwe_size.0;

        let boxed_re0 = avec![0.0f64; container_len].into_boxed_slice();
        let boxed_re1 = avec![0.0f64; container_len].into_boxed_slice();
        let boxed_im0 = avec![0.0f64; container_len].into_boxed_slice();
        let boxed_im1 = avec![0.0f64; container_len].into_boxed_slice();

        Fourier128LweBootstrapKey::from_container(
            boxed_re0,
            boxed_re1,
            boxed_im0,
            boxed_im1,
            polynomial_size,
            input_lwe_dimension,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }
}

impl<Cont> Fourier128LweBootstrapKey<Cont>
where
    Cont: ContainerMut<Element = f64>,
{
    /// Fill a bootstrapping key with the Fourier transform of a bootstrapping key in the standard
    /// domain.
    pub fn fill_with_forward_fourier<Scalar, ContBsk>(
        &mut self,
        coef_bsk: &LweBootstrapKey<ContBsk>,
        fft: Fft128View<'_>,
    ) where
        Scalar: UnsignedTorus,
        ContBsk: Container<Element = Scalar>,
    {
        fn implementation<Scalar: UnsignedTorus>(
            this: Fourier128LweBootstrapKey<&mut [f64]>,
            coef_bsk: LweBootstrapKey<&[Scalar]>,
            fft: Fft128View<'_>,
        ) {
            for (mut fourier_ggsw, standard_ggsw) in izip!(this.into_ggsw_iter(), coef_bsk.iter()) {
                fourier_ggsw.fill_with_forward_fourier(&standard_ggsw, fft);
            }
        }
        implementation(self.as_mut_view(), coef_bsk.as_view(), fft);
    }
}

/// Return the required memory for [`Fourier128LweBootstrapKey::blind_rotate_assign`].
pub fn blind_rotate_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?
        .try_and(cmux_scratch::<Scalar>(glwe_size, polynomial_size, fft)?)
}

/// Return the required memory for [`Fourier128LweBootstrapKey::bootstrap`].
pub fn bootstrap_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> Result<StackReq, SizeOverflow> {
    blind_rotate_scratch::<Scalar>(glwe_size, polynomial_size, fft)?.try_and(
        StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?,
    )
}

impl<Cont> Fourier128LweBootstrapKey<Cont>
where
    Cont: Container<Element = f64>,
{
    // CastInto required for PBS modulus switch which returns a usize
    pub fn blind_rotate_assign<Scalar, ContLut, ContLwe>(
        &self,
        lut: &mut GlweCiphertext<ContLut>,
        lwe: &LweCiphertext<ContLwe>,
        fft: Fft128View<'_>,
        stack: &mut PodStack,
    ) where
        Scalar: UnsignedTorus + CastInto<usize>,
        ContLut: ContainerMut<Element = Scalar>,
        ContLwe: Container<Element = Scalar>,
    {
        fn implementation<Scalar: UnsignedTorus + CastInto<usize>>(
            this: Fourier128LweBootstrapKey<&[f64]>,
            mut lut: GlweCiphertext<&mut [Scalar]>,
            lwe: LweCiphertext<&[Scalar]>,
            fft: Fft128View<'_>,
            stack: &mut PodStack,
        ) {
            let lwe = lwe.as_ref();
            let (lwe_body, lwe_mask) = lwe.split_last().unwrap();

            let lut_poly_size = lut.polynomial_size();
            let ciphertext_modulus = lut.ciphertext_modulus();
            assert!(ciphertext_modulus.is_compatible_with_native_modulus());
            let monomial_degree = pbs_modulus_switch(*lwe_body, lut_poly_size);

            lut.as_mut_polynomial_list()
                .iter_mut()
                .for_each(|mut poly| {
                    polynomial_wrapping_monic_monomial_div_assign(
                        &mut poly,
                        MonomialDegree(monomial_degree),
                    );
                });

            // We initialize the ct_0 used for the successive cmuxes
            let mut ct0 = lut;

            for (lwe_mask_element, bootstrap_key_ggsw) in
                izip!(lwe_mask.iter(), this.into_ggsw_iter())
            {
                if *lwe_mask_element != Scalar::ZERO {
                    let stack = &mut *stack;
                    // We copy ct_0 to ct_1
                    let (ct1, stack) =
                        stack.collect_aligned(CACHELINE_ALIGN, ct0.as_ref().iter().copied());
                    let mut ct1 = GlweCiphertextMutView::from_container(
                        ct1,
                        ct0.polynomial_size(),
                        ct0.ciphertext_modulus(),
                    );

                    // We rotate ct_1 by performing ct_1 <- ct_1 * X^{a_hat}
                    for mut poly in ct1.as_mut_polynomial_list().iter_mut() {
                        polynomial_wrapping_monic_monomial_mul_assign(
                            &mut poly,
                            MonomialDegree(pbs_modulus_switch(*lwe_mask_element, lut_poly_size)),
                        );
                    }

                    // ct1 is re-created each loop it can be moved, ct0 is already a view, but
                    // as_mut_view is required to keep borrow rules consistent
                    cmux(&mut ct0, &mut ct1, &bootstrap_key_ggsw, fft, stack);
                }
            }

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
                ct0.as_mut()
                    .iter_mut()
                    .for_each(|x| *x = signed_decomposer.closest_representable(*x));
            }
        }
        implementation(self.as_view(), lut.as_mut_view(), lwe.as_view(), fft, stack);
    }

    pub fn bootstrap<Scalar, ContLweOut, ContLweIn, ContAcc>(
        &self,
        lwe_out: &mut LweCiphertext<ContLweOut>,
        lwe_in: &LweCiphertext<ContLweIn>,
        accumulator: &GlweCiphertext<ContAcc>,
        fft: Fft128View<'_>,
        stack: &mut PodStack,
    ) where
        // CastInto required for PBS modulus switch which returns a usize
        Scalar: UnsignedTorus + CastInto<usize>,
        ContLweOut: ContainerMut<Element = Scalar>,
        ContLweIn: Container<Element = Scalar>,
        ContAcc: Container<Element = Scalar>,
    {
        fn implementation<Scalar: UnsignedTorus + CastInto<usize>>(
            this: Fourier128LweBootstrapKey<&[f64]>,
            mut lwe_out: LweCiphertext<&mut [Scalar]>,
            lwe_in: LweCiphertext<&[Scalar]>,
            accumulator: GlweCiphertext<&[Scalar]>,
            fft: Fft128View<'_>,
            stack: &mut PodStack,
        ) {
            // We type check dynamically with TypeId
            #[allow(clippy::transmute_undefined_repr)]
            if TypeId::of::<Scalar>() == TypeId::of::<u128>() {
                let mut lwe_out: LweCiphertext<&mut [u128]> = unsafe { transmute(lwe_out) };
                let lwe_in: LweCiphertext<&[u128]> = unsafe { transmute(lwe_in) };
                let accumulator: GlweCiphertext<&[u128]> = unsafe { transmute(accumulator) };

                return this.bootstrap_u128(&mut lwe_out, &lwe_in, &accumulator, fft, stack);
            }

            let (local_accumulator_data, stack) =
                stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
            let mut local_accumulator = GlweCiphertextMutView::from_container(
                local_accumulator_data,
                accumulator.polynomial_size(),
                accumulator.ciphertext_modulus(),
            );
            this.blind_rotate_assign(&mut local_accumulator.as_mut_view(), &lwe_in, fft, stack);
            extract_lwe_sample_from_glwe_ciphertext(
                &local_accumulator,
                &mut lwe_out,
                MonomialDegree(0),
            );
        }

        implementation(
            self.as_view(),
            lwe_out.as_mut_view(),
            lwe_in.as_view(),
            accumulator.as_view(),
            fft,
            stack,
        );
    }
}

impl<Scalar> FourierBootstrapKey<Scalar> for Fourier128LweBootstrapKeyOwned
where
    Scalar: UnsignedTorus + CastInto<usize>,
{
    type Fft = Fft128;

    fn new_fft(polynomial_size: PolynomialSize) -> Self::Fft {
        Fft128::new(polynomial_size)
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

    fn fill_with_forward_fourier<ContBsk>(
        &mut self,
        coef_bsk: &LweBootstrapKey<ContBsk>,
        fft: &Self::Fft,
        stack: &mut PodStack,
    ) where
        ContBsk: Container<Element = Scalar>,
    {
        let _ = stack;
        let fft = fft.as_view();
        self.fill_with_forward_fourier(coef_bsk, fft);
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
        self.bootstrap(lwe_out, lwe_in, accumulator, fft.as_view(), stack);
    }

    fn fill_with_forward_fourier_scratch(fft: &Self::Fft) -> Result<StackReq, SizeOverflow> {
        let _ = fft;
        Ok(StackReq::empty())
    }
}
