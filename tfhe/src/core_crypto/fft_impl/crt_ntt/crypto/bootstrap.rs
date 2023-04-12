use super::ggsw::{cmux, cmux_scratch, CrtNttGgswCiphertext};
use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LutCountLog, LweDimension,
    ModulusSwitchOffset, MonomialDegree, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, ContiguousEntityContainerMut, Split,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::common::{
    as_mut_array, as_ref_array, iter_array, pbs_modulus_switch, FourierBootstrapKey,
};
use crate::core_crypto::fft_impl::crt_ntt::math::ntt::CrtNtt;
use crate::core_crypto::prelude::{CiphertextModulus, ContainerMut, UnsignedInteger};
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
use dyn_stack::{PodStack, ReborrowMut, SizeOverflow, StackReq};

pub struct CrtNttLweBootstrapKey<
    CrtScalar,
    const N_COMPONENTS: usize,
    C: Container<Element = CrtScalar>,
> {
    data: [C; N_COMPONENTS],
    polynomial_size: PolynomialSize,
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

impl<CrtScalar: UnsignedInteger, const N_COMPONENTS: usize, C: Container<Element = CrtScalar>>
    CrtNttLweBootstrapKey<CrtScalar, N_COMPONENTS, C>
{
    pub fn from_container(
        data: [C; N_COMPONENTS],
        polynomial_size: PolynomialSize,
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        let container_len = input_lwe_dimension.0
            * polynomial_size.0
            * decomposition_level_count.0
            * glwe_size.0
            * glwe_size.0;
        data.iter()
            .for_each(|data| assert_eq!(data.container_len(), container_len));
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
    pub fn into_ggsw_iter(
        self,
    ) -> impl DoubleEndedIterator<Item = CrtNttGgswCiphertext<CrtScalar, N_COMPONENTS, C>>
    where
        C: Split,
    {
        iter_array(
            self.data
                .map(|data| data.split_into(self.input_lwe_dimension.0)),
        )
        .map(move |data| {
            CrtNttGgswCiphertext::from_container(
                data,
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

    pub fn data(self) -> [C; N_COMPONENTS] {
        self.data
    }

    pub fn as_view(&self) -> CrtNttLweBootstrapKey<CrtScalar, N_COMPONENTS, &[C::Element]> {
        CrtNttLweBootstrapKey {
            data: as_ref_array(&self.data).map(|data| data.as_ref()),
            polynomial_size: self.polynomial_size,
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(
        &mut self,
    ) -> CrtNttLweBootstrapKey<CrtScalar, N_COMPONENTS, &mut [C::Element]>
    where
        C: AsMut<[C::Element]>,
    {
        CrtNttLweBootstrapKey {
            data: as_mut_array(&mut self.data).map(|data| data.as_mut()),
            polynomial_size: self.polynomial_size,
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }
}

impl<CrtScalar: UnsignedInteger, const N_COMPONENTS: usize>
    CrtNttLweBootstrapKey<CrtScalar, N_COMPONENTS, ABox<[CrtScalar]>>
{
    pub fn new(
        input_lwe_dimension: LweDimension,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> CrtNttLweBootstrapKey<CrtScalar, N_COMPONENTS, ABox<[CrtScalar]>> {
        let container_len = polynomial_size.0
            * input_lwe_dimension.0
            * decomposition_level_count.0
            * glwe_size.0
            * glwe_size.0;

        let boxed =
            [(); N_COMPONENTS].map(|()| avec![CrtScalar::ZERO; container_len].into_boxed_slice());

        CrtNttLweBootstrapKey::from_container(
            boxed,
            polynomial_size,
            input_lwe_dimension,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }
}

impl<CrtScalar: UnsignedInteger, const N_COMPONENTS: usize, Cont>
    CrtNttLweBootstrapKey<CrtScalar, N_COMPONENTS, Cont>
where
    Cont: ContainerMut<Element = CrtScalar>,
{
    /// Fill a bootstrapping key with the NTT of a bootstrapping key in the standard
    /// domain.
    pub fn fill_with_forward_ntt<Scalar, ContBsk>(
        &mut self,
        coef_bsk: &LweBootstrapKey<ContBsk>,
        ntt_plan: Scalar::PlanView<'_>,
    ) where
        Scalar: CrtNtt<CrtScalar, N_COMPONENTS>,
        ContBsk: Container<Element = Scalar>,
    {
        fn implementation<
            CrtScalar: UnsignedInteger,
            const N_COMPONENTS: usize,
            Scalar: CrtNtt<CrtScalar, N_COMPONENTS>,
        >(
            this: CrtNttLweBootstrapKey<CrtScalar, N_COMPONENTS, &mut [CrtScalar]>,
            coef_bsk: LweBootstrapKey<&[Scalar]>,
            ntt_plan: Scalar::PlanView<'_>,
        ) {
            for (mut ntt_ggsw, standard_ggsw) in izip!(this.into_ggsw_iter(), coef_bsk.iter()) {
                ntt_ggsw.fill_with_forward_ntt(&standard_ggsw, ntt_plan);
            }
        }
        implementation(self.as_mut_view(), coef_bsk.as_view(), ntt_plan)
    }
}

/// Return the required memory for [`CrtNttLweBootstrapKey::blind_rotate_assign`].
pub fn blind_rotate_scratch<CrtScalar, const N_COMPONENTS: usize, Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> Result<StackReq, SizeOverflow>
where
    CrtScalar: UnsignedInteger,
    Scalar: CrtNtt<CrtScalar, N_COMPONENTS>,
{
    StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?.try_and(
        cmux_scratch::<CrtScalar, N_COMPONENTS, Scalar>(glwe_size, polynomial_size)?,
    )
}

/// Return the required memory for [`CrtNttLweBootstrapKey::bootstrap`].
pub fn bootstrap_scratch<CrtScalar, const N_COMPONENTS: usize, Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> Result<StackReq, SizeOverflow>
where
    CrtScalar: UnsignedInteger,
    Scalar: CrtNtt<CrtScalar, N_COMPONENTS>,
{
    blind_rotate_scratch::<CrtScalar, N_COMPONENTS, Scalar>(glwe_size, polynomial_size)?.try_and(
        StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?,
    )
}

impl<CrtScalar, const N_COMPONENTS: usize, Cont>
    CrtNttLweBootstrapKey<CrtScalar, N_COMPONENTS, Cont>
where
    CrtScalar: UnsignedInteger,
    Cont: Container<Element = CrtScalar>,
{
    // CastInto required for PBS modulus switch which returns a usize
    pub fn blind_rotate_assign<Scalar, ContLut, ContLwe>(
        &self,
        lut: &mut GlweCiphertext<ContLut>,
        lwe: &LweCiphertext<ContLwe>,
        ntt_plan: Scalar::PlanView<'_>,
        stack: PodStack<'_>,
    ) where
        Scalar: CrtNtt<CrtScalar, N_COMPONENTS> + CastInto<usize>,
        ContLut: ContainerMut<Element = Scalar>,
        ContLwe: Container<Element = Scalar>,
    {
        fn implementation<
            CrtScalar: UnsignedInteger,
            const N_COMPONENTS: usize,
            Scalar: CrtNtt<CrtScalar, N_COMPONENTS> + CastInto<usize>,
        >(
            this: CrtNttLweBootstrapKey<CrtScalar, N_COMPONENTS, &[CrtScalar]>,
            mut lut: GlweCiphertext<&mut [Scalar]>,
            lwe: LweCiphertext<&[Scalar]>,
            ntt_plan: Scalar::PlanView<'_>,
            mut stack: PodStack<'_>,
        ) {
            let lwe = lwe.as_ref();
            let (lwe_body, lwe_mask) = lwe.split_last().unwrap();

            let lut_poly_size = lut.polynomial_size();
            let monomial_degree = pbs_modulus_switch(
                *lwe_body,
                lut_poly_size,
                ModulusSwitchOffset(0),
                LutCountLog(0),
            );

            lut.as_mut_polynomial_list()
                .iter_mut()
                .for_each(|mut poly| {
                    polynomial_wrapping_monic_monomial_div_assign(
                        &mut poly,
                        MonomialDegree(monomial_degree),
                    )
                });

            // We initialize the ct_0 used for the successive cmuxes
            let mut ct0 = lut;

            for (lwe_mask_element, bootstrap_key_ggsw) in
                izip!(lwe_mask.iter(), this.into_ggsw_iter())
            {
                if *lwe_mask_element != Scalar::ZERO {
                    let stack = stack.rb_mut();
                    // We copy ct_0 to ct_1
                    let (mut ct1, stack) =
                        stack.collect_aligned(CACHELINE_ALIGN, ct0.as_ref().iter().copied());
                    let mut ct1 = GlweCiphertextMutView::from_container(
                        &mut *ct1,
                        ct0.polynomial_size(),
                        CiphertextModulus::new_native(),
                    );

                    // We rotate ct_1 by performing ct_1 <- ct_1 * X^{a_hat}
                    for mut poly in ct1.as_mut_polynomial_list().iter_mut() {
                        polynomial_wrapping_monic_monomial_mul_assign(
                            &mut poly,
                            MonomialDegree(pbs_modulus_switch(
                                *lwe_mask_element,
                                lut_poly_size,
                                ModulusSwitchOffset(0),
                                LutCountLog(0),
                            )),
                        );
                    }

                    // ct1 is re-created each loop it can be moved, ct0 is already a view, but
                    // as_mut_view is required to keep borrow rules consistent
                    cmux(&mut ct0, &mut ct1, &bootstrap_key_ggsw, ntt_plan, stack);
                }
            }
        }
        implementation(
            self.as_view(),
            lut.as_mut_view(),
            lwe.as_view(),
            ntt_plan,
            stack,
        )
    }

    pub fn bootstrap<Scalar, ContLweOut, ContLweIn, ContAcc>(
        &self,
        lwe_out: &mut LweCiphertext<ContLweOut>,
        lwe_in: &LweCiphertext<ContLweIn>,
        accumulator: &GlweCiphertext<ContAcc>,
        ntt_plan: Scalar::PlanView<'_>,
        stack: PodStack<'_>,
    ) where
        // CastInto required for PBS modulus switch which returns a usize
        Scalar: CrtNtt<CrtScalar, N_COMPONENTS> + CastInto<usize>,
        ContLweOut: ContainerMut<Element = Scalar>,
        ContLweIn: Container<Element = Scalar>,
        ContAcc: Container<Element = Scalar>,
    {
        fn implementation<
            CrtScalar: UnsignedInteger,
            const N_COMPONENTS: usize,
            Scalar: CrtNtt<CrtScalar, N_COMPONENTS> + CastInto<usize>,
        >(
            this: CrtNttLweBootstrapKey<CrtScalar, N_COMPONENTS, &[CrtScalar]>,
            mut lwe_out: LweCiphertext<&mut [Scalar]>,
            lwe_in: LweCiphertext<&[Scalar]>,
            accumulator: GlweCiphertext<&[Scalar]>,
            ntt_plan: Scalar::PlanView<'_>,
            stack: PodStack<'_>,
        ) {
            let (mut local_accumulator_data, stack) =
                stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
            let mut local_accumulator = GlweCiphertextMutView::from_container(
                &mut *local_accumulator_data,
                accumulator.polynomial_size(),
                CiphertextModulus::new_native(),
            );
            this.blind_rotate_assign(
                &mut local_accumulator.as_mut_view(),
                &lwe_in,
                ntt_plan,
                stack,
            );
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
            ntt_plan,
            stack,
        )
    }
}

impl<CrtScalar, const N_COMPONENTS: usize, Scalar> FourierBootstrapKey<Scalar>
    for CrtNttLweBootstrapKey<CrtScalar, N_COMPONENTS, ABox<[CrtScalar]>>
where
    CrtScalar: UnsignedInteger,
    Scalar: CrtNtt<CrtScalar, N_COMPONENTS> + CastInto<usize>,
{
    type Fft = Scalar::Plan;

    fn new_fft(polynomial_size: PolynomialSize) -> Self::Fft {
        Scalar::new_plan(polynomial_size)
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
            polynomial_size,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }

    fn fill_with_forward_fourier<ContBsk>(
        &mut self,
        coef_bsk: &LweBootstrapKey<ContBsk>,
        ntt_plan: &Self::Fft,
        stack: PodStack<'_>,
    ) where
        ContBsk: Container<Element = Scalar>,
    {
        let _ = stack;
        let ntt_plan = Scalar::plan_as_view(ntt_plan);
        self.fill_with_forward_ntt(coef_bsk, ntt_plan);
    }

    fn bootstrap_scratch(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        ntt_plan: &Self::Fft,
    ) -> Result<StackReq, SizeOverflow> {
        let _ = ntt_plan;
        bootstrap_scratch::<CrtScalar, N_COMPONENTS, Scalar>(glwe_size, polynomial_size)
    }

    fn bootstrap<ContLweOut, ContLweIn, ContAcc>(
        &self,
        lwe_out: &mut LweCiphertext<ContLweOut>,
        lwe_in: &LweCiphertext<ContLweIn>,
        accumulator: &GlweCiphertext<ContAcc>,
        ntt_plan: &Self::Fft,
        stack: PodStack<'_>,
    ) where
        ContLweOut: ContainerMut<Element = Scalar>,
        ContLweIn: Container<Element = Scalar>,
        ContAcc: Container<Element = Scalar>,
    {
        let ntt_plan = Scalar::plan_as_view(ntt_plan);
        self.bootstrap(lwe_out, lwe_in, accumulator, ntt_plan, stack)
    }

    fn fill_with_forward_fourier_scratch(ntt_plan: &Self::Fft) -> Result<StackReq, SizeOverflow> {
        let _ = ntt_plan;
        Ok(StackReq::empty())
    }
}
