//! "Half-rotate" 128-bit FFT programmable bootstrap.
//!
//! The input LWE mask is split in two sections of size
//! `input_lwe_dimension_start` and `input_lwe_dimension_end`. Each section is blind-rotated with
//! its own [`Fourier128LweBootstrapKey`], which can use its own decomposition parameters
//! `(base_log, level_count)`. Both sections share the same output GLWE key, polynomial size and
//! GLWE size, so together they realise a single blind rotation over the whole
//! `input_lwe_dimension_start + input_lwe_dimension_end` input dimension.
//!
//! This is useful to get intermediate values in the pareto frontier (level, decomposition_base) vs
//! noise and expand the search space of parameters in the optimization

use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, MonomialDegree,
    PolynomialSize,
};
use crate::core_crypto::commons::traits::{Container, ContiguousEntityContainerMut};
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::entities::*;
use crate::core_crypto::experimental::commons::parameters::LweDimensionPart;
use crate::core_crypto::experimental::entities::LweHalfRotateBootstrapKey;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap::{
    blind_rotate_scratch, cmux_step, Fourier128LweBootstrapKey,
};
use crate::core_crypto::fft_impl::fft128::math::fft::{Fft128, Fft128View};
use crate::core_crypto::prelude::{
    lwe_ciphertext_modulus_switch, ContainerMut, ModulusSwitchedLweCiphertext,
};
use aligned_vec::{ABox, CACHELINE_ALIGN};
use core::any::TypeId;
use core::mem::transmute;
use dyn_stack::{PodStack, StackReq};

mod fft128_u128;

/// A 128-bit FFT LWE bootstrap key whose blind rotation is split into two sections, each with its
/// own decomposition parameters. See the [module documentation](self) for details.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Fourier128HalfRotateLweBootstrapKey<C: Container<Element = f64>> {
    start: Fourier128LweBootstrapKey<C>,
    end: Fourier128LweBootstrapKey<C>,
}

impl<C: Container<Element = f64>> Fourier128HalfRotateLweBootstrapKey<C> {
    /// Return the section covering the first `input_lwe_dimension_start` input LWE mask elements.
    pub fn start(&self) -> &Fourier128LweBootstrapKey<C> {
        &self.start
    }

    /// Return the section covering the last `input_lwe_dimension_end` input LWE mask elements.
    pub fn end(&self) -> &Fourier128LweBootstrapKey<C> {
        &self.end
    }

    /// Number of input LWE mask elements handled by the start section.
    pub fn input_lwe_dimension_start(&self) -> LweDimensionPart {
        LweDimensionPart(self.start.input_lwe_dimension().0)
    }

    /// Number of input LWE mask elements handled by the end section.
    pub fn input_lwe_dimension_end(&self) -> LweDimensionPart {
        LweDimensionPart(self.end.input_lwe_dimension().0)
    }

    /// Total input LWE dimension (`input_lwe_dimension_start + input_lwe_dimension_end`).
    pub fn input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.input_lwe_dimension_start().0 + self.input_lwe_dimension_end().0)
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.start.polynomial_size()
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.start.glwe_size()
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.start.output_lwe_dimension()
    }

    pub fn decomposition_base_log_start(&self) -> DecompositionBaseLog {
        self.start.decomposition_base_log()
    }

    pub fn decomposition_level_count_start(&self) -> DecompositionLevelCount {
        self.start.decomposition_level_count()
    }

    pub fn decomposition_base_log_end(&self) -> DecompositionBaseLog {
        self.end.decomposition_base_log()
    }

    pub fn decomposition_level_count_end(&self) -> DecompositionLevelCount {
        self.end.decomposition_level_count()
    }

    pub fn as_view(&self) -> Fourier128HalfRotateLweBootstrapKey<&[f64]> {
        Fourier128HalfRotateLweBootstrapKey {
            start: self.start.as_view(),
            end: self.end.as_view(),
        }
    }

    pub fn as_mut_view(&mut self) -> Fourier128HalfRotateLweBootstrapKey<&mut [f64]>
    where
        C: AsMut<[f64]>,
    {
        Fourier128HalfRotateLweBootstrapKey {
            start: self.start.as_mut_view(),
            end: self.end.as_mut_view(),
        }
    }

    /// Return mutable references to the two sections
    pub fn as_mut_sections(
        &mut self,
    ) -> (
        &mut Fourier128LweBootstrapKey<C>,
        &mut Fourier128LweBootstrapKey<C>,
    ) {
        (&mut self.start, &mut self.end)
    }
}

pub type Fourier128HalfRotateLweBootstrapKeyOwned =
    Fourier128HalfRotateLweBootstrapKey<ABox<[f64]>>;

impl Fourier128HalfRotateLweBootstrapKey<ABox<[f64]>> {
    /// Allocate a new (zeroed) half-rotate key.
    ///
    /// The two sections share `glwe_size` and `polynomial_size` but may use different
    /// decomposition parameters.
    pub fn new(
        input_lwe_dimension_start: LweDimensionPart,
        decomposition_base_log_start: DecompositionBaseLog,
        decomposition_level_count_start: DecompositionLevelCount,
        input_lwe_dimension_end: LweDimensionPart,
        decomposition_base_log_end: DecompositionBaseLog,
        decomposition_level_count_end: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Self {
        let start = Fourier128LweBootstrapKey::new(
            LweDimension(input_lwe_dimension_start.0),
            glwe_size,
            polynomial_size,
            decomposition_base_log_start,
            decomposition_level_count_start,
        );
        let end = Fourier128LweBootstrapKey::new(
            LweDimension(input_lwe_dimension_end.0),
            glwe_size,
            polynomial_size,
            decomposition_base_log_end,
            decomposition_level_count_end,
        );
        Self { start, end }
    }

    pub fn new_fft(&self) -> Fft128 {
        Fft128::new(self.polynomial_size())
    }
}

impl<Cont> Fourier128HalfRotateLweBootstrapKey<Cont>
where
    Cont: ContainerMut<Element = f64>,
{
    /// Fill the key with the Fourier transform of a standard-domain half-rotate bootstrap key,
    /// converting each section in turn.
    ///
    /// The two sections of `coef_bsk` must encrypt, respectively, the first
    /// `input_lwe_dimension_start` and last `input_lwe_dimension_end` bits of the input LWE secret
    /// key under the same output GLWE key. The
    /// [generation
    /// helper][crate::core_crypto::experimental::algorithms::par_allocate_and_generate_new_half_rotate_lwe_bootstrap_key]
    /// produces such a key.
    pub fn fill_with_forward_fourier<Scalar, ContBsk>(
        &mut self,
        coef_bsk: &LweHalfRotateBootstrapKey<ContBsk>,
        fft: Fft128View<'_>,
    ) where
        Scalar: UnsignedTorus,
        ContBsk: Container<Element = Scalar>,
    {
        self.start.fill_with_forward_fourier(coef_bsk.start(), fft);
        self.end.fill_with_forward_fourier(coef_bsk.end(), fft);
    }
}

/// Return the required memory for [`Fourier128HalfRotateLweBootstrapKey::blind_rotate_assign`].
///
/// The requirement is the same as for the non-split key: the cmux scratch depends only on
/// `glwe_size`, `polynomial_size` and `fft`, not on the decomposition parameters, so the two
/// sections' differing level counts do not matter.
pub fn half_rotate_blind_rotate_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> StackReq {
    blind_rotate_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}

/// Return the required memory for [`Fourier128HalfRotateLweBootstrapKey::bootstrap`].
pub fn half_rotate_bootstrap_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> StackReq {
    half_rotate_blind_rotate_scratch::<Scalar>(glwe_size, polynomial_size, fft).and(
        StackReq::new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN),
    )
}

impl<Cont> Fourier128HalfRotateLweBootstrapKey<Cont>
where
    Cont: Container<Element = f64>,
{
    /// Blind-rotate `lut` in place, running the two sections one after the other.
    ///
    /// This is the non-`u128` path (the `u128` path is handled in [`Self::blind_rotate`]).
    pub fn blind_rotate_assign<OutputScalar, ContLut>(
        &self,
        lut: &mut GlweCiphertext<ContLut>,
        msed_lwe: &impl ModulusSwitchedLweCiphertext<usize>,
        fft: Fft128View<'_>,
        stack: &mut PodStack,
    ) where
        OutputScalar: UnsignedTorus,
        ContLut: ContainerMut<Element = OutputScalar>,
    {
        fn implementation<OutputScalar>(
            start: Fourier128LweBootstrapKey<&[f64]>,
            end: Fourier128LweBootstrapKey<&[f64]>,
            mut lut: GlweCiphertext<&mut [OutputScalar]>,
            msed_lwe: &impl ModulusSwitchedLweCiphertext<usize>,
            fft: Fft128View<'_>,
            stack: &mut PodStack,
        ) where
            OutputScalar: UnsignedTorus,
        {
            let input_lwe_dimension_start = start.input_lwe_dimension();
            let input_lwe_dimension =
                LweDimension(input_lwe_dimension_start.0 + end.input_lwe_dimension().0);
            assert_eq!(
                msed_lwe.lwe_dimension(),
                input_lwe_dimension,
                "The input LWE dimension must match the total input dimension of the two sections"
            );

            let msed_lwe_body = msed_lwe.body();

            let ciphertext_modulus = lut.ciphertext_modulus();
            assert!(ciphertext_modulus.is_compatible_with_native_modulus());

            // The body rotation is shared by both sections and applied only once.
            lut.as_mut_polynomial_list()
                .iter_mut()
                .for_each(|mut poly| {
                    polynomial_wrapping_monic_monomial_div_assign(
                        &mut poly,
                        MonomialDegree(msed_lwe_body),
                    );
                });

            let mut ct0 = lut;

            // The successive cmuxes over the two sections, the mask being split in the same place
            // as the key.
            for (bootstrap_key_ggsw, lwe_mask_element) in izip_eq!(
                start.into_ggsw_iter(),
                msed_lwe.mask().take(input_lwe_dimension_start.0)
            ) {
                cmux_step(&mut ct0, lwe_mask_element, &bootstrap_key_ggsw, fft, stack);
            }
            for (bootstrap_key_ggsw, lwe_mask_element) in izip_eq!(
                end.into_ggsw_iter(),
                msed_lwe.mask().skip(input_lwe_dimension_start.0)
            ) {
                cmux_step(&mut ct0, lwe_mask_element, &bootstrap_key_ggsw, fft, stack);
            }

            if !ciphertext_modulus.is_native_modulus() {
                // See the same block in the non-split `Fourier128LweBootstrapKey::blind_rotate`.
                let signed_decomposer = SignedDecomposer::new(
                    DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                    DecompositionLevelCount(1),
                );
                ct0.as_mut()
                    .iter_mut()
                    .for_each(|x| *x = signed_decomposer.closest_representable(*x));
            }
        }

        implementation(
            self.start.as_view(),
            self.end.as_view(),
            lut.as_mut_view(),
            msed_lwe,
            fft,
            stack,
        );
    }

    pub fn bootstrap<InputScalar, OutputScalar, ContLweOut, ContLweIn, ContAcc>(
        &self,
        lwe_out: &mut LweCiphertext<ContLweOut>,
        lwe_in: &LweCiphertext<ContLweIn>,
        accumulator: &GlweCiphertext<ContAcc>,
        fft: Fft128View<'_>,
        stack: &mut PodStack,
    ) where
        // CastInto required for PBS modulus switch which returns a usize
        InputScalar: UnsignedTorus + CastInto<usize>,
        OutputScalar: UnsignedTorus,
        ContLweOut: ContainerMut<Element = OutputScalar>,
        ContLweIn: Container<Element = InputScalar>,
        ContAcc: Container<Element = OutputScalar>,
    {
        let log_modulus = accumulator
            .polynomial_size()
            .to_blind_rotation_input_modulus_log();

        let lwe_in_msed = lwe_ciphertext_modulus_switch(lwe_in.as_view(), log_modulus);

        self.blind_rotate(lwe_out, &lwe_in_msed, accumulator, fft, stack);
    }

    pub fn blind_rotate<OutputScalar, ContLweOut, ContAcc>(
        &self,
        lwe_out: &mut LweCiphertext<ContLweOut>,
        msed_lwe_in: &impl ModulusSwitchedLweCiphertext<usize>,
        accumulator: &GlweCiphertext<ContAcc>,
        fft: Fft128View<'_>,
        stack: &mut PodStack,
    ) where
        OutputScalar: UnsignedTorus,
        ContLweOut: ContainerMut<Element = OutputScalar>,
        ContAcc: Container<Element = OutputScalar>,
    {
        fn implementation<OutputScalar>(
            this: Fourier128HalfRotateLweBootstrapKey<&[f64]>,
            mut lwe_out: LweCiphertext<&mut [OutputScalar]>,
            msed_lwe_in: &impl ModulusSwitchedLweCiphertext<usize>,
            accumulator: GlweCiphertext<&[OutputScalar]>,
            fft: Fft128View<'_>,
            stack: &mut PodStack,
        ) where
            OutputScalar: UnsignedTorus,
        {
            // We type check dynamically with TypeId, mirroring `Fourier128LweBootstrapKey`.
            #[allow(clippy::transmute_undefined_repr)]
            if TypeId::of::<OutputScalar>() == TypeId::of::<u128>() {
                let mut lwe_out: LweCiphertext<&mut [u128]> = unsafe { transmute(lwe_out) };
                let accumulator: GlweCiphertext<&[u128]> = unsafe { transmute(accumulator) };

                return this.blind_rotate_u128(&mut lwe_out, msed_lwe_in, &accumulator, fft, stack);
            }

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
    use crate::core_crypto::algorithms::test::{
        FftTestParams, TestResources, FFT128_U128_PARAMS, FFT_U64_PARAMS,
    };
    use crate::core_crypto::algorithms::{
        allocate_and_encrypt_new_lwe_ciphertext, decrypt_lwe_ciphertext,
        generate_programmable_bootstrap_glwe_lut,
    };
    use crate::core_crypto::commons::math::random::Uniform;
    use crate::core_crypto::experimental::algorithms::{
        par_allocate_and_convert_standard_half_rotate_lwe_bootstrap_key_to_fourier_128,
        par_allocate_and_generate_new_half_rotate_lwe_bootstrap_key,
    };
    use crate::core_crypto::experimental::commons::half_rotate_parameters::{
        HalfRotateNoiseSquashingParameters,
        HALF_ROTATE_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::core_crypto::prelude::*;

    // Run a half-rotate PBS from a `u64` input and check the result decrypts correctly. The output
    // is `u128`, so this exercises the split-limb `blind_rotate_u128` path.
    fn half_rotate_bootstrap(params: HalfRotateNoiseSquashingParameters) {
        let HalfRotateNoiseSquashingParameters {
            glwe_dimension,
            polynomial_size,
            glwe_noise_distribution,
            input_lwe_dimension_start,
            input_lwe_dimension_end,
            input_lwe_noise_distribution,
            input_ciphertext_modulus,
            decomp_base_log_start,
            decomp_level_count_start,
            decomp_base_log_end,
            decomp_level_count_end,
            output_ciphertext_modulus,
        } = params;
        let input_lwe_dimension = params.input_lwe_dimension();
        let glwe_size = glwe_dimension.to_glwe_size();

        let mut rsc = TestResources::new();

        let small_lwe_sk: LweSecretKeyOwned<u64> = LweSecretKey::generate_new_binary(
            input_lwe_dimension,
            &mut rsc.secret_random_generator,
        );
        let glwe_sk: GlweSecretKeyOwned<u128> = GlweSecretKey::generate_new_binary(
            glwe_dimension,
            polynomial_size,
            &mut rsc.secret_random_generator,
        );
        let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        let std_bsk = par_allocate_and_generate_new_half_rotate_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            input_lwe_dimension_start,
            input_lwe_dimension_end,
            decomp_base_log_start,
            decomp_level_count_start,
            decomp_base_log_end,
            decomp_level_count_end,
            glwe_noise_distribution,
            output_ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        assert_eq!(
            std_bsk.start().input_lwe_dimension().0,
            input_lwe_dimension_start.0
        );
        assert_eq!(
            std_bsk.end().input_lwe_dimension().0,
            input_lwe_dimension_end.0
        );

        let fourier_bsk =
            par_allocate_and_convert_standard_half_rotate_lwe_bootstrap_key_to_fourier_128(
                &std_bsk,
            );

        let fft = Fft128::new(polynomial_size);
        let fft = fft.as_view();

        let message_modulus: u64 = 1 << 4;
        let input_message: u64 = 3;
        let input_delta: u64 = (1 << (u64::BITS - 1)) / message_modulus;
        let output_delta: u128 = (1 << (u128::BITS - 1)) / message_modulus as u128;

        let plaintext = Plaintext(input_message * input_delta);

        let lwe_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
            &small_lwe_sk,
            plaintext,
            input_lwe_noise_distribution,
            input_ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        let f = |x: u128| x;
        let accumulator: GlweCiphertextOwned<u128> = generate_programmable_bootstrap_glwe_lut(
            polynomial_size,
            glwe_size,
            message_modulus as usize,
            output_ciphertext_modulus,
            output_delta,
            f,
        );

        let mut lwe_out = LweCiphertext::new(
            0u128,
            big_lwe_sk.lwe_dimension().to_lwe_size(),
            output_ciphertext_modulus,
        );

        let mut buf = dyn_stack::PodBuffer::try_new(half_rotate_bootstrap_scratch::<u128>(
            glwe_size,
            polynomial_size,
            fft,
        ))
        .unwrap();
        let stack = PodStack::new(&mut buf);

        fourier_bsk.bootstrap(&mut lwe_out, &lwe_in, &accumulator, fft, stack);

        let decrypted = decrypt_lwe_ciphertext(&big_lwe_sk, &lwe_out);
        let signed_decomposer =
            SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
        let result = signed_decomposer.closest_representable(decrypted.0) / output_delta;

        assert_eq!(
            f(input_message as u128),
            result,
            "half-rotate PBS result mismatch"
        );
    }

    // Two sections sharing one set of decomposition parameters and holding exactly the GGSWs of a
    // classic key must reproduce that key's bootstrap bit-for-bit. This pins the offset at which
    // the mask is split during the blind rotation against the offset at which the key was split:
    // any mismatch pairs a GGSW with the wrong mask element. `Scalar = u128` compares the
    // split-limb paths, any other `Scalar` the generic ones.
    fn half_rotate_matches_classic_bsk_generic<Scalar>(
        params: FftTestParams<Scalar>,
        input_lwe_dimension_start: LweDimensionPart,
    ) where
        Scalar: UnsignedTorus
            + CastInto<usize>
            + CastFrom<usize>
            + Sync
            + Send
            + Encryptable<Uniform, DynamicDistribution<Scalar>>,
    {
        let FftTestParams {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ciphertext_modulus,
        } = params;
        let glwe_size = glwe_dimension.to_glwe_size();

        let mut rsc = TestResources::new();

        let small_lwe_sk: LweSecretKeyOwned<Scalar> =
            LweSecretKey::generate_new_binary(lwe_dimension, &mut rsc.secret_random_generator);
        let glwe_sk: GlweSecretKeyOwned<Scalar> = GlweSecretKey::generate_new_binary(
            glwe_dimension,
            polynomial_size,
            &mut rsc.secret_random_generator,
        );
        let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        let classic_std_bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            pbs_base_log,
            pbs_level,
            glwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        // Both sections are cut out of the classic key rather than generated, so that a difference
        // in the outputs can only come from the blind rotation.
        let ggsw_len = classic_std_bsk.as_ref().len() / lwe_dimension.0;
        let (start_data, end_data) = classic_std_bsk
            .as_ref()
            .split_at(ggsw_len * input_lwe_dimension_start.0);
        let section = |data: &[Scalar]| {
            LweBootstrapKeyOwned::from_container(
                data.to_vec(),
                glwe_size,
                polynomial_size,
                pbs_base_log,
                pbs_level,
                ciphertext_modulus,
            )
        };
        let half_rotate_std_bsk =
            LweHalfRotateBootstrapKey::from_keys(section(start_data), section(end_data));

        let mut classic_fourier_bsk = Fourier128LweBootstrapKeyOwned::new(
            lwe_dimension,
            glwe_size,
            polynomial_size,
            pbs_base_log,
            pbs_level,
        );
        par_convert_standard_lwe_bootstrap_key_to_fourier_128(
            &classic_std_bsk,
            &mut classic_fourier_bsk,
        );
        let half_rotate_fourier_bsk =
            par_allocate_and_convert_standard_half_rotate_lwe_bootstrap_key_to_fourier_128(
                &half_rotate_std_bsk,
            );

        let fft = Fft128::new(polynomial_size);
        let fft = fft.as_view();

        let message_modulus: Scalar = Scalar::ONE << 4;
        let delta: Scalar = (Scalar::ONE << (Scalar::BITS - 1)) / message_modulus;

        let input_message: Scalar = 3usize.cast_into();

        // The input mask is uniformly random, which is what makes a wrong GGSW/mask pairing show up
        // in the output.
        let lwe_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &small_lwe_sk,
            Plaintext(input_message * delta),
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        let accumulator: GlweCiphertextOwned<Scalar> = generate_programmable_bootstrap_glwe_lut(
            polynomial_size,
            glwe_size,
            message_modulus.cast_into(),
            ciphertext_modulus,
            delta,
            |x| x,
        );

        let mut buf = dyn_stack::PodBuffer::try_new(half_rotate_bootstrap_scratch::<Scalar>(
            glwe_size,
            polynomial_size,
            fft,
        ))
        .unwrap();
        let stack = PodStack::new(&mut buf);

        let lwe_out_size = big_lwe_sk.lwe_dimension().to_lwe_size();

        let mut classic_lwe_out =
            LweCiphertext::new(Scalar::ZERO, lwe_out_size, ciphertext_modulus);
        classic_fourier_bsk.bootstrap(&mut classic_lwe_out, &lwe_in, &accumulator, fft, stack);

        let mut half_rotate_lwe_out =
            LweCiphertext::new(Scalar::ZERO, lwe_out_size, ciphertext_modulus);
        half_rotate_fourier_bsk.bootstrap(
            &mut half_rotate_lwe_out,
            &lwe_in,
            &accumulator,
            fft,
            stack,
        );

        assert_eq!(
            half_rotate_lwe_out, classic_lwe_out,
            "half-rotate bootstrap differs from the classic bootstrap on the same key material"
        );
    }

    // `u128` output: goes through the split-limb `blind_rotate_u128` path.
    #[test]
    fn test_half_rotate_bootstrap_u128() {
        half_rotate_bootstrap(
            HALF_ROTATE_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        );
    }

    #[test]
    fn test_half_rotate_matches_classic_bsk_u128() {
        half_rotate_matches_classic_bsk_generic(
            FFT128_U128_PARAMS,
            HALF_ROTATE_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                .input_lwe_dimension_start,
        );
    }

    // `u64` output: goes through the generic `blind_rotate_assign` path (the non-`u128` branch of
    // `blind_rotate`), which the `u128` tests never reach.
    #[test]
    fn test_half_rotate_matches_classic_bsk_u64() {
        half_rotate_matches_classic_bsk_generic(
            FFT_U64_PARAMS,
            HALF_ROTATE_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                .input_lwe_dimension_start,
        );
    }
}
