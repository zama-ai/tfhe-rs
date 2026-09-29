//! Combined "half-product + half-rotate" 128-bit FFT programmable bootstrap.
//!
//! The input LWE mask is split in two sections of size `input_lwe_dimension_start` and
//! `input_lwe_dimension_end` as in the [half-rotate
//! bootstrap](super::bootstrap_half_rotate), and each section is a
//! [`Fourier128HalfProductLweBootstrapKey`], so its GGSWs also give the body GLev its own
//! decomposition parameters. This is the combination of the two techniques, and the variant with
//! the smallest key and the lowest latency of the four.

use super::super::math::fft::{Fft128, Fft128View};
use super::bootstrap_half_product::{
    cmux_step_half_product, half_product_blind_rotate_scratch, half_product_bootstrap_scratch,
    Fourier128HalfProductLweBootstrapKey,
};
use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::backward_compatibility::fft_impl::Fourier128HalfProductHalfRotateLweBootstrapKeyVersions;
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
use crate::core_crypto::prelude::{
    lwe_ciphertext_modulus_switch, ContainerMut, ModulusSwitchedLweCiphertext,
};
use aligned_vec::{ABox, CACHELINE_ALIGN};
use core::any::TypeId;
use core::mem::transmute;
use dyn_stack::{PodStack, StackReq};
use tfhe_versionable::Versionize;

/// A 128-bit FFT LWE bootstrap key combining the half-product and half-rotate techniques. See the
/// [module documentation](self) for details.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(Fourier128HalfProductHalfRotateLweBootstrapKeyVersions)]
pub struct Fourier128HalfProductHalfRotateLweBootstrapKey<C: Container<Element = f64>> {
    start: Fourier128HalfProductLweBootstrapKey<C>,
    end: Fourier128HalfProductLweBootstrapKey<C>,
}

impl<C: Container<Element = f64>> Fourier128HalfProductHalfRotateLweBootstrapKey<C> {
    /// Return the section covering the first `input_lwe_dimension_start` input LWE mask elements.
    pub fn start(&self) -> &Fourier128HalfProductLweBootstrapKey<C> {
        &self.start
    }

    /// Return the section covering the last `input_lwe_dimension_end` input LWE mask elements.
    pub fn end(&self) -> &Fourier128HalfProductLweBootstrapKey<C> {
        &self.end
    }

    /// Number of input LWE mask elements handled by the start section.
    pub fn input_lwe_dimension_start(&self) -> LweDimension {
        self.start.input_lwe_dimension()
    }

    /// Number of input LWE mask elements handled by the end section.
    pub fn input_lwe_dimension_end(&self) -> LweDimension {
        self.end.input_lwe_dimension()
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

    pub fn as_view(&self) -> Fourier128HalfProductHalfRotateLweBootstrapKey<&[f64]> {
        Fourier128HalfProductHalfRotateLweBootstrapKey {
            start: self.start.as_view(),
            end: self.end.as_view(),
        }
    }

    pub fn as_mut_view(&mut self) -> Fourier128HalfProductHalfRotateLweBootstrapKey<&mut [f64]>
    where
        C: AsMut<[f64]>,
    {
        Fourier128HalfProductHalfRotateLweBootstrapKey {
            start: self.start.as_mut_view(),
            end: self.end.as_mut_view(),
        }
    }

    /// Return mutable references to the two sections
    pub fn as_mut_sections(
        &mut self,
    ) -> (
        &mut Fourier128HalfProductLweBootstrapKey<C>,
        &mut Fourier128HalfProductLweBootstrapKey<C>,
    ) {
        (&mut self.start, &mut self.end)
    }
}

pub type Fourier128HalfProductHalfRotateLweBootstrapKeyOwned =
    Fourier128HalfProductHalfRotateLweBootstrapKey<ABox<[f64]>>;

impl Fourier128HalfProductHalfRotateLweBootstrapKey<ABox<[f64]>> {
    /// Allocate a new (zeroed) half-product half-rotate key.
    ///
    /// The two sections share `glwe_size` and `polynomial_size` but may use different
    /// decomposition parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        input_lwe_dimension_start: LweDimension,
        decomposition_base_log_mask_start: DecompositionBaseLog,
        decomposition_level_count_mask_start: DecompositionLevelCount,
        decomposition_base_log_body_start: DecompositionBaseLog,
        decomposition_level_count_body_start: DecompositionLevelCount,
        input_lwe_dimension_end: LweDimension,
        decomposition_base_log_mask_end: DecompositionBaseLog,
        decomposition_level_count_mask_end: DecompositionLevelCount,
        decomposition_base_log_body_end: DecompositionBaseLog,
        decomposition_level_count_body_end: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
    ) -> Self {
        let start = Fourier128HalfProductLweBootstrapKey::new(
            input_lwe_dimension_start,
            glwe_size,
            polynomial_size,
            decomposition_base_log_mask_start,
            decomposition_level_count_mask_start,
            decomposition_base_log_body_start,
            decomposition_level_count_body_start,
        );
        let end = Fourier128HalfProductLweBootstrapKey::new(
            input_lwe_dimension_end,
            glwe_size,
            polynomial_size,
            decomposition_base_log_mask_end,
            decomposition_level_count_mask_end,
            decomposition_base_log_body_end,
            decomposition_level_count_body_end,
        );
        Self { start, end }
    }

    pub fn new_fft(&self) -> Fft128 {
        Fft128::new(self.polynomial_size())
    }
}

impl<Cont> Fourier128HalfProductHalfRotateLweBootstrapKey<Cont>
where
    Cont: ContainerMut<Element = f64>,
{
    /// Fill the key with the Fourier transform of a standard-domain key, converting each section in
    /// turn.
    pub fn fill_with_forward_fourier<Scalar, ContBsk>(
        &mut self,
        coef_bsk: &LweHalfProductHalfRotateBootstrapKey<ContBsk>,
        fft: Fft128View<'_>,
    ) where
        Scalar: UnsignedTorus,
        ContBsk: Container<Element = Scalar>,
    {
        self.start.fill_with_forward_fourier(coef_bsk.start(), fft);
        self.end.fill_with_forward_fourier(coef_bsk.end(), fft);
    }
}

/// Return the required memory for
/// [`Fourier128HalfProductHalfRotateLweBootstrapKey::blind_rotate_assign`].
///
/// The requirement is the same as for the non-split half-product key: the cmux scratch depends only
/// on `glwe_size`, `polynomial_size` and `fft`, not on the decomposition parameters, so the two
/// sections' differing level counts do not matter.
pub fn half_product_half_rotate_blind_rotate_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> StackReq {
    half_product_blind_rotate_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}

/// Return the required memory for
/// [`Fourier128HalfProductHalfRotateLweBootstrapKey::bootstrap`].
///
/// See [`half_product_half_rotate_blind_rotate_scratch`] for why this matches the non-split
/// requirement.
pub fn half_product_half_rotate_bootstrap_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> StackReq {
    half_product_bootstrap_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}

impl<Cont> Fourier128HalfProductHalfRotateLweBootstrapKey<Cont>
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
            start: Fourier128HalfProductLweBootstrapKey<&[f64]>,
            end: Fourier128HalfProductLweBootstrapKey<&[f64]>,
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
                cmux_step_half_product(&mut ct0, lwe_mask_element, &bootstrap_key_ggsw, fft, stack);
            }
            for (bootstrap_key_ggsw, lwe_mask_element) in izip_eq!(
                end.into_ggsw_iter(),
                msed_lwe.mask().skip(input_lwe_dimension_start.0)
            ) {
                cmux_step_half_product(&mut ct0, lwe_mask_element, &bootstrap_key_ggsw, fft, stack);
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
            this: Fourier128HalfProductHalfRotateLweBootstrapKey<&[f64]>,
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
pub(crate) mod tests {
    use super::*;
    use crate::core_crypto::algorithms::test::TestResources;
    use crate::core_crypto::algorithms::{
        allocate_and_encrypt_new_lwe_ciphertext, decrypt_lwe_ciphertext,
        generate_programmable_bootstrap_glwe_lut,
        par_allocate_and_convert_standard_half_product_half_rotate_lwe_bootstrap_key_to_fourier_128,
        par_allocate_and_generate_new_half_product_half_rotate_lwe_bootstrap_key,
    };
    use crate::core_crypto::commons::math::random::Uniform;
    use crate::core_crypto::prelude::*;

    // Run a half-product half-rotate PBS over `Scalar` and check the result decrypts correctly.
    // `Scalar = u128` exercises the split-limb `blind_rotate_u128` path; any other `Scalar` (e.g.
    // `u64`) exercises the generic `blind_rotate_assign` path.
    pub(crate) fn half_product_half_rotate_bootstrap_generic<Scalar>()
    where
        Scalar: UnsignedTorus
            + CastInto<usize>
            + CastFrom<usize>
            + Sync
            + Send
            + Encryptable<Uniform, DynamicDistribution<Scalar>>,
    {
        let lwe_dimension = LweDimension(742);
        // The mask is split roughly in half between the two sections.
        let input_lwe_dimension_start = LweDimension(400);
        let input_lwe_dimension_end = LweDimension(lwe_dimension.0 - input_lwe_dimension_start.0);

        let glwe_dimension = GlweDimension(1);
        let polynomial_size = PolynomialSize(2048);
        let glwe_size = glwe_dimension.to_glwe_size();
        let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();

        // Distinct parameters per section, and a lighter body decomposition within each: both
        // techniques at once.
        let base_log_mask_start = DecompositionBaseLog(23);
        let level_mask_start = DecompositionLevelCount(1);
        let base_log_body_start = DecompositionBaseLog(23);
        let level_body_start = DecompositionLevelCount(1);
        let base_log_mask_end = DecompositionBaseLog(11);
        let level_mask_end = DecompositionLevelCount(2);
        let base_log_body_end = DecompositionBaseLog(23);
        let level_body_end = DecompositionLevelCount(1);

        let glwe_noise_distribution = DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000000000000000000008645717832544903,
        ));
        let lwe_noise_distribution = DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000004998277131225527,
        ));

        let mut rsc = TestResources::new();

        let small_lwe_sk: LweSecretKeyOwned<Scalar> =
            LweSecretKey::generate_new_binary(lwe_dimension, &mut rsc.secret_random_generator);
        let glwe_sk: GlweSecretKeyOwned<Scalar> = GlweSecretKey::generate_new_binary(
            glwe_dimension,
            polynomial_size,
            &mut rsc.secret_random_generator,
        );
        let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        let std_bsk = par_allocate_and_generate_new_half_product_half_rotate_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            input_lwe_dimension_start,
            base_log_mask_start,
            level_mask_start,
            base_log_body_start,
            level_body_start,
            base_log_mask_end,
            level_mask_end,
            base_log_body_end,
            level_body_end,
            glwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        assert_eq!(
            std_bsk.start().input_lwe_dimension(),
            input_lwe_dimension_start
        );
        assert_eq!(std_bsk.end().input_lwe_dimension(), input_lwe_dimension_end);

        let fourier_bsk =
            par_allocate_and_convert_standard_half_product_half_rotate_lwe_bootstrap_key_to_fourier_128(
                &std_bsk,
            );

        let fft = Fft128::new(polynomial_size);
        let fft = fft.as_view();

        let message_modulus: Scalar = Scalar::ONE << 4;
        let input_message: Scalar = 3usize.cast_into();
        let delta: Scalar = (Scalar::ONE << (Scalar::BITS - 1)) / message_modulus;
        let plaintext = Plaintext(input_message * delta);

        let lwe_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &small_lwe_sk,
            plaintext,
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        let f = |x: Scalar| x;
        let accumulator: GlweCiphertextOwned<Scalar> = generate_programmable_bootstrap_glwe_lut(
            polynomial_size,
            glwe_size,
            message_modulus.cast_into(),
            ciphertext_modulus,
            delta,
            f,
        );

        let mut lwe_out = LweCiphertext::new(
            Scalar::ZERO,
            big_lwe_sk.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );

        let mut buf = dyn_stack::PodBuffer::try_new(half_product_half_rotate_bootstrap_scratch::<
            Scalar,
        >(glwe_size, polynomial_size, fft))
        .unwrap();
        let stack = PodStack::new(&mut buf);

        fourier_bsk.bootstrap(&mut lwe_out, &lwe_in, &accumulator, fft, stack);

        let decrypted = decrypt_lwe_ciphertext(&big_lwe_sk, &lwe_out);
        let signed_decomposer =
            SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
        let result = signed_decomposer.closest_representable(decrypted.0) / delta;

        assert_eq!(
            f(input_message),
            result,
            "half-product half-rotate PBS result mismatch"
        );
    }
}
