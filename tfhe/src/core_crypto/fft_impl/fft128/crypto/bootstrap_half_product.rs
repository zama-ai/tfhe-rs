//! "Half-product" 128-bit FFT programmable bootstrap.
//!
//! Each GGSW of the bootstrap key is a [`half-product GGSW
//! ciphertext`](`crate::core_crypto::entities::HalfProductGgswCiphertext`): its `k` mask GLev
//! ciphertexts use `(base_log_mask, level_count_mask)` while its body GLev uses
//! `(base_log_body, level_count_body)`, typically with a smaller level count. This trades a little
//! noise for a smaller key and fewer FFTs per external product.
//!
//! This is useful to get intermediate values in the pareto frontier (level, decomposition_base) vs
//! noise and expand the search space of parameters in the optimization

use super::super::math::fft::{Fft128, Fft128View};
use super::ggsw_half_product::{
    cmux_half_product, cmux_half_product_scratch, Fourier128HalfProductGgswCiphertext,
};
use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::backward_compatibility::fft_impl::Fourier128HalfProductLweBootstrapKeyVersions;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, MonomialDegree,
    PolynomialSize,
};
use crate::core_crypto::commons::traits::{Container, ContiguousEntityContainerMut, Split};
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::entities::half_product_ggsw_ciphertext::fourier_half_product_ggsw_ciphertext_size;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{
    lwe_ciphertext_modulus_switch, ContainerMut, ModulusSwitchedLweCiphertext,
};
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
use core::any::TypeId;
use core::mem::transmute;
use dyn_stack::{PodStack, StackReq};
use tfhe_versionable::Versionize;

/// A 128-bit FFT LWE bootstrap key made of half-product GGSW ciphertexts. See the [module
/// documentation](self) for details.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(Fourier128HalfProductLweBootstrapKeyVersions)]
pub struct Fourier128HalfProductLweBootstrapKey<C: Container<Element = f64>> {
    data_re0: C,
    data_re1: C,
    data_im0: C,
    data_im1: C,
    polynomial_size: PolynomialSize,
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    decomposition_base_log_mask: DecompositionBaseLog,
    decomposition_level_count_mask: DecompositionLevelCount,
    decomposition_base_log_body: DecompositionBaseLog,
    decomposition_level_count_body: DecompositionLevelCount,
}

impl<C: Container<Element = f64>> Fourier128HalfProductLweBootstrapKey<C> {
    #[allow(clippy::too_many_arguments)]
    pub fn from_container(
        data_re0: C,
        data_re1: C,
        data_im0: C,
        data_im1: C,
        polynomial_size: PolynomialSize,
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        decomposition_base_log_mask: DecompositionBaseLog,
        decomposition_level_count_mask: DecompositionLevelCount,
        decomposition_base_log_body: DecompositionBaseLog,
        decomposition_level_count_body: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(polynomial_size.0 % 2, 0);
        let container_len = input_lwe_dimension.0
            * fourier_half_product_ggsw_ciphertext_size(
                glwe_size,
                polynomial_size.to_fourier_polynomial_size(),
                decomposition_level_count_mask,
                decomposition_level_count_body,
            );
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
            decomposition_base_log_mask,
            decomposition_level_count_mask,
            decomposition_base_log_body,
            decomposition_level_count_body,
        }
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

    pub fn decomposition_base_log_mask(&self) -> DecompositionBaseLog {
        self.decomposition_base_log_mask
    }

    pub fn decomposition_level_count_mask(&self) -> DecompositionLevelCount {
        self.decomposition_level_count_mask
    }

    pub fn decomposition_base_log_body(&self) -> DecompositionBaseLog {
        self.decomposition_base_log_body
    }

    pub fn decomposition_level_count_body(&self) -> DecompositionLevelCount {
        self.decomposition_level_count_body
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        LweDimension((self.glwe_size.0 - 1) * self.polynomial_size().0)
    }

    pub fn data(self) -> (C, C, C, C) {
        (self.data_re0, self.data_re1, self.data_im0, self.data_im1)
    }

    pub fn as_view(&self) -> Fourier128HalfProductLweBootstrapKey<&[C::Element]> {
        Fourier128HalfProductLweBootstrapKey {
            data_re0: self.data_re0.as_ref(),
            data_re1: self.data_re1.as_ref(),
            data_im0: self.data_im0.as_ref(),
            data_im1: self.data_im1.as_ref(),
            polynomial_size: self.polynomial_size,
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log_mask: self.decomposition_base_log_mask,
            decomposition_level_count_mask: self.decomposition_level_count_mask,
            decomposition_base_log_body: self.decomposition_base_log_body,
            decomposition_level_count_body: self.decomposition_level_count_body,
        }
    }

    pub fn as_mut_view(&mut self) -> Fourier128HalfProductLweBootstrapKey<&mut [C::Element]>
    where
        C: AsMut<[C::Element]>,
    {
        Fourier128HalfProductLweBootstrapKey {
            data_re0: self.data_re0.as_mut(),
            data_re1: self.data_re1.as_mut(),
            data_im0: self.data_im0.as_mut(),
            data_im1: self.data_im1.as_mut(),
            polynomial_size: self.polynomial_size,
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log_mask: self.decomposition_base_log_mask,
            decomposition_level_count_mask: self.decomposition_level_count_mask,
            decomposition_base_log_body: self.decomposition_base_log_body,
            decomposition_level_count_body: self.decomposition_level_count_body,
        }
    }

    /// Return an iterator over the half-product GGSW ciphertexts of the key.
    pub fn into_ggsw_iter(
        self,
    ) -> impl DoubleEndedIterator<Item = Fourier128HalfProductGgswCiphertext<C>>
           + ExactSizeIterator<Item = Fourier128HalfProductGgswCiphertext<C>>
    where
        C: Split,
    {
        let input_lwe_dimension = self.input_lwe_dimension.0;
        let polynomial_size = self.polynomial_size;
        let glwe_size = self.glwe_size;
        let decomposition_base_log_mask = self.decomposition_base_log_mask;
        let decomposition_level_count_mask = self.decomposition_level_count_mask;
        let decomposition_base_log_body = self.decomposition_base_log_body;
        let decomposition_level_count_body = self.decomposition_level_count_body;

        izip_eq!(
            self.data_re0.split_into(input_lwe_dimension),
            self.data_re1.split_into(input_lwe_dimension),
            self.data_im0.split_into(input_lwe_dimension),
            self.data_im1.split_into(input_lwe_dimension)
        )
        .map(move |(data_re0, data_re1, data_im0, data_im1)| {
            Fourier128HalfProductGgswCiphertext::from_container(
                data_re0,
                data_re1,
                data_im0,
                data_im1,
                polynomial_size,
                glwe_size,
                decomposition_base_log_mask,
                decomposition_level_count_mask,
                decomposition_base_log_body,
                decomposition_level_count_body,
            )
        })
    }
}

pub type Fourier128HalfProductLweBootstrapKeyOwned =
    Fourier128HalfProductLweBootstrapKey<ABox<[f64]>>;

impl Fourier128HalfProductLweBootstrapKey<ABox<[f64]>> {
    pub fn new(
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log_mask: DecompositionBaseLog,
        decomposition_level_count_mask: DecompositionLevelCount,
        decomposition_base_log_body: DecompositionBaseLog,
        decomposition_level_count_body: DecompositionLevelCount,
    ) -> Self {
        let container_len = input_lwe_dimension.0
            * fourier_half_product_ggsw_ciphertext_size(
                glwe_size,
                polynomial_size.to_fourier_polynomial_size(),
                decomposition_level_count_mask,
                decomposition_level_count_body,
            );

        let boxed_re0 = avec![0.0f64; container_len].into_boxed_slice();
        let boxed_re1 = avec![0.0f64; container_len].into_boxed_slice();
        let boxed_im0 = avec![0.0f64; container_len].into_boxed_slice();
        let boxed_im1 = avec![0.0f64; container_len].into_boxed_slice();

        Self::from_container(
            boxed_re0,
            boxed_re1,
            boxed_im0,
            boxed_im1,
            polynomial_size,
            input_lwe_dimension,
            glwe_size,
            decomposition_base_log_mask,
            decomposition_level_count_mask,
            decomposition_base_log_body,
            decomposition_level_count_body,
        )
    }

    pub fn new_fft(&self) -> Fft128 {
        Fft128::new(self.polynomial_size())
    }
}

impl<Cont> Fourier128HalfProductLweBootstrapKey<Cont>
where
    Cont: ContainerMut<Element = f64>,
{
    /// Fill the key with the Fourier transform of a standard-domain half-product bootstrap key.
    pub fn fill_with_forward_fourier<Scalar, ContBsk>(
        &mut self,
        coef_bsk: &LweHalfProductBootstrapKey<ContBsk>,
        fft: Fft128View<'_>,
    ) where
        Scalar: UnsignedTorus,
        ContBsk: Container<Element = Scalar>,
    {
        fn implementation<Scalar: UnsignedTorus>(
            this: Fourier128HalfProductLweBootstrapKey<&mut [f64]>,
            coef_bsk: &LweHalfProductBootstrapKey<&[Scalar]>,
            fft: Fft128View<'_>,
        ) {
            for (mut fourier_ggsw, standard_ggsw) in
                izip_eq!(this.into_ggsw_iter(), coef_bsk.iter())
            {
                fourier_ggsw.fill_with_forward_fourier(&standard_ggsw, fft);
            }
        }
        implementation(self.as_mut_view(), &coef_bsk.as_view(), fft);
    }
}

/// Return the required memory for
/// [`Fourier128HalfProductLweBootstrapKey::blind_rotate_assign`].
pub fn half_product_blind_rotate_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> StackReq {
    StackReq::new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN).and(
        cmux_half_product_scratch::<Scalar>(glwe_size, polynomial_size, fft),
    )
}

/// Return the required memory for [`Fourier128HalfProductLweBootstrapKey::bootstrap`].
pub fn half_product_bootstrap_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> StackReq {
    half_product_blind_rotate_scratch::<Scalar>(glwe_size, polynomial_size, fft).and(
        StackReq::new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN),
    )
}

/// One cmux of a half-product blind rotation:
/// `ct0 <- cmux(ggsw, ct0, ct0 * X^{lwe_mask_element})`.
///
/// A no-op when `lwe_mask_element == 0`. This is the half-product analog of
/// [`cmux_step`](super::bootstrap::cmux_step).
#[inline]
pub(crate) fn cmux_step_half_product<OutputScalar, ContGgsw>(
    ct0: &mut GlweCiphertext<&mut [OutputScalar]>,
    lwe_mask_element: usize,
    ggsw: &Fourier128HalfProductGgswCiphertext<ContGgsw>,
    fft: Fft128View<'_>,
    stack: &mut PodStack,
) where
    OutputScalar: UnsignedTorus,
    ContGgsw: Container<Element = f64>,
{
    if lwe_mask_element == 0 {
        return;
    }

    // We copy ct_0 to ct_1
    let (ct1, stack) = stack.collect_aligned(CACHELINE_ALIGN, ct0.as_ref().iter().copied());
    let mut ct1 =
        GlweCiphertextMutView::from_container(ct1, ct0.polynomial_size(), ct0.ciphertext_modulus());

    // We rotate ct_1 by performing ct_1 <- ct_1 * X^{lwe_mask_element}
    for mut poly in ct1.as_mut_polynomial_list().iter_mut() {
        polynomial_wrapping_monic_monomial_mul_assign(&mut poly, MonomialDegree(lwe_mask_element));
    }

    cmux_half_product(ct0, &mut ct1, ggsw, fft, stack);
}

impl<Cont> Fourier128HalfProductLweBootstrapKey<Cont>
where
    Cont: Container<Element = f64>,
{
    /// Blind-rotate `lut` in place.
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
            this: Fourier128HalfProductLweBootstrapKey<&[f64]>,
            mut lut: GlweCiphertext<&mut [OutputScalar]>,
            msed_lwe: &impl ModulusSwitchedLweCiphertext<usize>,
            fft: Fft128View<'_>,
            stack: &mut PodStack,
        ) where
            OutputScalar: UnsignedTorus,
        {
            assert_eq!(
                msed_lwe.lwe_dimension(),
                this.input_lwe_dimension(),
                "The input LWE dimension must match the input dimension of the key"
            );

            let msed_lwe_mask = msed_lwe.mask();
            let msed_lwe_body = msed_lwe.body();

            let ciphertext_modulus = lut.ciphertext_modulus();
            assert!(ciphertext_modulus.is_compatible_with_native_modulus());

            lut.as_mut_polynomial_list()
                .iter_mut()
                .for_each(|mut poly| {
                    polynomial_wrapping_monic_monomial_div_assign(
                        &mut poly,
                        MonomialDegree(msed_lwe_body),
                    );
                });

            // We initialize the ct_0 used for the successive cmuxes
            let mut ct0 = lut;

            for (lwe_mask_element, bootstrap_key_ggsw) in
                izip_eq!(msed_lwe_mask, this.into_ggsw_iter())
            {
                cmux_step_half_product(&mut ct0, lwe_mask_element, &bootstrap_key_ggsw, fft, stack);
            }

            if !ciphertext_modulus.is_native_modulus() {
                // See the same block in `Fourier128LweBootstrapKey::blind_rotate_assign`.
                let signed_decomposer = SignedDecomposer::new(
                    DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                    DecompositionLevelCount(1),
                );
                ct0.as_mut()
                    .iter_mut()
                    .for_each(|x| *x = signed_decomposer.closest_representable(*x));
            }
        }
        implementation(self.as_view(), lut.as_mut_view(), msed_lwe, fft, stack);
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
            this: Fourier128HalfProductLweBootstrapKey<&[f64]>,
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
    use super::super::bootstrap::bootstrap_scratch;
    use super::*;
    use crate::core_crypto::algorithms::test::TestResources;
    use crate::core_crypto::algorithms::{
        allocate_and_encrypt_new_lwe_ciphertext, decrypt_lwe_ciphertext,
        generate_programmable_bootstrap_glwe_lut,
        par_allocate_and_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128,
        par_allocate_and_generate_new_half_product_lwe_bootstrap_key,
    };
    use crate::core_crypto::commons::math::random::Uniform;
    use crate::core_crypto::prelude::*;

    // Run a half-product PBS over `Scalar` and check the result decrypts correctly. `Scalar = u128`
    // exercises the split-limb `blind_rotate_u128` path; any other `Scalar` (e.g. `u64`) exercises
    // the generic `blind_rotate_assign` path.
    pub(crate) fn half_product_bootstrap_generic<Scalar>()
    where
        Scalar: UnsignedTorus
            + CastInto<usize>
            + CastFrom<usize>
            + Sync
            + Send
            + Encryptable<Uniform, DynamicDistribution<Scalar>>,
    {
        let lwe_dimension = LweDimension(742);

        let glwe_dimension = GlweDimension(1);
        let polynomial_size = PolynomialSize(2048);
        let glwe_size = glwe_dimension.to_glwe_size();
        let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();

        // A lighter body decomposition than the mask one: the point of the "half product".
        let base_log_mask = DecompositionBaseLog(11);
        let level_mask = DecompositionLevelCount(2);
        let base_log_body = DecompositionBaseLog(23);
        let level_body = DecompositionLevelCount(1);

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

        let std_bsk = par_allocate_and_generate_new_half_product_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            base_log_mask,
            level_mask,
            base_log_body,
            level_body,
            glwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        assert_eq!(std_bsk.input_lwe_dimension(), lwe_dimension);

        let fourier_bsk =
            par_allocate_and_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128(
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

        let mut buf = dyn_stack::PodBuffer::try_new(half_product_bootstrap_scratch::<Scalar>(
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
        let result = signed_decomposer.closest_representable(decrypted.0) / delta;

        assert_eq!(f(input_message), result, "half-product PBS result mismatch");
    }

    /// Gather the rows of a classic bootstrap key into the half-product layout.
    ///
    /// Only valid when the mask and body decomposition parameters are equal, in which case a
    /// half-product key holds exactly the same GLWE ciphertexts as a classic one, reordered.
    pub(crate) fn gather_half_product_key_from_classic<Scalar: UnsignedTorus>(
        classic: &LweBootstrapKeyOwned<Scalar>,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
    ) -> LweHalfProductBootstrapKeyOwned<Scalar> {
        let glwe_size = classic.glwe_size();
        let polynomial_size = classic.polynomial_size();
        let glwe_dimension = glwe_size.to_glwe_dimension().0;
        let row_len = glwe_ciphertext_size(glwe_size, polynomial_size);

        let mut data = Vec::with_capacity(classic.as_ref().len());
        for ggsw in classic.iter() {
            let rows: Vec<&[Scalar]> = ggsw.as_ref().chunks_exact(row_len).collect();
            // Mask block: rows 0..k-1 of each level matrix, levels in the stored order.
            for level_index in 0..level.0 {
                for row_index in 0..glwe_dimension {
                    data.extend_from_slice(rows[level_index * glwe_size.0 + row_index]);
                }
            }
            // Body block: row k of each level matrix.
            for level_index in 0..level.0 {
                data.extend_from_slice(rows[level_index * glwe_size.0 + glwe_dimension]);
            }
        }

        LweHalfProductBootstrapKeyOwned::from_container(
            data,
            glwe_size,
            polynomial_size,
            base_log,
            level,
            base_log,
            level,
            classic.ciphertext_modulus(),
        )
    }

    /// Assert that two bootstrap outputs agree up to `max_abs_diff` on the torus.
    ///
    /// A wrong row pairing or level pairing is off by a factor of at least `2^base_log`, i.e. by a
    /// large fraction of the modulus, so a bound far below the modulus still pins the layout.
    pub(crate) fn assert_bootstrap_outputs_close<Scalar: UnsignedTorus>(
        lhs: &LweCiphertextOwned<Scalar>,
        rhs: &LweCiphertextOwned<Scalar>,
        max_abs_diff: Scalar,
        context: &str,
    ) {
        for (index, (&lhs, &rhs)) in izip_eq!(lhs.as_ref(), rhs.as_ref()).enumerate() {
            let diff = lhs.wrapping_sub(rhs);
            let abs_diff = diff.min(Scalar::ZERO.wrapping_sub(diff));
            assert!(
                abs_diff <= max_abs_diff,
                "{context}: coefficient {index} differs by {abs_diff:?}, more than the tolerated \
                {max_abs_diff:?} ({lhs:?} vs {rhs:?})"
            );
        }
    }

    // A half-product key holding exactly the GGSW rows of a classic key, with the same
    // decomposition parameters for the mask and the body, must reproduce that key's bootstrap.
    // This pins the row ordering, the level ordering and the two-decomposer bookkeeping at once.
    // `Scalar = u128` compares the split-limb paths, any other `Scalar` the generic ones.
    //
    // `max_abs_diff` is the tolerated torus distance. The half-product external product
    // accumulates every mask level before the body levels, whereas a classic one accumulates the
    // body row within each level, and floating-point addition is not associative: at `u128` the
    // sums sit near the `fft128` mantissa limit, so the two orders differ in the low bits. Any
    // narrower `Scalar` keeps the products exact and matches bit-for-bit.
    pub(crate) fn half_product_matches_classic_bsk_generic<Scalar>(max_abs_diff: Scalar)
    where
        Scalar: UnsignedTorus
            + CastInto<usize>
            + CastFrom<usize>
            + Sync
            + Send
            + Encryptable<Uniform, DynamicDistribution<Scalar>>,
    {
        let lwe_dimension = LweDimension(30);

        let glwe_dimension = GlweDimension(2);
        let polynomial_size = PolynomialSize(512);
        let glwe_size = glwe_dimension.to_glwe_size();
        let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();

        let base_log = DecompositionBaseLog(11);
        let level = DecompositionLevelCount(2);

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

        let classic_std_bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            base_log,
            level,
            glwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        // The half-product key is cut out of the classic key rather than generated, so that a
        // difference in the outputs can only come from the external product.
        let half_product_std_bsk =
            gather_half_product_key_from_classic(&classic_std_bsk, base_log, level);

        let mut classic_fourier_bsk = Fourier128LweBootstrapKeyOwned::new(
            lwe_dimension,
            glwe_size,
            polynomial_size,
            base_log,
            level,
        );
        par_convert_standard_lwe_bootstrap_key_to_fourier_128(
            &classic_std_bsk,
            &mut classic_fourier_bsk,
        );
        let half_product_fourier_bsk =
            par_allocate_and_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128(
                &half_product_std_bsk,
            );

        let fft = Fft128::new(polynomial_size);
        let fft = fft.as_view();

        let message_modulus: Scalar = Scalar::ONE << 4;
        let delta: Scalar = (Scalar::ONE << (Scalar::BITS - 1)) / message_modulus;

        let input_message: Scalar = 3usize.cast_into();

        // The input mask is uniformly random, which is what makes a wrong row pairing show up in
        // the output.
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

        let mut buf = dyn_stack::PodBuffer::try_new(half_product_bootstrap_scratch::<Scalar>(
            glwe_size,
            polynomial_size,
            fft,
        ))
        .unwrap();
        let stack = PodStack::new(&mut buf);

        let lwe_out_size = big_lwe_sk.lwe_dimension().to_lwe_size();

        // The classic bootstrap needs its own, larger scratch: the half-product external product
        // decomposes the mask polynomials only, so its term buffer is one polynomial shorter.
        let mut classic_buf = dyn_stack::PodBuffer::try_new(bootstrap_scratch::<Scalar>(
            glwe_size,
            polynomial_size,
            fft,
        ))
        .unwrap();
        let classic_stack = PodStack::new(&mut classic_buf);

        let mut classic_lwe_out =
            LweCiphertext::new(Scalar::ZERO, lwe_out_size, ciphertext_modulus);
        classic_fourier_bsk.bootstrap(
            &mut classic_lwe_out,
            &lwe_in,
            &accumulator,
            fft,
            classic_stack,
        );

        let mut half_product_lwe_out =
            LweCiphertext::new(Scalar::ZERO, lwe_out_size, ciphertext_modulus);
        half_product_fourier_bsk.bootstrap(
            &mut half_product_lwe_out,
            &lwe_in,
            &accumulator,
            fft,
            stack,
        );

        assert_bootstrap_outputs_close(
            &half_product_lwe_out,
            &classic_lwe_out,
            max_abs_diff,
            "half-product bootstrap differs from the classic bootstrap on the same key material",
        );
    }
}
