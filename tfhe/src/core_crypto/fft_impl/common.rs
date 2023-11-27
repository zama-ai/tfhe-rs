use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::{CastInto, UnsignedInteger};
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LutCountLog, LweDimension,
    ModulusSwitchOffset, PolynomialSize,
};
use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::ContainerMut;
use dyn_stack::{PodStack, SizeOverflow, StackReq};

/// This function switches modulus for a single coefficient of a ciphertext,
/// only in the context of a PBS
///
/// - offset: the number of msb discarded
/// - lut_count_log: the right padding
///
/// # Note
///
/// If you are switching to a modulus of $2N$ then this function may return the value $2N$ while a
/// "true" modulus switch would return $0$ in that case. It turns out that this is not affecting
/// other parts of the code relying on the modulus switch (as a rotation by $2N$ is effectively the
/// same as rotation by $0$ for polynomials of size $N$ in the ring $X^N+1$) but it could be
/// problematic for code requiring an output in the expected $[0; 2N[$ range. Also this saves a few
/// instructions which can add up when this is being called hundreds or thousands of times per PBS.
pub fn fast_pbs_modulus_switch<Scalar: UnsignedTorus + CastInto<usize>>(
    input: Scalar,
    poly_size: PolynomialSize,
    offset: ModulusSwitchOffset,
    lut_count_log: LutCountLog,
) -> usize {
    // First, do the left shift (we discard the offset msb)
    let mut output = input << offset.0;
    // Start doing the right shift
    output >>= Scalar::BITS - poly_size.log2().0 - 2 + lut_count_log.0;
    // Do the rounding
    output += Scalar::ONE;
    // Finish the right shift
    output >>= 1;
    // Apply the lsb padding
    output <<= lut_count_log.0;
    <Scalar as CastInto<usize>>::cast_into(output)
}

pub trait FourierBootstrapKey<Scalar: UnsignedInteger> {
    type Fft;

    fn new_fft(polynomial_size: PolynomialSize) -> Self::Fft;

    fn new(
        input_lwe_dimension: LweDimension,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self;

    fn fill_with_forward_fourier_scratch(fft: &Self::Fft) -> Result<StackReq, SizeOverflow>;

    fn fill_with_forward_fourier<ContBsk>(
        &mut self,
        coef_bsk: &LweBootstrapKey<ContBsk>,
        fft: &Self::Fft,
        stack: PodStack<'_>,
    ) where
        ContBsk: Container<Element = Scalar>;

    fn bootstrap_scratch(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        fft: &Self::Fft,
    ) -> Result<StackReq, SizeOverflow>;

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
        ContAcc: Container<Element = Scalar>;
}

#[cfg(test)]
pub mod tests {
    pub(crate) use crate::core_crypto::algorithms::test::gen_keys_or_get_from_cache_if_enabled;

    use crate::core_crypto::algorithms::test::{FftBootstrapKeys, FftTestParams, TestResources};
    use crate::core_crypto::commons::numeric::Numeric;
    use crate::core_crypto::fft_impl::common::FourierBootstrapKey;
    use crate::core_crypto::keycache::KeyCacheAccess;
    use crate::core_crypto::prelude::*;
    use dyn_stack::{GlobalPodBuffer, PodStack};
    use serde::de::DeserializeOwned;
    use serde::Serialize;

    pub fn generate_keys<
        Scalar: UnsignedTorus
            + Sync
            + Send
            + CastFrom<usize>
            + CastInto<usize>
            + Serialize
            + DeserializeOwned,
    >(
        params: FftTestParams<Scalar>,
        rsc: &mut TestResources,
    ) -> FftBootstrapKeys<Scalar> {
        // Generate an LweSecretKey with binary coefficients
        let small_lwe_sk = LweSecretKey::generate_new_binary(
            params.lwe_dimension,
            &mut rsc.secret_random_generator,
        );

        // Generate a GlweSecretKey with binary coefficients
        let glwe_sk = GlweSecretKey::generate_new_binary(
            params.glwe_dimension,
            params.polynomial_size,
            &mut rsc.secret_random_generator,
        );

        // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
        let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        let bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            params.pbs_base_log,
            params.pbs_level,
            params.glwe_modular_std_dev,
            params.ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        FftBootstrapKeys {
            small_lwe_sk,
            big_lwe_sk,
            bsk,
        }
    }

    pub fn test_bootstrap_generic<Scalar, K>(params: FftTestParams<Scalar>)
    where
        Scalar: Numeric
            + UnsignedTorus
            + CastFrom<usize>
            + CastInto<usize>
            + Send
            + Sync
            + Serialize
            + DeserializeOwned,
        K: FourierBootstrapKey<Scalar>,
        FftTestParams<Scalar>: KeyCacheAccess<Keys = FftBootstrapKeys<Scalar>>,
    {
        let lwe_modular_std_dev = params.lwe_modular_std_dev;
        let glwe_dimension = params.glwe_dimension;
        let polynomial_size = params.polynomial_size;
        let ciphertext_modulus = params.ciphertext_modulus;

        let mut rsc = TestResources::new();

        let fft = K::new_fft(polynomial_size);

        let mut keys_gen = |params| generate_keys(params, &mut rsc);
        let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
        let (std_bootstrapping_key, small_lwe_sk, big_lwe_sk) =
            (keys.bsk, keys.small_lwe_sk, keys.big_lwe_sk);

        // Create the empty bootstrapping key in the Fourier domain
        let mut fourier_bsk = K::new(
            std_bootstrapping_key.input_lwe_dimension(),
            std_bootstrapping_key.polynomial_size(),
            std_bootstrapping_key.glwe_size(),
            std_bootstrapping_key.decomposition_base_log(),
            std_bootstrapping_key.decomposition_level_count(),
        );

        fourier_bsk.fill_with_forward_fourier(
            &std_bootstrapping_key,
            &fft,
            PodStack::new(&mut GlobalPodBuffer::new(
                K::fill_with_forward_fourier_scratch(&fft).unwrap(),
            )),
        );

        // Our 4 bits message space
        let message_modulus: Scalar = Scalar::ONE << 4;

        // Our input message
        let input_message: Scalar = 3usize.cast_into();

        // Delta used to encode 4 bits of message + a bit of padding on Scalar
        let delta: Scalar = (Scalar::ONE << (Scalar::BITS - 1)) / message_modulus;

        // Apply our encoding
        let plaintext = Plaintext(input_message * delta);

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &small_lwe_sk,
            plaintext,
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        // Here we will define a helper function to generate an accumulator for a PBS
        fn generate_accumulator<Scalar: Numeric + UnsignedTorus + CastFrom<usize>, F>(
            polynomial_size: PolynomialSize,
            glwe_size: GlweSize,
            message_modulus: usize,
            ciphertext_modulus: CiphertextModulus<Scalar>,
            delta: Scalar,
            f: F,
        ) -> GlweCiphertextOwned<Scalar>
        where
            F: Fn(Scalar) -> Scalar,
        {
            // N/(p/2) = size of each block, to correct noise from the input we introduce the notion
            // of box, which manages redundancy to yield a denoised value for several
            // noisy values around a true input value.
            let box_size = polynomial_size.0 / message_modulus;

            // Create the accumulator
            let mut accumulator_scalar: Vec<Scalar> = vec![Scalar::ZERO; polynomial_size.0];

            // Fill each box with the encoded denoised value
            for i in 0..message_modulus {
                let index = i * box_size;
                accumulator_scalar[index..index + box_size]
                    .iter_mut()
                    .for_each(|a| *a = f(i.cast_into()) * delta);
            }

            let half_box_size = box_size / 2;

            // Negate the first half_box_size coefficients to manage negacyclicity and rotate
            for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
                *a_i = (*a_i).wrapping_neg();
            }

            // Rotate the accumulator
            accumulator_scalar.rotate_left(half_box_size);

            let accumulator_plaintext = PlaintextList::from_container(accumulator_scalar);

            allocate_and_trivially_encrypt_new_glwe_ciphertext(
                glwe_size,
                &accumulator_plaintext,
                ciphertext_modulus,
            )
        }

        let f = |x: Scalar| x;
        let accumulator: GlweCiphertextOwned<Scalar> = generate_accumulator(
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            message_modulus.cast_into(),
            ciphertext_modulus,
            delta,
            f,
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut pbs_ct: LweCiphertext<Vec<Scalar>> = LweCiphertext::new(
            Scalar::ZERO,
            big_lwe_sk.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );
        println!("Computing PBS...");

        fourier_bsk.bootstrap(
            &mut pbs_ct,
            &lwe_ciphertext_in,
            &accumulator,
            &fft,
            PodStack::new(&mut GlobalPodBuffer::new(
                K::bootstrap_scratch(
                    std_bootstrapping_key.glwe_size(),
                    std_bootstrapping_key.polynomial_size(),
                    &fft,
                )
                .unwrap(),
            )),
        );

        // Decrypt the PBS result
        let pbs_plaintext: Plaintext<Scalar> = decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_ct);

        // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
        // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want
        // to round the 5 MSB, 1 bit of padding plus our 4 bits of message
        let signed_decomposer =
            SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

        // Round and remove our encoding
        let pbs_result: Scalar = signed_decomposer.closest_representable(pbs_plaintext.0) / delta;

        println!("Checking result...");
        assert_eq!(f(input_message), pbs_result);
    }
}
