use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
};
use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{CastInto, CiphertextModulusLog, ContainerMut};
use dyn_stack::{PodStack, SizeOverflow, StackReq};

pub fn pbs_modulus_switch<Scalar: UnsignedInteger + CastInto<usize>>(
    input: Scalar,
    polynomial_size: PolynomialSize,
) -> usize {
    modulus_switch(input, polynomial_size.to_blind_rotation_input_modulus_log()).cast_into()
}

pub fn modulus_switch<Scalar: UnsignedInteger>(
    input: Scalar,
    log_modulus: CiphertextModulusLog,
) -> Scalar {
    // Flooring output_to_floor is equivalent to rounding the input
    let output_to_floor = input.wrapping_add(Scalar::ONE << (Scalar::BITS - log_modulus.0 - 1));

    output_to_floor >> (Scalar::BITS - log_modulus.0)
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
        stack: &mut PodStack,
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
        stack: &mut PodStack,
    ) where
        ContLweOut: ContainerMut<Element = Scalar>,
        ContLweIn: Container<Element = Scalar>,
        ContAcc: Container<Element = Scalar>;
}

#[cfg(test)]
pub mod tests {
    pub(crate) use crate::core_crypto::algorithms::test::gen_keys_or_get_from_cache_if_enabled;

    use crate::core_crypto::algorithms::test::{FftBootstrapKeys, FftTestParams, TestResources};
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
            params.glwe_noise_distribution,
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
        let lwe_noise_distribution = params.lwe_noise_distribution;
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
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        let f = |x: Scalar| x;
        let accumulator: GlweCiphertextOwned<Scalar> = generate_programmable_bootstrap_glwe_lut(
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
