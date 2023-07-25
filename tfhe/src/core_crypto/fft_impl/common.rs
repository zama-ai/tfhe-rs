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
/// offset: the number of msb discarded
/// lut_count_log: the right padding
pub fn pbs_modulus_switch<Scalar: UnsignedTorus + CastInto<usize>>(
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
    output += output & Scalar::ONE;
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
    use crate::core_crypto::commons::numeric::Numeric;
    use crate::core_crypto::fft_impl::common::FourierBootstrapKey;
    use crate::core_crypto::prelude::*;
    use dyn_stack::{GlobalPodBuffer, PodStack};

    pub fn test_bootstrap_generic<
        Scalar: Numeric + UnsignedTorus + CastFrom<usize> + CastInto<usize> + Send + Sync,
        K: FourierBootstrapKey<Scalar>,
    >(
        lwe_modular_std_dev: StandardDev,
        glwe_modular_std_dev: StandardDev,
    ) {
        // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
        // computations
        // Define the parameters for a 4 bits message able to hold the doubled 2 bits message
        let small_lwe_dimension = LweDimension(742);
        let glwe_dimension = GlweDimension(1);
        let polynomial_size = PolynomialSize(2048);
        let pbs_base_log = DecompositionBaseLog(23);
        let pbs_level = DecompositionLevelCount(1);
        let ciphertext_modulus = CiphertextModulus::new_native();

        // Request the best seeder possible, starting with hardware entropy sources and falling back
        // to /dev/random on Unix systems if enabled via cargo features
        let mut boxed_seeder = new_seeder();
        // Get a mutable reference to the seeder as a trait object from the Box returned by
        // new_seeder
        let seeder = boxed_seeder.as_mut();

        // Create a generator which uses a CSPRNG to generate secret keys
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
        // noise
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        println!("Generating keys...");

        // Generate an LweSecretKey with binary coefficients
        let small_lwe_sk =
            LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

        // Generate a GlweSecretKey with binary coefficients
        let glwe_sk = GlweSecretKey::generate_new_binary(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );

        // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
        let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            pbs_base_log,
            pbs_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        // Create the empty bootstrapping key in the Fourier domain
        let mut fourier_bsk = K::new(
            std_bootstrapping_key.input_lwe_dimension(),
            std_bootstrapping_key.polynomial_size(),
            std_bootstrapping_key.glwe_size(),
            std_bootstrapping_key.decomposition_base_log(),
            std_bootstrapping_key.decomposition_level_count(),
        );

        let fft = K::new_fft(polynomial_size);
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
            &mut encryption_generator,
        );

        // Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
        // doing this operation in terms of performance as it's much more costly than a
        // multiplication with a cleartext, however it resets the noise in a ciphertext to a
        // nominal level and allows to evaluate arbitrary functions so depending on your use
        // case it can be a better fit.

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

        let f = |x: Scalar| Scalar::TWO * x;
        let accumulator: GlweCiphertextOwned<Scalar> = generate_accumulator(
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            message_modulus.cast_into(),
            ciphertext_modulus,
            delta,
            f,
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut pbs_multiplication_ct: LweCiphertext<Vec<Scalar>> = LweCiphertext::new(
            Scalar::ZERO,
            big_lwe_sk.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );
        println!("Computing PBS...");

        fourier_bsk.bootstrap(
            &mut pbs_multiplication_ct,
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

        // Decrypt the PBS multiplication result
        let pbs_multiplication_plaintext: Plaintext<Scalar> =
            decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);

        // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
        // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want
        // to round the 5 MSB, 1 bit of padding plus our 4 bits of message
        let signed_decomposer =
            SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

        // Round and remove our encoding
        let pbs_multiplication_result: Scalar =
            signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;

        println!("Checking result...");
        assert_eq!(f(input_message), pbs_multiplication_result);
        println!(
            "Mulitplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
        );
    }
}
