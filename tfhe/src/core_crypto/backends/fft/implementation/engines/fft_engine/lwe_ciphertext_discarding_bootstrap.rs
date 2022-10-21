use super::{FftEngine, FftError};
use crate::core_crypto::backends::fft::private::crypto::bootstrap::bootstrap_scratch;
use crate::core_crypto::backends::fft::private::math::fft::Fft;
use crate::core_crypto::commons::math::tensor::{AsMutSlice, AsRefSlice};
use crate::core_crypto::prelude::{
    FftFourierLweBootstrapKey32, FftFourierLweBootstrapKey64, GlweCiphertext32, GlweCiphertext64,
    GlweCiphertextEntity, GlweCiphertextView32, GlweCiphertextView64, LweCiphertext32,
    LweCiphertext64, LweCiphertextDiscardingBootstrapEngine, LweCiphertextDiscardingBootstrapError,
    LweCiphertextMutView32, LweCiphertextMutView64, LweCiphertextView32, LweCiphertextView64,
};

impl From<FftError> for LweCiphertextDiscardingBootstrapError<FftError> {
    fn from(err: FftError) -> Self {
        Self::Engine(err)
    }
}

/// # Description
///
/// Implementation of [`LweCiphertextDiscardingBootstrapEngine`] for [`FftEngine`] that operates
/// on 32 bit integers.
impl
    LweCiphertextDiscardingBootstrapEngine<
        FftFourierLweBootstrapKey32,
        GlweCiphertext32,
        LweCiphertext32,
        LweCiphertext32,
    > for FftEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(4),
    ///     LweDimension(1024),
    ///     GlweDimension(1),
    ///     PolynomialSize(1024),
    /// );
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// // A constant function is applied during the bootstrap
    /// let lut = vec![8_u32 << 20; poly_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let lwe_sk: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey32 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    /// let bsk: FftFourierLweBootstrapKey32 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let lwe_sk_output: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(lwe_dim_output)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector_from(&lut)?;
    /// let acc = default_engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dim.to_glwe_size(), &plaintext_vector)?;
    /// let input = default_engine.encrypt_lwe_ciphertext(&lwe_sk, &plaintext, noise)?;
    /// let mut output = default_engine.zero_encrypt_lwe_ciphertext(&lwe_sk_output, noise)?;
    ///
    /// fft_engine.discard_bootstrap_lwe_ciphertext(&mut output, &input, &acc, &bsk)?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
        acc: &GlweCiphertext32,
        bsk: &FftFourierLweBootstrapKey32,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<Self::EngineError>> {
        FftError::perform_fft_checks(acc.polynomial_size())?;
        LweCiphertextDiscardingBootstrapError::perform_generic_checks(output, input, acc, bsk)?;
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
        acc: &GlweCiphertext32,
        bsk: &FftFourierLweBootstrapKey32,
    ) {
        let fft = Fft::new(acc.0.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            bootstrap_scratch::<u32>(acc.0.size(), acc.0.polynomial_size(), fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        bsk.0.as_view().bootstrap(
            output.0.tensor.as_mut_slice(),
            input.0.tensor.as_slice(),
            acc.0.as_view(),
            fft,
            self.stack(),
        );
    }
}

/// # Description
///
/// Implementation of [`LweCiphertextDiscardingBootstrapEngine`] for [`FftEngine`] that operates
/// on 64 bit integers.
impl
    LweCiphertextDiscardingBootstrapEngine<
        FftFourierLweBootstrapKey64,
        GlweCiphertext64,
        LweCiphertext64,
        LweCiphertext64,
    > for FftEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(4),
    ///     LweDimension(1024),
    ///     GlweDimension(1),
    ///     PolynomialSize(1024),
    /// );
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// // A constant function is applied during the bootstrap
    /// let lut = vec![8_u64 << 50; poly_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey64 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    /// let bsk: FftFourierLweBootstrapKey64 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let lwe_sk_output: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(lwe_dim_output)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector_from(&lut)?;
    /// let acc = default_engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dim.to_glwe_size(), &plaintext_vector)?;
    /// let input = default_engine.encrypt_lwe_ciphertext(&lwe_sk, &plaintext, noise)?;
    /// let mut output = default_engine.zero_encrypt_lwe_ciphertext(&lwe_sk_output, noise)?;
    ///
    /// fft_engine.discard_bootstrap_lwe_ciphertext(&mut output, &input, &acc, &bsk)?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        acc: &GlweCiphertext64,
        bsk: &FftFourierLweBootstrapKey64,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<Self::EngineError>> {
        FftError::perform_fft_checks(acc.polynomial_size())?;
        LweCiphertextDiscardingBootstrapError::perform_generic_checks(output, input, acc, bsk)?;
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        acc: &GlweCiphertext64,
        bsk: &FftFourierLweBootstrapKey64,
    ) {
        let fft = Fft::new(acc.0.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            bootstrap_scratch::<u64>(acc.0.size(), acc.0.polynomial_size(), fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        bsk.0.as_view().bootstrap(
            output.0.tensor.as_mut_slice(),
            input.0.tensor.as_slice(),
            acc.0.as_view(),
            fft,
            self.stack(),
        );
    }
}

/// # Description
///
/// Implementation of [`LweCiphertextDiscardingBootstrapEngine`] for [`FftEngine`] that operates
/// on 32 bit integers.
impl
    LweCiphertextDiscardingBootstrapEngine<
        FftFourierLweBootstrapKey32,
        GlweCiphertextView32<'_>,
        LweCiphertextView32<'_>,
        LweCiphertextMutView32<'_>,
    > for FftEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// use tfhe::core_crypto::backends::fft::engines::FftEngine;
    /// use tfhe::core_crypto::backends::fft::entities::FftFourierLweBootstrapKey32;
    /// let input = 3_u32 << 20;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(4),
    ///     LweDimension(1024),
    ///     GlweDimension(1),
    ///     PolynomialSize(1024),
    /// );
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// // A constant function is applied during the bootstrap
    /// let lut = vec![8_u32 << 20; poly_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let lwe_sk: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey32 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    /// let bsk: FftFourierLweBootstrapKey32 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let lwe_sk_output: LweSecretKey32 =
    ///     default_engine.generate_new_lwe_secret_key(lwe_dim_output)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector_from(&lut)?;
    /// let acc = default_engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dim.to_glwe_size(), &plaintext_vector)?;
    ///
    /// // Get the GlweCiphertext as a View
    /// let raw_glwe = default_engine.consume_retrieve_glwe_ciphertext(acc)?;
    /// let acc: GlweCiphertextView32 =
    ///     default_engine.create_glwe_ciphertext_from(&raw_glwe[..], poly_size)?;
    ///
    /// let mut raw_input_container = vec![0_u32; lwe_sk.lwe_dimension().to_lwe_size().0];
    /// let input: LweCiphertextMutView32 =
    ///     default_engine.create_lwe_ciphertext_from(&mut raw_input_container[..])?;
    /// let input = default_engine.encrypt_lwe_ciphertext(&lwe_sk, &plaintext, noise)?;
    ///
    /// // Convert MutView to View
    /// let raw_input = default_engine.consume_retrieve_lwe_ciphertext(input)?;
    /// let input = default_engine.create_lwe_ciphertext_from(&raw_input[..])?;
    ///
    /// let mut raw_output_container = vec![0_u32; lwe_sk_output.lwe_dimension().to_lwe_size().0];
    /// let mut output = default_engine.create_lwe_ciphertext_from(&mut raw_output_container[..])?;
    ///
    /// fft_engine.discard_bootstrap_lwe_ciphertext(&mut output, &input, &acc, &bsk)?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextMutView32,
        input: &LweCiphertextView32,
        acc: &GlweCiphertextView32,
        bsk: &FftFourierLweBootstrapKey32,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<Self::EngineError>> {
        FftError::perform_fft_checks(acc.polynomial_size())?;
        LweCiphertextDiscardingBootstrapError::perform_generic_checks(output, input, acc, bsk)?;
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView32,
        input: &LweCiphertextView32,
        acc: &GlweCiphertextView32,
        bsk: &FftFourierLweBootstrapKey32,
    ) {
        let fft = Fft::new(acc.0.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            bootstrap_scratch::<u32>(acc.0.size(), acc.0.polynomial_size(), fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        bsk.0.as_view().bootstrap(
            output.0.tensor.as_mut_slice(),
            input.0.tensor.as_slice(),
            acc.0.as_view(),
            fft,
            self.stack(),
        );
    }
}

/// # Description
///
/// Implementation of [`LweCiphertextDiscardingBootstrapEngine`] for [`FftEngine`] that operates
/// on 64 bit integers.
impl
    LweCiphertextDiscardingBootstrapEngine<
        FftFourierLweBootstrapKey64,
        GlweCiphertextView64<'_>,
        LweCiphertextView64<'_>,
        LweCiphertextMutView64<'_>,
    > for FftEngine
{
    /// # Example
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// use tfhe::core_crypto::backends::fft::engines::FftEngine;
    /// use tfhe::core_crypto::backends::fft::entities::FftFourierLweBootstrapKey32;
    /// let input = 3_u64 << 20;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(4),
    ///     LweDimension(1024),
    ///     GlweDimension(1),
    ///     PolynomialSize(1024),
    /// );
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// // A constant function is applied during the bootstrap
    /// let lut = vec![8_u64 << 20; poly_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    /// let lwe_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey64 =
    ///     default_engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    /// let bsk: FftFourierLweBootstrapKey64 = fft_engine.convert_lwe_bootstrap_key(&bsk)?;
    /// let lwe_sk_output: LweSecretKey64 =
    ///     default_engine.generate_new_lwe_secret_key(lwe_dim_output)?;
    /// let plaintext = default_engine.create_plaintext_from(&input)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector_from(&lut)?;
    /// let acc = default_engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dim.to_glwe_size(), &plaintext_vector)?;
    ///
    /// // Get the GlweCiphertext as a View
    /// let raw_glwe = default_engine.consume_retrieve_glwe_ciphertext(acc)?;
    /// let acc: GlweCiphertextView64 =
    ///     default_engine.create_glwe_ciphertext_from(&raw_glwe[..], poly_size)?;
    ///
    /// let mut raw_input_container = vec![0_u64; lwe_sk.lwe_dimension().to_lwe_size().0];
    /// let input: LweCiphertextMutView64 =
    ///     default_engine.create_lwe_ciphertext_from(&mut raw_input_container[..])?;
    /// let input = default_engine.encrypt_lwe_ciphertext(&lwe_sk, &plaintext, noise)?;
    ///
    /// // Convert MutView to View
    /// let raw_input = default_engine.consume_retrieve_lwe_ciphertext(input)?;
    /// let input = default_engine.create_lwe_ciphertext_from(&raw_input[..])?;
    ///
    /// let mut raw_output_container = vec![0_u64; lwe_sk_output.lwe_dimension().to_lwe_size().0];
    /// let mut output = default_engine.create_lwe_ciphertext_from(&mut raw_output_container[..])?;
    ///
    /// fft_engine.discard_bootstrap_lwe_ciphertext(&mut output, &input, &acc, &bsk)?;
    /// #
    /// assert_eq!(output.lwe_dimension(), lwe_dim_output);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertextMutView64,
        input: &LweCiphertextView64,
        acc: &GlweCiphertextView64,
        bsk: &FftFourierLweBootstrapKey64,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<Self::EngineError>> {
        FftError::perform_fft_checks(acc.polynomial_size())?;
        LweCiphertextDiscardingBootstrapError::perform_generic_checks(output, input, acc, bsk)?;
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertextMutView64,
        input: &LweCiphertextView64,
        acc: &GlweCiphertextView64,
        bsk: &FftFourierLweBootstrapKey64,
    ) {
        let fft = Fft::new(acc.0.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            bootstrap_scratch::<u64>(acc.0.size(), acc.0.polynomial_size(), fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        bsk.0.as_view().bootstrap(
            output.0.tensor.as_mut_slice(),
            input.0.tensor.as_slice(),
            acc.0.as_view(),
            fft,
            self.stack(),
        );
    }
}

#[cfg(test)]
mod unit_test_pbs {
    use crate::core_crypto::commons::test_tools::new_random_generator;
    use crate::core_crypto::prelude::*;
    use std::error::Error;

    fn generate_accumulator_with_engine<F>(
        engine: &mut DefaultEngine,
        bootstrapping_key: &FftFourierLweBootstrapKey64,
        message_modulus: usize,
        carry_modulus: usize,
        f: F,
    ) -> Result<GlweCiphertext64, Box<dyn Error>>
    where
        F: Fn(u64) -> u64,
    {
        // Modulus of the msg contained in the msg bits and operations buffer
        let modulus_sup = message_modulus * carry_modulus;

        // N/(p/2) = size of each block
        let box_size = bootstrapping_key.polynomial_size().0 / modulus_sup;

        // Value of the shift we multiply our messages by
        let delta = (1_u64 << 63) / (modulus_sup) as u64;

        // Create the accumulator
        let mut accumulator_u64 = vec![0_u64; bootstrapping_key.polynomial_size().0];

        // This accumulator extracts the carry bits
        for i in 0..modulus_sup {
            let index = i as usize * box_size;
            accumulator_u64[index..index + box_size]
                .iter_mut()
                .for_each(|a| *a = f(i as u64) * delta);
        }

        let half_box_size = box_size / 2;

        // Negate the first half_box_size coefficients
        for a_i in accumulator_u64[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        // Rotate the accumulator
        accumulator_u64.rotate_left(half_box_size);

        // Everywhere
        let accumulator_plaintext = engine.create_plaintext_vector_from(&accumulator_u64)?;

        let accumulator = engine.trivially_encrypt_glwe_ciphertext(
            bootstrapping_key.glwe_dimension().to_glwe_size(),
            &accumulator_plaintext,
        )?;

        Ok(accumulator)
    }

    #[test]
    fn test_pbs() -> Result<(), Box<dyn Error>> {
        // Shortint 2_2 params
        let lwe_dimension = LweDimension(742);
        let glwe_dimension = GlweDimension(1);
        let polynomial_size = PolynomialSize(2048);
        let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
        let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
        let pbs_base_log = DecompositionBaseLog(23);
        let pbs_level = DecompositionLevelCount(1);
        let message_modulus: usize = 4;
        let carry_modulus: usize = 4;

        let payload_modulus = (message_modulus * carry_modulus) as u64;

        // Value of the shift we multiply our messages by
        let delta = (1_u64 << 63) / payload_modulus;

        // Unix seeder must be given a secret input.
        // Here we just give it 0, which is totally unsafe.
        const UNSAFE_SECRET: u128 = 0;

        let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
        let mut fft_engine = FftEngine::new(())?;

        let mut default_parallel_engine =
            DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;

        let repetitions = 10;
        let samples = 100;

        let mut error_sample_vec = Vec::<u64>::with_capacity(repetitions * samples);

        let mut generator = new_random_generator();

        for _ in 0..repetitions {
            // Generate client-side keys

            // generate the lwe secret key
            let small_lwe_secret_key: LweSecretKey64 =
                default_engine.generate_new_lwe_secret_key(lwe_dimension)?;

            // generate the rlwe secret key
            let glwe_secret_key: GlweSecretKey64 =
                default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;

            let large_lwe_secret_key = default_engine
                .transform_glwe_secret_key_to_lwe_secret_key(glwe_secret_key.clone())?;

            // Convert into a variance for rlwe context
            let var_rlwe = Variance(glwe_modular_std_dev.get_variance());

            let bootstrap_key: LweBootstrapKey64 = default_parallel_engine
                .generate_new_lwe_bootstrap_key(
                    &small_lwe_secret_key,
                    &glwe_secret_key,
                    pbs_base_log,
                    pbs_level,
                    var_rlwe,
                )?;

            // Creation of the bootstrapping key in the Fourier domain

            let fourier_bsk: FftFourierLweBootstrapKey64 =
                fft_engine.convert_lwe_bootstrap_key(&bootstrap_key)?;

            let accumulator = generate_accumulator_with_engine(
                &mut default_engine,
                &fourier_bsk,
                message_modulus,
                carry_modulus,
                |x| x,
            )?;

            // convert into a variance
            let var_lwe = Variance(lwe_modular_std_dev.get_variance());

            for _ in 0..samples {
                let input_plaintext: u64 =
                    (generator.random_uniform::<u64>() % payload_modulus) << delta;

                let plaintext = default_engine.create_plaintext_from(&input_plaintext)?;
                let input = default_engine.encrypt_lwe_ciphertext(
                    &small_lwe_secret_key,
                    &plaintext,
                    var_lwe,
                )?;

                let mut output =
                    default_engine.zero_encrypt_lwe_ciphertext(&large_lwe_secret_key, var_lwe)?;

                fft_engine.discard_bootstrap_lwe_ciphertext(
                    &mut output,
                    &input,
                    &accumulator,
                    &fourier_bsk,
                )?;

                // decryption
                let decrypted =
                    default_engine.decrypt_lwe_ciphertext(&large_lwe_secret_key, &output)?;

                if decrypted == plaintext {
                    panic!("Equal {decrypted:?}, {plaintext:?}");
                }

                let mut decrypted_u64: u64 = 0;
                default_engine.discard_retrieve_plaintext(&mut decrypted_u64, &decrypted)?;

                // let err = if decrypted_u64 >= input_plaintext {
                //     decrypted_u64 - input_plaintext
                // } else {
                //     input_plaintext - decrypted_u64
                // };

                let err = {
                    let d0 = decrypted_u64.wrapping_sub(input_plaintext);
                    let d1 = input_plaintext.wrapping_sub(decrypted_u64);
                    std::cmp::min(d0, d1)
                };

                // let err = torus_modular_distance(input_plaintext, decrypted_u64);

                error_sample_vec.push(err);

                //The bit before the message
                let rounding_bit = delta >> 1;

                //compute the rounding bit
                let rounding = (decrypted_u64 & rounding_bit) << 1;

                let decoded = (decrypted_u64.wrapping_add(rounding)) / delta;

                assert_eq!(decoded, input_plaintext / delta);
            }
        }

        error_sample_vec.sort();

        let bit_errors: Vec<_> = error_sample_vec
            .iter()
            .map(|&x| if x != 0 { 63 - x.leading_zeros() } else { 0 })
            .collect();

        let mean_bit_errors: u32 = bit_errors.iter().sum::<u32>() / bit_errors.len() as u32;
        let mean_bit_errors_f64: f64 =
            bit_errors.iter().map(|&x| x as f64).sum::<f64>() as f64 / bit_errors.len() as f64;

        for (idx, (&val, &bit_error)) in error_sample_vec.iter().zip(bit_errors.iter()).enumerate()
        {
            println!("#{idx}: Error {val}, bit_error {bit_error}");
        }

        println!("Mean bit error: {mean_bit_errors}");
        println!("Mean bit error f64: {mean_bit_errors_f64}");

        Ok(())
    }
}
