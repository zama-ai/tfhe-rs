use crate::core_crypto::backends::default::entities::{
    LweCiphertextVectorMutView32, LweCiphertextVectorMutView64, LweCiphertextVectorView32,
    LweCiphertextVectorView64, LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64, PlaintextVector32,
    PlaintextVector64,
};
use crate::core_crypto::backends::fft::engines::{FftEngine, FftError};
use crate::core_crypto::backends::fft::entities::{
    FftFourierLweBootstrapKey32, FftFourierLweBootstrapKey64,
};
use crate::core_crypto::backends::fft::private::crypto::wop_pbs::{
    circuit_bootstrap_boolean_vertical_packing, circuit_bootstrap_boolean_vertical_packing_scratch,
};
use crate::core_crypto::backends::fft::private::math::fft::Fft;
use crate::core_crypto::commons::math::polynomial::PolynomialList;
use crate::core_crypto::commons::math::tensor::{AsRefSlice, AsRefTensor};
use crate::core_crypto::prelude::{
    CiphertextCount, LweCiphertextVectorEntity,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity, PlaintextVectorEntity,
    PolynomialCount,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingEngine,
    LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError,
};
use crate::core_crypto::specification::entities::LweBootstrapKeyEntity;
use crate::core_crypto::specification::parameters::{
    DecompositionBaseLog, DecompositionLevelCount,
};

impl From<FftError>
    for LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError<FftError>
{
    fn from(err: FftError) -> Self {
        Self::Engine(err)
    }
}

impl
    LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingEngine<
        LweCiphertextVectorView32<'_>,
        LweCiphertextVectorMutView32<'_>,
        FftFourierLweBootstrapKey32,
        PlaintextVector32,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    > for FftEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let polynomial_size = PolynomialSize(1024);
    /// let glwe_dimension = GlweDimension(1);
    /// let lwe_dimension = LweDimension(481);
    ///
    /// let var_small = Variance::from_variance(2f64.powf(-70.0));
    /// let var_big = Variance::from_variance(2f64.powf(-60.0));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut default_parallel_engine =
    ///     DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    ///
    /// let glwe_sk: GlweSecretKey32 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let lwe_small_sk: LweSecretKey32 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let lwe_big_sk: LweSecretKey32 =
    ///     default_engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_sk.clone())?;
    ///
    /// let bsk_level_count = DecompositionLevelCount(7);
    /// let bsk_base_log = DecompositionBaseLog(4);
    ///
    /// let std_bsk: LweBootstrapKey32 = default_parallel_engine.generate_new_lwe_bootstrap_key(
    ///     &lwe_small_sk,
    ///     &glwe_sk,
    ///     bsk_base_log,
    ///     bsk_level_count,
    ///     var_small,
    /// )?;
    ///
    /// let fourier_bsk: FftFourierLweBootstrapKey32 =
    ///     fft_engine.convert_lwe_bootstrap_key(&std_bsk)?;
    ///
    /// let ksk_level_count = DecompositionLevelCount(9);
    /// let ksk_base_log = DecompositionBaseLog(1);
    ///
    /// let ksk_big_to_small: LweKeyswitchKey32 = default_engine.generate_new_lwe_keyswitch_key(
    ///     &lwe_big_sk,
    ///     &lwe_small_sk,
    ///     ksk_level_count,
    ///     ksk_base_log,
    ///     var_big,
    /// )?;
    ///
    /// let pfpksk_level_count = DecompositionLevelCount(7);
    /// let pfpksk_base_log = DecompositionBaseLog(4);
    ///
    /// let cbs_pfpksk: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32 = default_engine
    ///     .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
    ///         &lwe_big_sk,
    ///         &glwe_sk,
    ///         pfpksk_base_log,
    ///         pfpksk_level_count,
    ///         var_small,
    ///     )?;
    ///
    /// // We will have a message with 10 bits of information
    /// let message_bits = 10;
    /// let bits_to_extract = ExtractedBitsCount(message_bits);
    ///
    /// // The value we encrypt is 42, we will extract the bits of this value and apply the
    /// // circuit bootstrapping followed by the vertical packing on the extracted bits.
    /// let cleartext = 42;
    /// let delta_log_msg = DeltaLog(32 - message_bits);
    ///
    /// let encoded_message = default_engine.create_plaintext_from(&(cleartext << delta_log_msg.0))?;
    /// let lwe_in = default_engine.encrypt_lwe_ciphertext(&lwe_big_sk, &encoded_message, var_big)?;
    ///
    /// // Bit extraction output, use the zero_encrypt engine to allocate a ciphertext vector
    /// let mut bit_extraction_output = default_engine.zero_encrypt_lwe_ciphertext_vector(
    ///     &lwe_small_sk,
    ///     var_small,
    ///     LweCiphertextCount(bits_to_extract.0),
    /// )?;
    ///
    /// fft_engine.discard_extract_bits_lwe_ciphertext(
    ///     &mut bit_extraction_output,
    ///     &lwe_in,
    ///     &fourier_bsk,
    ///     &ksk_big_to_small,
    ///     bits_to_extract,
    ///     delta_log_msg,
    /// )?;
    ///
    /// // Though the delta log here is the same as the message delta log, in the general case they
    /// // are different, so we create two DeltaLog parameters
    /// let delta_log_lut = DeltaLog(32 - message_bits);
    ///
    /// // Create a look-up table we want to apply during vertical packing, here just the identity
    /// // with the proper encoding.
    /// // Note that this particular table will not trigger the cmux tree from the vertical packing,
    /// // adapt the LUT generation to your usage.
    /// // Here we apply a single look-up table as we output a single ciphertext.
    /// let number_of_luts_and_output_vp_ciphertexts = 1;
    /// let lut_size = 1 << bits_to_extract.0;
    /// let mut lut: Vec<u32> = Vec::with_capacity(lut_size);
    ///
    /// for i in 0..lut_size {
    ///     lut.push((i as u32 % (1 << message_bits)) << delta_log_lut.0);
    /// }
    ///
    /// let lut_as_plaintext_vector = default_engine.create_plaintext_vector_from(lut.as_slice())?;
    ///
    /// // We run on views, so we need a container for the output
    /// let mut output_cbs_vp_ct_container = vec![
    ///     0u32;
    ///     lwe_big_sk.lwe_dimension().to_lwe_size().0
    ///         * number_of_luts_and_output_vp_ciphertexts
    /// ];
    ///
    /// let mut output_cbs_vp_ct_mut_view: LweCiphertextVectorMutView32 = default_engine
    ///     .create_lwe_ciphertext_vector_from(
    ///         output_cbs_vp_ct_container.as_mut_slice(),
    ///         lwe_big_sk.lwe_dimension().to_lwe_size(),
    ///     )?;
    /// // And we need to get a view on the bits extracted earlier that serve as inputs to the
    /// // circuit bootstrap + vertical packing
    /// let extracted_bits_lwe_size = bit_extraction_output.lwe_dimension().to_lwe_size();
    /// let extracted_bits_container =
    ///     default_engine.consume_retrieve_lwe_ciphertext_vector(bit_extraction_output)?;
    /// let cbs_vp_input_vector_view: LweCiphertextVectorView32 = default_engine
    ///     .create_lwe_ciphertext_vector_from(
    ///         extracted_bits_container.as_slice(),
    ///         extracted_bits_lwe_size,
    ///     )?;
    ///
    /// let cbs_level_count = DecompositionLevelCount(4);
    /// let cbs_base_log = DecompositionBaseLog(6);
    ///
    /// fft_engine.discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector(
    ///     &mut output_cbs_vp_ct_mut_view,
    ///     &cbs_vp_input_vector_view,
    ///     &fourier_bsk,
    ///     &lut_as_plaintext_vector,
    ///     cbs_level_count,
    ///     cbs_base_log,
    ///     &cbs_pfpksk,
    /// )?;
    ///
    /// assert_eq!(output_cbs_vp_ct_mut_view.lwe_ciphertext_count().0, 1);
    /// assert_eq!(
    ///     output_cbs_vp_ct_mut_view.lwe_dimension(),
    ///     LweDimension(glwe_dimension.0 * polynomial_size.0)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVectorMutView32,
        input: &LweCiphertextVectorView32,
        bsk: &FftFourierLweBootstrapKey32,
        luts: &PlaintextVector32,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    ) -> Result<
        (),
        LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError<Self::EngineError>,
    > {
        FftError::perform_fft_checks(bsk.polynomial_size())?;
        LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError::
            perform_generic_checks(
                input,
                output,
                bsk,
                luts,
                cbs_level_count,
                cbs_base_log,
                cbs_pfpksk,
                32,
            )?;
        unsafe {
            self.discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector_unchecked(
            output,
            input,
            bsk,
            luts,
            cbs_level_count,
            cbs_base_log,
            cbs_pfpksk,
        );
        }
        Ok(())
    }

    unsafe fn discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVectorMutView32,
        input: &LweCiphertextVectorView32,
        bsk: &FftFourierLweBootstrapKey32,
        luts: &PlaintextVector32,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys32,
    ) {
        let lut_as_polynomial_list =
            PolynomialList::from_container(luts.0.as_tensor().as_slice(), bsk.polynomial_size());

        let fft = Fft::new(bsk.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            circuit_bootstrap_boolean_vertical_packing_scratch::<u32>(
                CiphertextCount(input.lwe_ciphertext_count().0),
                CiphertextCount(output.lwe_ciphertext_count().0),
                input.lwe_dimension().to_lwe_size(),
                PolynomialCount(luts.plaintext_count().0),
                bsk.output_lwe_dimension().to_lwe_size(),
                cbs_pfpksk.output_polynomial_size(),
                bsk.glwe_dimension().to_glwe_size(),
                cbs_level_count,
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        circuit_bootstrap_boolean_vertical_packing(
            lut_as_polynomial_list.as_view(),
            bsk.0.as_view(),
            output.0.as_mut_view(),
            input.0.as_view(),
            cbs_pfpksk.0.as_view(),
            cbs_level_count,
            cbs_base_log,
            fft,
            self.stack(),
        )
    }
}

impl
    LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingEngine<
        LweCiphertextVectorView64<'_>,
        LweCiphertextVectorMutView64<'_>,
        FftFourierLweBootstrapKey64,
        PlaintextVector64,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    > for FftEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let polynomial_size = PolynomialSize(1024);
    /// let glwe_dimension = GlweDimension(1);
    /// let lwe_dimension = LweDimension(481);
    ///
    /// let var_small = Variance::from_variance(2f64.powf(-80.0));
    /// let var_big = Variance::from_variance(2f64.powf(-70.0));
    ///
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut default_parallel_engine =
    ///     DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fft_engine = FftEngine::new(())?;
    ///
    /// let glwe_sk: GlweSecretKey64 =
    ///     default_engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let lwe_small_sk: LweSecretKey64 = default_engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let lwe_big_sk: LweSecretKey64 =
    ///     default_engine.transform_glwe_secret_key_to_lwe_secret_key(glwe_sk.clone())?;
    ///
    /// let bsk_level_count = DecompositionLevelCount(9);
    /// let bsk_base_log = DecompositionBaseLog(4);
    ///
    /// let std_bsk: LweBootstrapKey64 = default_parallel_engine.generate_new_lwe_bootstrap_key(
    ///     &lwe_small_sk,
    ///     &glwe_sk,
    ///     bsk_base_log,
    ///     bsk_level_count,
    ///     var_small,
    /// )?;
    ///
    /// let fourier_bsk: FftFourierLweBootstrapKey64 =
    ///     fft_engine.convert_lwe_bootstrap_key(&std_bsk)?;
    ///
    /// let ksk_level_count = DecompositionLevelCount(9);
    /// let ksk_base_log = DecompositionBaseLog(1);
    ///
    /// let ksk_big_to_small: LweKeyswitchKey64 = default_engine.generate_new_lwe_keyswitch_key(
    ///     &lwe_big_sk,
    ///     &lwe_small_sk,
    ///     ksk_level_count,
    ///     ksk_base_log,
    ///     var_big,
    /// )?;
    ///
    /// let pfpksk_level_count = DecompositionLevelCount(9);
    /// let pfpksk_base_log = DecompositionBaseLog(4);
    ///
    /// let cbs_pfpksk: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64 = default_engine
    ///     .generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
    ///         &lwe_big_sk,
    ///         &glwe_sk,
    ///         pfpksk_base_log,
    ///         pfpksk_level_count,
    ///         var_small,
    ///     )?;
    ///
    /// // We will have a message with 10 bits of information
    /// let message_bits = 10;
    /// let bits_to_extract = ExtractedBitsCount(message_bits);
    ///
    /// // The value we encrypt is 42, we will extract the bits of this value and apply the
    /// // circuit bootstrapping followed by the vertical packing on the extracted bits.
    /// let cleartext = 42;
    /// let delta_log_msg = DeltaLog(64 - message_bits);
    ///
    /// let encoded_message = default_engine.create_plaintext_from(&(cleartext << delta_log_msg.0))?;
    /// let lwe_in = default_engine.encrypt_lwe_ciphertext(&lwe_big_sk, &encoded_message, var_big)?;
    ///
    /// // Bit extraction output, use the zero_encrypt engine to allocate a ciphertext vector
    /// let mut bit_extraction_output = default_engine.zero_encrypt_lwe_ciphertext_vector(
    ///     &lwe_small_sk,
    ///     var_small,
    ///     LweCiphertextCount(bits_to_extract.0),
    /// )?;
    ///
    /// fft_engine.discard_extract_bits_lwe_ciphertext(
    ///     &mut bit_extraction_output,
    ///     &lwe_in,
    ///     &fourier_bsk,
    ///     &ksk_big_to_small,
    ///     bits_to_extract,
    ///     delta_log_msg,
    /// )?;
    ///
    /// // Though the delta log here is the same as the message delta log, in the general case they
    /// // are different, so we create two DeltaLog parameters
    /// let delta_log_lut = DeltaLog(64 - message_bits);
    ///
    /// // Create a look-up table we want to apply during vertical packing, here just the identity
    /// // with the proper encoding.
    /// // Note that this particular table will not trigger the cmux tree from the vertical packing,
    /// // adapt the LUT generation to your usage.
    /// // Here we apply a single look-up table as we output a single ciphertext.
    /// let number_of_luts_and_output_vp_ciphertexts = 1;
    /// let lut_size = 1 << bits_to_extract.0;
    /// let mut lut: Vec<u64> = Vec::with_capacity(lut_size);
    ///
    /// for i in 0..lut_size {
    ///     lut.push((i as u64 % (1 << message_bits)) << delta_log_lut.0);
    /// }
    ///
    /// let lut_as_plaintext_vector = default_engine.create_plaintext_vector_from(lut.as_slice())?;
    ///
    /// // We run on views, so we need a container for the output
    /// let mut output_cbs_vp_ct_container = vec![
    ///     0u64;
    ///     lwe_big_sk.lwe_dimension().to_lwe_size().0
    ///         * number_of_luts_and_output_vp_ciphertexts
    /// ];
    ///
    /// let mut output_cbs_vp_ct_mut_view: LweCiphertextVectorMutView64 = default_engine
    ///     .create_lwe_ciphertext_vector_from(
    ///         output_cbs_vp_ct_container.as_mut_slice(),
    ///         lwe_big_sk.lwe_dimension().to_lwe_size(),
    ///     )?;
    /// // And we need to get a view on the bits extracted earlier that serve as inputs to the
    /// // circuit bootstrap + vertical packing
    /// let extracted_bits_lwe_size = bit_extraction_output.lwe_dimension().to_lwe_size();
    /// let extracted_bits_container =
    ///     default_engine.consume_retrieve_lwe_ciphertext_vector(bit_extraction_output)?;
    /// let cbs_vp_input_vector_view: LweCiphertextVectorView64 = default_engine
    ///     .create_lwe_ciphertext_vector_from(
    ///         extracted_bits_container.as_slice(),
    ///         extracted_bits_lwe_size,
    ///     )?;
    ///
    /// let cbs_level_count = DecompositionLevelCount(4);
    /// let cbs_base_log = DecompositionBaseLog(6);
    ///
    /// fft_engine.discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector(
    ///     &mut output_cbs_vp_ct_mut_view,
    ///     &cbs_vp_input_vector_view,
    ///     &fourier_bsk,
    ///     &lut_as_plaintext_vector,
    ///     cbs_level_count,
    ///     cbs_base_log,
    ///     &cbs_pfpksk,
    /// )?;
    ///
    /// assert_eq!(output_cbs_vp_ct_mut_view.lwe_ciphertext_count().0, 1);
    /// assert_eq!(
    ///     output_cbs_vp_ct_mut_view.lwe_dimension(),
    ///     LweDimension(glwe_dimension.0 * polynomial_size.0)
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector(
        &mut self,
        output: &mut LweCiphertextVectorMutView64,
        input: &LweCiphertextVectorView64,
        bsk: &FftFourierLweBootstrapKey64,
        luts: &PlaintextVector64,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    ) -> Result<
        (),
        LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError<Self::EngineError>,
    > {
        FftError::perform_fft_checks(bsk.polynomial_size())?;
        LweCiphertextVectorDiscardingCircuitBootstrapBooleanVerticalPackingError::
            perform_generic_checks(
                input,
                output,
                bsk,
                luts,
                cbs_level_count,
                cbs_base_log,
                cbs_pfpksk,
                64,
            )?;
        unsafe {
            self.discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector_unchecked(
            output,
            input,
            bsk,
            luts,
            cbs_level_count,
            cbs_base_log,
            cbs_pfpksk,
        );
        }
        Ok(())
    }

    unsafe fn discard_circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut LweCiphertextVectorMutView64,
        input: &LweCiphertextVectorView64,
        bsk: &FftFourierLweBootstrapKey64,
        luts: &PlaintextVector64,
        cbs_level_count: DecompositionLevelCount,
        cbs_base_log: DecompositionBaseLog,
        cbs_pfpksk: &LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeys64,
    ) {
        let lut_as_polynomial_list =
            PolynomialList::from_container(luts.0.as_tensor().as_slice(), bsk.polynomial_size());

        let fft = Fft::new(bsk.polynomial_size());
        let fft = fft.as_view();
        self.resize(
            circuit_bootstrap_boolean_vertical_packing_scratch::<u64>(
                CiphertextCount(input.lwe_ciphertext_count().0),
                CiphertextCount(output.lwe_ciphertext_count().0),
                input.lwe_dimension().to_lwe_size(),
                PolynomialCount(luts.plaintext_count().0),
                bsk.output_lwe_dimension().to_lwe_size(),
                cbs_pfpksk.output_polynomial_size(),
                bsk.glwe_dimension().to_glwe_size(),
                cbs_level_count,
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        circuit_bootstrap_boolean_vertical_packing(
            lut_as_polynomial_list.as_view(),
            bsk.0.as_view(),
            output.0.as_mut_view(),
            input.0.as_view(),
            cbs_pfpksk.0.as_view(),
            cbs_level_count,
            cbs_base_log,
            fft,
            self.stack(),
        )
    }
}
