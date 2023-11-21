use super::*;
use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::test::{FftWopPbsKeys, FftWopPbsTestParams};
use crate::core_crypto::commons::dispersion::LogStandardDev;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DeltaLog, ExtractedBitsCount, GlweDimension,
    LweDimension, PlaintextCount, PolynomialCount, PolynomialSize,
};
use crate::core_crypto::commons::test_tools;
use crate::core_crypto::fft_impl::common::tests::gen_keys_or_get_from_cache_if_enabled;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::{
    fill_with_forward_fourier_scratch, FourierLweBootstrapKey,
};
use crate::core_crypto::fft_impl::fft64::math::fft::Fft;
use crate::core_crypto::prelude::test::{
    TestResources, FFT_WOPBS_N1024_PARAMS, FFT_WOPBS_N2048_PARAMS, FFT_WOPBS_N512_PARAMS,
    FFT_WOPBS_PARAMS,
};
use concrete_fft::c64;
use dyn_stack::{GlobalPodBuffer, PodStack, ReborrowMut, StackReq};
use serde::de::DeserializeOwned;
use serde::Serialize;

#[cfg(not(feature = "__coverage"))]
// Tests take about 2-3 seconds on a laptop with this number
const NB_TESTS: usize = 32;
#[cfg(not(feature = "__coverage"))]
const NB_TESTS_LIGHT: usize = 10;
#[cfg(feature = "__coverage")]
const NB_TESTS: usize = 1;
#[cfg(feature = "__coverage")]
const NB_TESTS_LIGHT: usize = 1;

pub fn generate_keys<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize> + Serialize + DeserializeOwned,
>(
    params: FftWopPbsTestParams<Scalar>,
    rsc: &mut TestResources,
) -> FftWopPbsKeys<Scalar> {
    //create GLWE and LWE secret key
    let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
        params.glwe_dimension,
        params.polynomial_size,
        &mut rsc.secret_random_generator,
    );
    let small_lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
        params.lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    // allocation and generation of the key in coef domain:
    let std_bsk = allocate_and_generate_new_lwe_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        params.pbs_base_log,
        params.pbs_level,
        params.lwe_modular_std_dev,
        params.ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    // allocation for the bootstrapping key
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        params.lwe_dimension,
        params.glwe_dimension.to_glwe_size(),
        params.polynomial_size,
        params.pbs_base_log,
        params.pbs_level,
    );

    let fft = Fft::new(params.polynomial_size);
    let fft = fft.as_view();

    fourier_bsk
        .as_mut_view()
        .par_fill_with_forward_fourier(std_bsk.as_view(), fft);

    // Creation of all the pfksk for the circuit bootstrapping
    let vec_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
        &big_lwe_sk,
        &glwe_sk,
        params.pfks_base_log,
        params.pfks_level,
        params.lwe_modular_std_dev,
        params.ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );
    FftWopPbsKeys {
        small_lwe_sk,
        big_lwe_sk,
        fbsk: fourier_bsk,
        lwe_pfpksk: vec_pfpksk,
    }
}

// Extract all the bits of a LWE
#[test]
pub fn test_extract_bits() {
    // Define settings for an insecure toy example
    let polynomial_size = PolynomialSize(1024);
    let glwe_dimension = GlweDimension(1);
    let small_lwe_dimension = LweDimension(585);

    let level_bsk = DecompositionLevelCount(2);
    let base_log_bsk = DecompositionBaseLog(10);

    let level_ksk = DecompositionLevelCount(7);
    let base_log_ksk = DecompositionBaseLog(4);

    let std = LogStandardDev::from_log_standard_dev(-60.);

    let ciphertext_modulus = CiphertextModulus::new_native();

    let number_of_bits_of_message_including_padding = 5_usize;

    let mut rsc = TestResources::new();

    // allocation and generation of the key in coef domain:
    let glwe_sk: GlweSecretKeyOwned<u64> = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );
    let lwe_small_sk: LweSecretKeyOwned<u64> = allocate_and_generate_new_binary_lwe_secret_key(
        small_lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    let std_bsk: LweBootstrapKeyOwned<u64> = allocate_and_generate_new_lwe_bootstrap_key(
        &lwe_small_sk,
        &glwe_sk,
        base_log_bsk,
        level_bsk,
        std,
        ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    let mut fourier_bsk = FourierLweBootstrapKey::new(
        small_lwe_dimension,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        base_log_bsk,
        level_bsk,
    );

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    let lwe_big_sk = glwe_sk.clone().into_lwe_secret_key();
    let ksk_lwe_big_to_small: LweKeyswitchKeyOwned<u64> =
        allocate_and_generate_new_lwe_keyswitch_key(
            &lwe_big_sk,
            &lwe_small_sk,
            base_log_ksk,
            level_ksk,
            std,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

    let input_lwe_dimension = lwe_big_sk.lwe_dimension();

    let req = || {
        StackReq::try_any_of([
            fill_with_forward_fourier_scratch(fft)?,
            extract_bits_scratch::<u64>(
                input_lwe_dimension,
                ksk_lwe_big_to_small.output_key_lwe_dimension(),
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                fft,
            )?,
        ])
    };
    let req = req().unwrap();
    let mut mem = GlobalPodBuffer::new(req);
    let mut stack = PodStack::new(&mut mem);

    fourier_bsk
        .as_mut_view()
        .par_fill_with_forward_fourier(std_bsk.as_view(), fft);

    let delta_log = DeltaLog(64 - number_of_bits_of_message_including_padding);
    // Decomposer to manage the rounding after decrypting the extracted bit
    let decomposer = SignedDecomposer::new(DecompositionBaseLog(1), DecompositionLevelCount(1));

    ////////////////////////////////////////////////////////////////////////////////////////////////

    for _ in 0..NB_TESTS {
        // Generate a random plaintext in [0; 2^{number_of_bits_of_message_including_padding}[
        let val = test_tools::random_uint_between(
            0..2u64.pow(number_of_bits_of_message_including_padding as u32),
        );

        // Encryption
        let message = Plaintext(val << delta_log.0);
        println!("{message:?}");
        let mut lwe_in = LweCiphertextOwned::new(
            0u64,
            lwe_big_sk.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );
        encrypt_lwe_ciphertext(
            &lwe_big_sk,
            &mut lwe_in,
            message,
            std,
            &mut rsc.encryption_random_generator,
        );

        // Bit extraction
        // Extract all the bits
        let number_values_to_extract = ExtractedBitsCount(64 - delta_log.0);

        let mut lwe_out_list = LweCiphertextListOwned::new(
            0u64,
            ksk_lwe_big_to_small.output_lwe_size(),
            LweCiphertextCount(number_values_to_extract.0),
            ciphertext_modulus,
        );

        extract_bits(
            lwe_out_list.as_mut_view(),
            lwe_in.as_view(),
            ksk_lwe_big_to_small.as_view(),
            fourier_bsk.as_view(),
            delta_log,
            number_values_to_extract,
            fft,
            stack.rb_mut(),
        );

        // Decryption of extracted bit
        for (i, result_ct) in lwe_out_list.iter().rev().enumerate() {
            let decrypted_message = decrypt_lwe_ciphertext(&lwe_small_sk, &result_ct);
            // Round after decryption using decomposer
            let decrypted_rounded = decomposer.closest_representable(decrypted_message.0);
            // Bring back the extracted bit found in the MSB in the LSB
            let decrypted_extract_bit = decrypted_rounded >> 63;
            println!("extracted bit : {decrypted_extract_bit:?}");
            println!("{decrypted_message:?}");
            assert_eq!(
                ((message.0 >> delta_log.0) >> i) & 1,
                decrypted_extract_bit,
                "Bit #{}, for plaintext {:#066b}",
                delta_log.0 + i,
                message.0
            );
        }
    }
}

// Test the circuit bootstrapping with private functional ks
// Verify the decryption has the expected content
#[test]
fn test_circuit_bootstrapping_binary() {
    // Define settings for an insecure toy example
    let polynomial_size = PolynomialSize(512);
    let glwe_dimension = GlweDimension(2);
    let small_lwe_dimension = LweDimension(10);

    let level_bsk = DecompositionLevelCount(2);
    let base_log_bsk = DecompositionBaseLog(15);

    let level_pksk = DecompositionLevelCount(2);
    let base_log_pksk = DecompositionBaseLog(15);

    let level_count_cbs = DecompositionLevelCount(1);
    let base_log_cbs = DecompositionBaseLog(10);

    let std = LogStandardDev::from_log_standard_dev(-60.);

    let ciphertext_modulus = CiphertextModulus::new_native();

    let mut rsc = TestResources::new();

    // Create GLWE and LWE secret key
    let glwe_sk: GlweSecretKeyOwned<u64> = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );
    let lwe_sk: LweSecretKeyOwned<u64> = allocate_and_generate_new_binary_lwe_secret_key(
        small_lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    // Allocation and generation of the bootstrap key in standard domain:
    let std_bsk: LweBootstrapKeyOwned<u64> = allocate_and_generate_new_lwe_bootstrap_key(
        &lwe_sk,
        &glwe_sk,
        base_log_bsk,
        level_bsk,
        std,
        ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    let mut fourier_bsk = FourierLweBootstrapKey::new(
        small_lwe_dimension,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        base_log_bsk,
        level_bsk,
    );

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    fourier_bsk
        .as_mut_view()
        .par_fill_with_forward_fourier(std_bsk.as_view(), fft);

    let lwe_sk_bs_output = glwe_sk.clone().into_lwe_secret_key();

    // Creation of all the pfksk for the circuit bootstrapping
    let vec_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
        &lwe_sk_bs_output,
        &glwe_sk,
        base_log_pksk,
        level_pksk,
        std,
        ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    let delta_log = DeltaLog(60);

    for _ in 0..NB_TESTS {
        // value is 0 or 1 as CBS works on messages expected to contain 1 bit of information
        let value: u64 = test_tools::random_uint_between(0..2u64);
        // Encryption of an LWE with the value 'message'
        let message = Plaintext((value) << delta_log.0);
        let mut lwe_in =
            LweCiphertextOwned::new(0u64, small_lwe_dimension.to_lwe_size(), ciphertext_modulus);
        encrypt_lwe_ciphertext(
            &lwe_sk,
            &mut lwe_in,
            message,
            std,
            &mut rsc.encryption_random_generator,
        );

        let mut cbs_res = GgswCiphertextOwned::new(
            0u64,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            base_log_cbs,
            level_count_cbs,
            ciphertext_modulus,
        );

        let mut mem = GlobalPodBuffer::new(
            circuit_bootstrap_boolean_scratch::<u64>(
                lwe_in.lwe_size(),
                fourier_bsk.output_lwe_dimension().to_lwe_size(),
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                fft,
            )
            .unwrap(),
        );
        let stack = PodStack::new(&mut mem);
        // Execute the CBS
        circuit_bootstrap_boolean(
            fourier_bsk.as_view(),
            lwe_in.as_view(),
            cbs_res.as_mut_view(),
            delta_log,
            vec_pfpksk.as_view(),
            fft,
            stack,
        );

        let glwe_size = glwe_dimension.to_glwe_size();

        //print the key to check if the RLWE in the GGSW seem to be well created
        println!("RLWE secret key:\n{glwe_sk:?}");
        let mut decrypted = PlaintextListOwned::new(
            0_u64,
            PlaintextCount(polynomial_size.0 * level_count_cbs.0 * glwe_size.0),
        );
        decrypt_glwe_ciphertext_list(&glwe_sk, &cbs_res.as_glwe_list(), &mut decrypted);

        let level_size = polynomial_size.0 * glwe_size.0;

        println!("\nGGSW decryption:");
        for (level_idx, level_decrypted_glwe) in decrypted.chunks_exact_mut(level_size).enumerate()
        {
            for (decrypted_glwe, original_polynomial_from_glwe_sk) in level_decrypted_glwe
                .chunks_exact(polynomial_size.0)
                .take(glwe_dimension.0)
                .zip(glwe_sk.as_polynomial_list().iter())
            {
                let current_level = level_idx + 1;
                let mut expected_decryption = PlaintextListOwned::new(
                    0u64,
                    PlaintextCount(original_polynomial_from_glwe_sk.polynomial_size().0),
                );
                expected_decryption
                    .as_mut()
                    .copy_from_slice(original_polynomial_from_glwe_sk.as_ref());

                let multiplying_factor = 0u64.wrapping_sub(value);

                slice_wrapping_scalar_mul_assign(expected_decryption.as_mut(), multiplying_factor);

                let decomposer =
                    SignedDecomposer::new(base_log_cbs, DecompositionLevelCount(current_level));

                expected_decryption
                    .as_mut()
                    .iter_mut()
                    .for_each(|coeff| *coeff >>= 64 - base_log_cbs.0 * current_level);

                let mut decoded_glwe =
                    PlaintextList::from_container(decrypted_glwe.as_ref().to_vec());

                decoded_glwe.as_mut().iter_mut().for_each(|coeff| {
                    *coeff = decomposer.closest_representable(*coeff)
                        >> (64 - base_log_cbs.0 * current_level);
                });

                assert_eq!(expected_decryption.as_ref(), decoded_glwe.as_ref());
            }
            let last_decrypted_glwe = level_decrypted_glwe
                .chunks_exact(polynomial_size.0)
                .next_back()
                .unwrap();

            let mut last_decoded_glwe =
                PlaintextList::from_container(last_decrypted_glwe.as_ref().to_vec());

            let decomposer = SignedDecomposer::new(base_log_cbs, level_count_cbs);

            last_decoded_glwe.as_mut().iter_mut().for_each(|coeff| {
                *coeff = decomposer.closest_representable(*coeff)
                    >> (64 - base_log_cbs.0 * level_count_cbs.0);
            });

            let mut expected_decryption =
                PlaintextListOwned::new(0u64, last_decoded_glwe.plaintext_count());

            *expected_decryption.as_mut().first_mut().unwrap() = value;

            assert_eq!(expected_decryption.as_ref(), last_decoded_glwe.as_ref());
        }
    }
}

#[test]
pub fn test_cmux_tree() {
    // Define settings for an insecure toy example
    let polynomial_size = PolynomialSize(512);
    let glwe_dimension = GlweDimension(1);
    let std = LogStandardDev::from_log_standard_dev(-60.);
    let level = DecompositionLevelCount(3);
    let base_log = DecompositionBaseLog(6);
    let ciphertext_modulus = CiphertextModulus::new_native();
    // We need (1 << nb_ggsw) > polynomial_size to have an actual CMUX tree and not just a blind
    // rotation
    let nb_ggsw = 10;
    let delta_log = 60;

    let mut rsc = TestResources::new();

    // Allocation and generation of the key in coef domain:
    let glwe_sk: GlweSecretKeyOwned<u64> = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );
    let glwe_size = glwe_sk.glwe_dimension().to_glwe_size();

    // Creation of the 'big' lut
    // lut = [[0...0][1...1][2...2] ...] where [X...X] is a lut
    // The values in the lut are taken mod 2 ^ {64 - delta_log} and shifted by delta_log to the left
    let mut lut = PolynomialListOwned::new(0u64, polynomial_size, PolynomialCount(1 << nb_ggsw));
    for (i, mut polynomial) in lut.iter_mut().enumerate() {
        polynomial
            .as_mut()
            .fill((i as u64 % (1 << (64 - delta_log))) << delta_log);
    }

    // Values between [0; 1023]
    // Note that we use a delta log which does not handle more than 4 bits of message
    let number_of_bits_for_payload = nb_ggsw;

    // Decomposer to manage the rounding after decrypting
    let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

    for _ in 0..NB_TESTS {
        let mut value =
            test_tools::random_uint_between(0..2u64.pow(number_of_bits_for_payload as u32));
        println!("value: {value}");
        let witness = value % (1 << (64 - delta_log));

        // Bit decomposition of the value from MSB to LSB
        let mut vec_message = vec![Plaintext(0); nb_ggsw];
        for i in (0..nb_ggsw).rev() {
            vec_message[i] = Plaintext(value & 1);
            value >>= 1;
        }

        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();

        // Encrypt all bits in fourier GGSW ciphertexts from MSB to LSB, store them in a vec
        let mut ggsw_list = FourierGgswCiphertextList::new(
            vec![
                c64::default();
                nb_ggsw
                    * polynomial_size.to_fourier_polynomial_size().0
                    * glwe_size.0
                    * glwe_size.0
                    * level.0
            ],
            nb_ggsw,
            glwe_size,
            polynomial_size,
            base_log,
            level,
        );
        for (&single_bit_msg, mut fourier_ggsw) in
            izip!(vec_message.iter(), ggsw_list.as_mut_view().into_ggsw_iter())
        {
            let mut ggsw = GgswCiphertextOwned::new(
                0_u64,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                base_log,
                level,
                ciphertext_modulus,
            );
            encrypt_constant_ggsw_ciphertext(
                &glwe_sk,
                &mut ggsw,
                single_bit_msg,
                std,
                &mut rsc.encryption_random_generator,
            );

            let mut mem = GlobalPodBuffer::new(fill_with_forward_fourier_scratch(fft).unwrap());
            let stack = PodStack::new(&mut mem);
            fourier_ggsw
                .as_mut_view()
                .fill_with_forward_fourier(ggsw.as_view(), fft, stack);
        }

        let mut result_cmux_tree =
            GlweCiphertext::new(0_u64, glwe_size, polynomial_size, ciphertext_modulus);
        let mut mem = GlobalPodBuffer::new(
            cmux_tree_memory_optimized_scratch::<u64>(glwe_size, polynomial_size, nb_ggsw, fft)
                .unwrap(),
        );
        cmux_tree_memory_optimized(
            result_cmux_tree.as_mut_view(),
            lut.as_view(),
            ggsw_list.as_view(),
            fft,
            PodStack::new(&mut mem),
        );
        let mut decrypted_result =
            PlaintextListOwned::new(0u64, PlaintextCount(glwe_sk.polynomial_size().0));
        decrypt_glwe_ciphertext(&glwe_sk, &result_cmux_tree, &mut decrypted_result);

        let decoded_result = decomposer
            .closest_representable(*decrypted_result.as_ref().first().unwrap())
            >> delta_log;

        // The recovered lut_number must be equal to the value stored in the lut at index
        // witness % 2 ^ {64 - delta_log}
        println!("result : {decoded_result:?}");
        println!("witness : {witness:?}");
        assert_eq!(decoded_result, witness);
    }
}

// Circuit bootstrap + vertical packing applying an identity lut
#[test]
pub fn test_extract_bit_circuit_bootstrapping_vertical_packing() {
    let params = FFT_WOPBS_PARAMS;

    let polynomial_size = params.polynomial_size;
    let glwe_dimension = params.glwe_dimension;
    let ciphertext_modulus = params.ciphertext_modulus;
    let level_cbs = params.cbs_level;
    let base_log_cbs = params.cbs_base_log;
    let level_ksk = DecompositionLevelCount(9);
    let base_log_ksk = DecompositionBaseLog(1);
    let std_big = params.glwe_modular_std_dev;

    let mut rsc = TestResources::new();

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    let mut keys_gen = |params| generate_keys(params, &mut rsc);
    let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
    let (fourier_bsk, lwe_small_sk, lwe_big_sk, vec_pfpksk) = (
        keys.fbsk,
        keys.small_lwe_sk,
        keys.big_lwe_sk,
        keys.lwe_pfpksk,
    );

    let input_lwe_dimension = lwe_big_sk.lwe_dimension();

    let ksk_lwe_big_to_small: LweKeyswitchKeyOwned<u64> =
        allocate_and_generate_new_lwe_keyswitch_key(
            &lwe_big_sk,
            &lwe_small_sk,
            base_log_ksk,
            level_ksk,
            std_big,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

    let number_of_bits_in_input_lwe = 10;
    let number_of_values_to_extract = ExtractedBitsCount(number_of_bits_in_input_lwe);

    let decomposer = SignedDecomposer::new(DecompositionBaseLog(10), DecompositionLevelCount(1));

    // Here even thought the deltas have the same value, they can differ between ciphertexts and lut
    // so keeping both separate
    let delta_log = DeltaLog(64 - number_of_values_to_extract.0);
    let delta_lut = DeltaLog(64 - number_of_values_to_extract.0);

    for run_number in 0..NB_TESTS_LIGHT {
        let cleartext =
            test_tools::random_uint_between(0..2u64.pow(number_of_bits_in_input_lwe as u32));

        println!("cleartext: {cleartext}");
        println!("cleartext bits: {cleartext:b}");

        let message = Plaintext(cleartext << delta_log.0);
        let mut lwe_in = LweCiphertextOwned::new(
            0u64,
            glwe_dimension
                .to_equivalent_lwe_dimension(polynomial_size)
                .to_lwe_size(),
            ciphertext_modulus,
        );
        encrypt_lwe_ciphertext(
            &lwe_big_sk,
            &mut lwe_in,
            message,
            std_big,
            &mut rsc.encryption_random_generator,
        );

        let mut extracted_bits_lwe_list = LweCiphertextListOwned::new(
            0u64,
            ksk_lwe_big_to_small.output_lwe_size(),
            LweCiphertextCount(number_of_values_to_extract.0),
            ciphertext_modulus,
        );

        let mut mem = GlobalPodBuffer::new(
            extract_bits_scratch::<u64>(
                input_lwe_dimension,
                ksk_lwe_big_to_small.output_key_lwe_dimension(),
                fourier_bsk.glwe_size(),
                polynomial_size,
                fft,
            )
            .unwrap(),
        );
        extract_bits(
            extracted_bits_lwe_list.as_mut_view(),
            lwe_in.as_view(),
            ksk_lwe_big_to_small.as_view(),
            fourier_bsk.as_view(),
            delta_log,
            number_of_values_to_extract,
            fft,
            PodStack::new(&mut mem),
        );

        // Decrypt all extracted bit for checking purposes in case of problems
        for ct in extracted_bits_lwe_list.iter() {
            let decrypted_message = decrypt_lwe_ciphertext(&lwe_small_sk, &ct);
            let extract_bit_result =
                (((decrypted_message.0 as f64) / (1u64 << (63)) as f64).round()) as u64;
            println!("extract_bit_result: {extract_bit_result:?}");
            println!("decrypted_message: {decrypted_message:?}");
        }

        // LUT creation
        let number_of_luts_and_output_vp_ciphertexts = 1;
        let mut lut_size = polynomial_size.0;

        let lut_poly_list = if run_number % 2 == 0 {
            // Test with a small lut, only triggering a blind rotate
            if lut_size < (1 << extracted_bits_lwe_list.lwe_ciphertext_count().0) {
                lut_size = 1 << extracted_bits_lwe_list.lwe_ciphertext_count().0;
            }
            let mut lut = Vec::with_capacity(lut_size);

            for i in 0..lut_size {
                lut.push((i as u64 % (1 << (64 - delta_log.0))) << delta_lut.0);
            }

            // Here we have a single lut, so store it directly in the polynomial list
            PolynomialListOwned::from_container(lut, PolynomialSize(lut_size))
        } else {
            // Test with a big lut, triggering an actual cmux tree
            let mut lut_poly_list = PolynomialListOwned::new(
                0u64,
                polynomial_size,
                PolynomialCount(1 << number_of_bits_in_input_lwe),
            );
            for (i, mut polynomial) in lut_poly_list.iter_mut().enumerate() {
                polynomial
                    .as_mut()
                    .fill((i as u64 % (1 << (64 - delta_log.0))) << delta_lut.0);
            }
            lut_poly_list
        };

        // We need as many output ciphertexts as we have input luts
        let mut vertical_packing_lwe_list_out = LweCiphertextListOwned::new(
            0u64,
            glwe_dimension
                .to_equivalent_lwe_dimension(polynomial_size)
                .to_lwe_size(),
            LweCiphertextCount(number_of_luts_and_output_vp_ciphertexts),
            ciphertext_modulus,
        );

        // Perform circuit bootstrap + vertical packing
        let mut mem = GlobalPodBuffer::new(
            circuit_bootstrap_boolean_vertical_packing_scratch::<u64>(
                extracted_bits_lwe_list.lwe_ciphertext_count(),
                vertical_packing_lwe_list_out.lwe_ciphertext_count(),
                extracted_bits_lwe_list.lwe_size(),
                lut_poly_list.polynomial_count(),
                fourier_bsk.output_lwe_dimension().to_lwe_size(),
                fourier_bsk.glwe_size(),
                vec_pfpksk.output_polynomial_size(),
                level_cbs,
                fft,
            )
            .unwrap(),
        );
        circuit_bootstrap_boolean_vertical_packing(
            lut_poly_list.as_view(),
            fourier_bsk.as_view(),
            vertical_packing_lwe_list_out.as_mut_view(),
            extracted_bits_lwe_list.as_view(),
            vec_pfpksk.as_view(),
            level_cbs,
            base_log_cbs,
            fft,
            PodStack::new(&mut mem),
        );

        // We have a single output ct
        let result_ct = vertical_packing_lwe_list_out.iter().next().unwrap();

        // decrypt result
        let decrypted_message = decrypt_lwe_ciphertext(&lwe_big_sk, &result_ct);
        let decoded_message = decomposer.closest_representable(decrypted_message.0) >> delta_log.0;

        // print information if the result is wrong
        assert!(
            decoded_message == cleartext,
            "decoded_message ({decoded_message:?}) != cleartext ({cleartext:?})\n\
                decrypted_message: {decrypted_message:?}, decoded_message: {decoded_message:?}",
        );
        println!("{decoded_message:?}");
    }
}

fn test_wop_add_one(params: FftWopPbsTestParams<u64>) {
    let polynomial_size = params.polynomial_size;
    let small_dim = params.lwe_dimension;
    let level_cbs = params.cbs_level;
    let base_log_cbs = params.cbs_base_log;
    let ciphertext_modulus = params.ciphertext_modulus;
    let std_small = params.lwe_modular_std_dev;

    let mut rsc = TestResources::new();

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    let mut keys_gen = |params| generate_keys(params, &mut rsc);
    let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
    let (fourier_bsk, small_sk, big_lwe_sk, cbs_pfpksk) = (
        keys.fbsk,
        keys.small_lwe_sk,
        keys.big_lwe_sk,
        keys.lwe_pfpksk,
    );

    // We are going to encrypt 10 bits
    let number_of_input_bits: usize = 10;

    #[cfg(not(feature = "__coverage"))]
    const SIZE: usize = 10;
    #[cfg(feature = "__coverage")]
    const SIZE: usize = 1;

    // Test on 610, binary representation 10011 00010
    let mut vals = [0u64; SIZE];
    vals[0] = 610;
    // Use our generator to have more random values
    rsc.encryption_random_generator
        .fill_slice_with_random_mask(&mut vals[1..]);
    // Apply our modulus to be sure we can represent the test values
    vals.iter_mut()
        .for_each(|x| *x %= 1 << number_of_input_bits);

    for val in vals {
        let mut extracted_bits = LweCiphertextList::new(
            0u64,
            small_dim.to_lwe_size(),
            LweCiphertextCount(number_of_input_bits),
            ciphertext_modulus,
        );

        // Encrypt bits as if
        for i in 0..number_of_input_bits {
            encrypt_lwe_ciphertext(
                &small_sk,
                &mut extracted_bits.get_mut(number_of_input_bits - i - 1),
                Plaintext(((val >> i) & 1) << 63),
                std_small,
                &mut rsc.encryption_random_generator,
            );
        }

        // We'll apply a single table look-up computing x + 1 to our 10 bits input integer
        let number_of_luts_and_output_cts: usize = 1;

        let mut output_cbs_vp = LweCiphertextList::new(
            0u64,
            big_lwe_sk.lwe_dimension().to_lwe_size(),
            LweCiphertextCount(number_of_luts_and_output_cts),
            ciphertext_modulus,
        );

        // Here we will create a single lut which will result in a single Output ciphertext
        // We take the max between polynomial_size and the number of input bits because:
        // If polynomial_size > 2^number_of_inputs_bits some values will go unused by the vertical
        // packing, we just fill the whole lut anyways as it's easier to write
        // If both are equal then no cmux tree and only blind rotations will be performed on the lut
        // containing a single polynomial
        // If the polynomial_size < 2^number_of_inputs_bits then we first create a lut  with
        // 2^number_of_inputs_bits values that is then adapted to the right polynomial size via a
        // polynomial list
        let luts_size = (1 << number_of_input_bits).max(polynomial_size.0);
        let luts_length = number_of_luts_and_output_cts * luts_size;
        let mut lut: Vec<u64> = Vec::with_capacity(luts_length);

        let delta_log_lut = 64 - number_of_input_bits;

        for i in 0..luts_length {
            lut.push(((i + 1) as u64 % (1 << number_of_input_bits)) << delta_log_lut);
        }

        let lut_as_polynomial_list = PolynomialList::from_container(lut, polynomial_size);

        // Perform circuit bootstrap + vertical packing
        let mut mem = GlobalPodBuffer::new(
            circuit_bootstrap_boolean_vertical_packing_scratch::<u64>(
                extracted_bits.lwe_ciphertext_count(),
                output_cbs_vp.lwe_ciphertext_count(),
                extracted_bits.lwe_size(),
                lut_as_polynomial_list.polynomial_count(),
                fourier_bsk.output_lwe_dimension().to_lwe_size(),
                fourier_bsk.glwe_size(),
                cbs_pfpksk.output_polynomial_size(),
                level_cbs,
                fft,
            )
            .unwrap(),
        );
        circuit_bootstrap_boolean_vertical_packing(
            lut_as_polynomial_list.as_view(),
            fourier_bsk.as_view(),
            output_cbs_vp.as_mut_view(),
            extracted_bits.as_view(),
            cbs_pfpksk.as_view(),
            level_cbs,
            base_log_cbs,
            fft,
            PodStack::new(&mut mem),
        );

        let expected = (val + 1) % (1 << number_of_input_bits);

        // We have a single output ct
        let result_ct = output_cbs_vp.iter().next().unwrap();

        // Decomposer helper to round the result and decode
        let decomposer = SignedDecomposer::new(
            DecompositionBaseLog(number_of_input_bits),
            DecompositionLevelCount(1),
        );

        // decrypt result
        let decrypted_message = decrypt_lwe_ciphertext(&big_lwe_sk, &result_ct);
        let decoded_message =
            decomposer.closest_representable(decrypted_message.0) >> delta_log_lut;

        assert_eq!(expected, decoded_message);
    }
}

//CMUX tree
#[test]
fn test_wop_add_one_cmux_tree() {
    test_wop_add_one(FFT_WOPBS_N512_PARAMS);
}

//No CMUX tree
#[test]
fn test_wop_add_one_no_cmux_tree() {
    test_wop_add_one(FFT_WOPBS_N1024_PARAMS);
}

//Expanded lut
#[test]
fn test_wop_add_one_expanded_lut() {
    test_wop_add_one(FFT_WOPBS_N2048_PARAMS);
}
