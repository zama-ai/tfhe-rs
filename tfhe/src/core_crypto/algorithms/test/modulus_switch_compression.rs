use super::*;
use crate::core_crypto::prelude::compressed_modulus_switched_lwe_ciphertext::CompressedModulusSwitchedLweCiphertext;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 10;
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

fn encryption_ms_decryption<Scalar: UnsignedTorus + Sync + Send>(
    params: ClassicTestParams<Scalar>,
) {
    let ClassicTestParams {
        lwe_noise_distribution,
        message_modulus_log,
        ciphertext_modulus,
        ..
    } = params;

    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc: TestResources = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            // Create the LweSecretKey
            let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key::<Scalar, _>(
                params.lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let lwe = allocate_and_encrypt_new_lwe_ciphertext(
                &lwe_secret_key,
                Plaintext(msg * delta),
                lwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            // Can be stored using much less space than the standard lwe ciphertexts
            let compressed = CompressedModulusSwitchedLweCiphertext::compress(
                &lwe,
                CiphertextModulusLog(params.polynomial_size.log2().0 + 1),
            );

            let lwe_ms_ed = compressed.extract();

            let decrypted = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe_ms_ed);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;
            assert_eq!(decoded, msg);
        }

        // In coverage, we break after one while loop iteration, changing message values does
        // not yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parametrized_test!(encryption_ms_decryption);
