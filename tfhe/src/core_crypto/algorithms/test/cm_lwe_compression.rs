use cm_lwe_compression::test::cm_lwe_compression_key_generation::allocate_and_generate_new_cm_lwe_compression_key;
use itertools::Itertools;

use super::*;

const NB_TESTS: usize = 10;

#[test]
fn cm_compression() {
    cm_compression_generic(TEST_PARAMS_4_BITS_NATIVE_U64);
}

fn cm_compression_generic(params: ClassicTestParams<u64>) {
    let in_lwe_dimension = LweDimension(13);

    let out_lwe_dimension = LweDimension(10);

    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let ks_decomp_base_log = params.ks_base_log;
    let ks_decomp_level_count = params.ks_level;

    let cm_dimension = CmDimension(10);

    let mut rsc = TestResources::new();

    let msg_modulus = 1 << message_modulus_log.0;
    let mut msg = msg_modulus;
    let delta: u64 = encoding_with_padding / msg_modulus;

    for _ in 0..NB_TESTS {
        let lwe_sk_in = allocate_and_generate_new_binary_lwe_secret_key(
            in_lwe_dimension,
            &mut rsc.secret_random_generator,
        );

        let lwe_sks_out = (0..cm_dimension.0)
            .map(|_| {
                allocate_and_generate_new_binary_lwe_secret_key(
                    out_lwe_dimension,
                    &mut rsc.secret_random_generator,
                )
            })
            .collect_vec();

        let compression_key = allocate_and_generate_new_cm_lwe_compression_key(
            &lwe_sk_in,
            &lwe_sks_out,
            ks_decomp_base_log,
            ks_decomp_level_count,
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &compression_key,
            ciphertext_modulus
        ));
        while msg != 0 {
            msg = msg.wrapping_sub(1);

            let ct = (0..cm_dimension.0)
                .map(|_| {
                    allocate_and_encrypt_new_lwe_ciphertext(
                        &lwe_sk_in,
                        Plaintext(msg * delta),
                        lwe_noise_distribution,
                        ciphertext_modulus,
                        &mut rsc.encryption_random_generator,
                    )
                })
                .collect_vec();

            let mut output_ct =
                CmLweCiphertext::new(0, out_lwe_dimension, cm_dimension, ciphertext_modulus);

            compress_lwe_ciphertexts_into_cm(&compression_key, &ct, &mut output_ct);

            for (i, lwe_sk_out) in lwe_sks_out.iter().enumerate() {
                let output_ct = output_ct.extract_lwe_ciphertext(i);

                assert!(check_encrypted_content_respects_mod(
                    &output_ct,
                    ciphertext_modulus
                ));

                let decrypted = decrypt_lwe_ciphertext(lwe_sk_out, &output_ct);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                assert_eq!(msg, decoded);
            }
        }
    }
}
