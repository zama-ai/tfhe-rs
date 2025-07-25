use super::cm_params::{CmApParams, PARAMS_CM_2M_128, PARAMS_CM_2M_64};
use crate::core_crypto::commons::noise_formulas::secure_noise::minimal_lwe_variance_for_132_bits_security_gaussian;
use crate::core_crypto::prelude::cm_lwe_keyswitch_key_generation::allocate_and_generate_new_cm_lwe_keyswitch_key;
use itertools::Itertools;

use super::*;

const NB_TESTS: usize = 10;

#[test]
fn test_cm_keyswitch() {
    for param in PARAMS_CM_2M_64 {
        cm_keyswitch_generic(&param);
    }
    for param in PARAMS_CM_2M_128 {
        cm_keyswitch_generic(&param);
    }
}

fn cm_keyswitch_generic(params: &CmApParams) {
    let in_lwe_dimension = params
        .glwe_dimension
        .to_equivalent_lwe_dimension(params.polynomial_size);

    let out_lwe_dimension = params.lwe_dimension;

    let in_lwe_noise_distribution = DynamicDistribution::new_gaussian(
        minimal_lwe_variance_for_132_bits_security_gaussian(in_lwe_dimension, 2_f64.powi(64)),
    );
    let key_lwe_noise_distribution = DynamicDistribution::new_gaussian(
        minimal_lwe_variance_for_132_bits_security_gaussian(out_lwe_dimension, 2_f64.powi(64)),
    );
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let ks_decomp_base_log = params.base_log_ks;
    let ks_decomp_level_count = params.level_ks;

    let cm_dimension = CmDimension(10);

    let mut rsc = TestResources::new();

    let msg_modulus = 1 << params.precision;
    let mut msg = msg_modulus;
    let delta: u64 = encoding_with_padding / msg_modulus;

    for _ in 0..NB_TESTS {
        let lwe_sks_in = (0..cm_dimension.0)
            .map(|_| {
                allocate_and_generate_new_binary_lwe_secret_key(
                    in_lwe_dimension,
                    &mut rsc.secret_random_generator,
                )
            })
            .collect_vec();

        let lwe_sks_out = (0..cm_dimension.0)
            .map(|_| {
                allocate_and_generate_new_binary_lwe_secret_key(
                    out_lwe_dimension,
                    &mut rsc.secret_random_generator,
                )
            })
            .collect_vec();

        let cm_lwe_keyswitch_key = allocate_and_generate_new_cm_lwe_keyswitch_key(
            &lwe_sks_in,
            &lwe_sks_out,
            cm_dimension,
            ks_decomp_base_log,
            ks_decomp_level_count,
            key_lwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &cm_lwe_keyswitch_key,
            ciphertext_modulus
        ));
        while msg != 0 {
            msg = msg.wrapping_sub(1);

            let pts = PlaintextList::from_container(
                (0..cm_dimension.0).map(|_| msg * delta).collect_vec(),
            );

            let ct = allocate_and_encrypt_new_cm_lwe_ciphertext(
                &lwe_sks_in,
                &pts,
                in_lwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            let mut output_ct =
                CmLweCiphertext::new(0, out_lwe_dimension, cm_dimension, ciphertext_modulus);

            cm_keyswitch_lwe_ciphertext(&cm_lwe_keyswitch_key, &ct, &mut output_ct);

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
