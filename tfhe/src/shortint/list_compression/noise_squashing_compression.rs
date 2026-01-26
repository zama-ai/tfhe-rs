use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;

use crate::core_crypto::prelude::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::core_crypto::prelude::{
    par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext, GlweCiphertext,
    LweCiphertextList,
};
use crate::shortint::ciphertext::{
    CompressedSquashedNoiseCiphertextList, CompressedSquashedNoiseCiphertextListMeta,
    SquashedNoiseCiphertext,
};
use crate::shortint::parameters::LweCiphertextCount;

use super::server_keys::NoiseSquashingCompressionKey;

impl NoiseSquashingCompressionKey {
    /// Compress a list of [`SquashedNoiseCiphertext`] into a GLWE list.
    ///
    /// This is similar to
    /// [`CompressionKey::compress_ciphertexts_into_list`](crate::shortint::list_compression::CompressionKey::compress_ciphertexts_into_list),
    /// however it is possible to extract the ciphertexts without a PBS.
    pub fn compress_noise_squashed_ciphertexts_into_list(
        &self,
        ciphertexts: &[SquashedNoiseCiphertext],
    ) -> CompressedSquashedNoiseCiphertextList {
        let lwe_pksk = &self.packing_key_switching_key;
        let lwe_per_glwe = self.lwe_per_glwe;
        let polynomial_size = lwe_pksk.output_polynomial_size();
        let glwe_size = lwe_pksk.output_glwe_size();

        if ciphertexts.is_empty() {
            return CompressedSquashedNoiseCiphertextList {
                glwe_ciphertext_list: Vec::new(),
                meta: None,
            };
        }

        let lwe_pksk = &self.packing_key_switching_key;

        let lwe_size = lwe_pksk.input_key_lwe_dimension().to_lwe_size();

        assert!(
            lwe_per_glwe.0 <= polynomial_size.0,
            "Cannot pack more than polynomial_size(={}) elements per glwe, {} requested",
            polynomial_size.0,
            lwe_per_glwe.0,
        );

        let first_ct = &ciphertexts[0];

        let message_modulus = first_ct.message_modulus();
        let carry_modulus = first_ct.carry_modulus();
        let ciphertext_modulus = first_ct.lwe_ciphertext().ciphertext_modulus();

        assert!(
            ciphertext_modulus.is_power_of_two(),
            "Squashed noise ciphertext modulus should be a power of 2 for compression, got {ciphertext_modulus:?}"

        );

        let ciphertext_modulus_log = ciphertext_modulus.into_modulus_log();

        let glwe_ciphertext_list: Vec<_> = ciphertexts
            .par_chunks(lwe_per_glwe.0)
            .map(|ct_list| {
                let mut list: Vec<_> = vec![];

                for ct in ct_list {
                    assert_eq!(
                        lwe_size,
                        ct.lwe_ciphertext().lwe_size(),
                        "All ciphertexts do not have the same lwe size as the packing keyswitch key"
                    );

                    assert_eq!(
                        message_modulus,
                        ct.message_modulus(),
                        "All ciphertexts do not have the same message modulus"
                    );

                    assert_eq!(
                        carry_modulus,
                        ct.carry_modulus(),
                        "All ciphertexts do not have the same message modulus"
                    );

                    list.extend(ct.lwe_ciphertext().as_ref());
                }

                let list = LweCiphertextList::from_container(list, lwe_size, ciphertext_modulus);

                let mut out =
                    GlweCiphertext::new(0u128, glwe_size, polynomial_size, ciphertext_modulus);

                par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                    lwe_pksk, &list, &mut out,
                );

                CompressedModulusSwitchedGlweCiphertext::compress(
                    &out,
                    ciphertext_modulus_log,
                    LweCiphertextCount(ct_list.len()),
                )
            })
            .collect();

        let meta = Some(CompressedSquashedNoiseCiphertextListMeta {
            message_modulus,
            carry_modulus,
            lwe_per_glwe,
        });

        CompressedSquashedNoiseCiphertextList {
            glwe_ciphertext_list,
            meta,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::shortint::ciphertext::MaxDegree;
    use crate::shortint::keycache::KEY_CACHE;
    use crate::shortint::list_compression::private_key::NoiseSquashingCompressionPrivateKey;
    use crate::shortint::noise_squashing::{
        NoiseSquashingKey, NoiseSquashingPrivateKey, NoiseSquashingPrivateKeyView,
    };
    use crate::shortint::parameters::test_params::{
        TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
        TEST_META_PARAM_PROD_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    };
    use crate::shortint::parameters::{Degree, MetaParameters};
    use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;

    use rand::prelude::*;
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    fn test_noise_squashing_compression(meta_params: MetaParameters) {
        let (params, noise_squashing_params, noise_squashing_compression_params) = {
            let meta_noise_squashing_params = meta_params
                .noise_squashing_parameters
                .expect("MetaParameters should have noise_squashing_parameters");
            (
                meta_params.compute_parameters,
                meta_noise_squashing_params.parameters,
                meta_noise_squashing_params
                    .compression_parameters
                    .expect("MetaNoiseSquashingParameters should have compression_parameters"),
            )
        };

        let keycache_entry = KEY_CACHE.get_from_param(params);
        let (cks, sks) = (keycache_entry.client_key(), keycache_entry.server_key());
        let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_params);
        let noise_squashing_key = NoiseSquashingKey::new(cks, &noise_squashing_private_key);

        let compression_private_key =
            NoiseSquashingCompressionPrivateKey::new(noise_squashing_compression_params);

        let compression_key = noise_squashing_private_key
            .new_noise_squashing_compression_key(&compression_private_key);

        let mut rng = thread_rng();

        let id_lut = sks.generate_lookup_table(|x| x);
        let max_ct_count = noise_squashing_compression_params.lwe_per_glwe;

        for ct_count in [0, 1, max_ct_count.0] {
            // Generate random msgs
            let msgs: Vec<_> = (0..ct_count)
                .map(|_| {
                    (
                        rng.gen::<u64>() % cks.parameters().message_modulus().0,
                        rng.gen::<u64>() % cks.parameters().message_modulus().0,
                    )
                })
                .collect();

            // Pack the ciphertext and apply noise squashing
            let ct: Vec<_> = msgs
                .par_iter()
                .map(|(msg_1, msg_2)| {
                    let mut ct_1 = cks.encrypt(*msg_1);
                    let mut ct_2 = cks.encrypt(*msg_2);

                    // Set ciphertext noise level to nominal
                    rayon::join(
                        || sks.apply_lookup_table_assign(&mut ct_1, &id_lut),
                        || sks.apply_lookup_table_assign(&mut ct_2, &id_lut),
                    );

                    let packed = sks.unchecked_add(
                        &sks.unchecked_scalar_mul(&ct_1, sks.message_modulus.0.try_into().unwrap()),
                        &ct_2,
                    );

                    noise_squashing_key.squash_ciphertext_noise(&packed, sks)
                })
                .collect();

            // Compress the ciphertexts in a list
            let compressed = compression_key.compress_noise_squashed_ciphertexts_into_list(&ct);

            let expected_degree = Degree::new(
                MaxDegree::from_msg_carry_modulus(sks.message_modulus, sks.carry_modulus).get(),
            );

            // Extract from the list
            let extracted = (0..compressed.len()).map(|i| {
                let ciphertext = compressed.unpack(i).unwrap();
                assert_eq!(ciphertext.degree(), expected_degree);
                ciphertext
            });

            // Decrypt
            let decryption_key = NoiseSquashingPrivateKeyView::from(&compression_private_key);
            let decrypted_values = extracted
                .map(|ciphertext| decryption_key.decrypt_squashed_noise_ciphertext(&ciphertext));

            for (idx, value) in decrypted_values.enumerate() {
                let dec_msg1 = value / (sks.message_modulus.0 as u128);
                let dec_msg2 = value % (sks.message_modulus.0 as u128);

                let msg = msgs[idx];

                assert_eq!(dec_msg1, msg.0 as u128);
                assert_eq!(dec_msg2, msg.1 as u128);
            }
        }
    }

    create_parameterized_test!(test_noise_squashing_compression {
        (TEST_META_PARAM_PROD_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128, CPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
        (TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128, CPU_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128)
    });
}
