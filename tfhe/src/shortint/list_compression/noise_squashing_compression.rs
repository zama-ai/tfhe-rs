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
    use crate::shortint::keycache::KEY_CACHE;
    use crate::shortint::list_compression::private_key::NoiseSquashingCompressionPrivateKey;
    use crate::shortint::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
    use crate::shortint::parameters::v1_3::V1_3_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use crate::shortint::parameters::*;

    use rand::prelude::*;
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    #[test]
    fn test_noise_squashing_compression_ci_run_filter() {
        let keycache_entry =
            KEY_CACHE.get_from_param(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
        let (cks, sks) = (keycache_entry.client_key(), keycache_entry.server_key());
        let noise_squashing_private_key = NoiseSquashingPrivateKey::new(
            NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        );
        let noise_squashing_key = NoiseSquashingKey::new(cks, &noise_squashing_private_key);

        let compression_private_key = NoiseSquashingCompressionPrivateKey::new(
            V1_3_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        );

        let compression_key = noise_squashing_private_key
            .new_noise_squashing_compression_key(&compression_private_key);

        let mut rng = thread_rng();

        let id_lut = sks.generate_lookup_table(|x| x);
        let max_ct_count =
            V1_3_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.lwe_per_glwe;

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

            // Extract from the list and decrypt
            let decrypted_values =
                compression_private_key.unpack_and_decrypt_squashed_noise_ciphertexts(&compressed);

            for (idx, value) in decrypted_values.iter().enumerate() {
                let dec_msg1 = value / (sks.message_modulus.0 as u128);
                let dec_msg2 = value % (sks.message_modulus.0 as u128);

                let msg = msgs[idx];

                assert_eq!(dec_msg1, msg.0 as u128);
                assert_eq!(dec_msg2, msg.1 as u128);
            }
        }
    }
}
