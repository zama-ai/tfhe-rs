use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;

use crate::core_crypto::prelude::{
    par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext, CiphertextCount, GlweCiphertext,
    GlweCiphertextCount, GlweCiphertextList, LweCiphertextList,
};
use crate::shortint::ciphertext::{CompressedSquashedNoiseCiphertextList, SquashedNoiseCiphertext};
use crate::shortint::MessageModulus;

use super::server_keys::NoiseSquashingCompressionKey;

impl NoiseSquashingCompressionKey {
    /// Compress a list of [`SquashedNoiseCiphertext`] into a GLWE list.
    ///
    /// This is similar to [`CompressionKey::compress_ciphertexts_into_list`], except that the
    /// resulting GLWE are not modulus switched. This means that it is possible to extract the
    /// ciphertext from the list without a PBS.
    ///
    /// [`CompressionKey::compress_ciphertexts_into_list`]: crate::shortint::list_compression::CompressionKey::compress_ciphertexts_into_list
    pub fn compress_noise_squashed_ciphertexts_into_list(
        &self,
        ciphertexts: &[SquashedNoiseCiphertext],
    ) -> CompressedSquashedNoiseCiphertextList {
        let lwe_pksk = &self.packing_key_switching_key;
        let lwe_per_glwe = self.lwe_per_glwe;
        let ciphertext_modulus = lwe_pksk.ciphertext_modulus();
        let polynomial_size = lwe_pksk.output_polynomial_size();
        let glwe_size = lwe_pksk.output_glwe_size();

        if ciphertexts.is_empty() {
            return CompressedSquashedNoiseCiphertextList {
                glwe_ciphertext_list: GlweCiphertextList::new(
                    0,
                    glwe_size,
                    polynomial_size,
                    GlweCiphertextCount(0),
                    ciphertext_modulus,
                ),
                // These values don't matter if the list is empty
                message_modulus: MessageModulus(1),
                lwe_per_glwe,
                count: CiphertextCount(0),
            };
        }

        let count = CiphertextCount(ciphertexts.len());

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

        let glwe_ct_list: Vec<_> = ciphertexts
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

                    list.extend(ct.lwe_ciphertext().as_ref());
                }

                let list = LweCiphertextList::from_container(list, lwe_size, ciphertext_modulus);

                let mut out =
                    GlweCiphertext::new(0u128, glwe_size, polynomial_size, ciphertext_modulus);

                par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                    lwe_pksk, &list, &mut out,
                );

                out.into_container()
            })
            .flatten()
            .collect();

        let glwe_ciphertext_list = GlweCiphertextList::from_container(
            glwe_ct_list,
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        );

        CompressedSquashedNoiseCiphertextList {
            glwe_ciphertext_list,
            message_modulus,
            lwe_per_glwe,
            count,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::shortint::keycache::KEY_CACHE;
    use crate::shortint::list_compression::private_key::NoiseSquashingCompressionPrivateKey;
    use crate::shortint::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
    use crate::shortint::parameters::list_compression::NoiseSquashingCompressionParameters;
    use crate::shortint::parameters::*;

    use rand::prelude::*;
    use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

    #[test]
    fn test_noise_squashing_compression_ci_run_filter() {
        const TEST_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
            NoiseSquashingParameters = NoiseSquashingParameters {
            glwe_dimension: GlweDimension(4),
            polynomial_size: PolynomialSize(1024),
            glwe_noise_distribution: DynamicDistribution::new_t_uniform(30),
            decomp_base_log: DecompositionBaseLog(32),
            decomp_level_count: DecompositionLevelCount(2),
            modulus_switch_noise_reduction_params: Some(ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(19),
                ms_bound: NoiseEstimationMeasureBound(2.88230376151712E+017f64),
                ms_r_sigma_factor: RSigmaFactor(6.11765253740946f64),
                ms_input_variance: Variance(2.53571133302789E-07f64),
            }),
            ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
        };

        const TEST_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
            NoiseSquashingCompressionParameters = NoiseSquashingCompressionParameters {
            packing_ks_level: DecompositionLevelCount(1),
            packing_ks_base_log: DecompositionBaseLog(60),
            packing_ks_polynomial_size: PolynomialSize(1024),
            packing_ks_glwe_dimension: GlweDimension(5),
            lwe_per_glwe: LweCiphertextCount(128),
            packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(4),
            ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
        };

        let keycache_entry =
            KEY_CACHE.get_from_param(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
        let (cks, sks) = (keycache_entry.client_key(), keycache_entry.server_key());
        let noise_squashing_private_key = NoiseSquashingPrivateKey::new(
            cks,
            TEST_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        );
        let noise_squashing_key = NoiseSquashingKey::new(cks, &noise_squashing_private_key);

        let compression_private_key = NoiseSquashingCompressionPrivateKey::new(
            TEST_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        );

        let compression_key = noise_squashing_private_key
            .new_noise_squashing_compression_key(&compression_private_key);
        let decryption_key = compression_private_key.into_noise_squashing_private_key();

        let mut rng = thread_rng();

        let id_lut = sks.generate_lookup_table(|x| x);

        for number_to_pack in [0, 1, 128] {
            // Generate random msgs
            let msgs: Vec<_> = (0..number_to_pack)
                .map(|_| {
                    (
                        rng.gen::<u64>() % cks.parameters.message_modulus().0,
                        rng.gen::<u64>() % cks.parameters.message_modulus().0,
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
            msgs.par_iter()
                .enumerate()
                .for_each(|(idx, (msg_1, msg_2))| {
                    let noise_squashed = compressed.unpack(idx).unwrap();

                    let recovered =
                        decryption_key.decrypt_squashed_noise_ciphertext(&noise_squashed);

                    let expected_u128: u128 = (msg_1 * sks.message_modulus.0 + msg_2).into();
                    assert_eq!(recovered, expected_u128);
                })
        }
    }
}
