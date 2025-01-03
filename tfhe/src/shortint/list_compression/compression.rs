use super::{CompressionKey, DecompressionKey};
use crate::core_crypto::prelude::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::core_crypto::prelude::{
    extract_lwe_sample_from_glwe_ciphertext,
    par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext, CiphertextCount, GlweCiphertext,
    LweCiphertext, LweCiphertextCount, LweCiphertextList, MonomialDegree,
};
use crate::shortint::ciphertext::CompressedCiphertextList;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{CarryModulus, MessageModulus, NoiseLevel};
use crate::shortint::server_key::{
    apply_programmable_bootstrap_no_ms_noise_reduction, generate_lookup_table_with_output_encoding,
    unchecked_scalar_mul_assign, LookupTableSize, ShortintBootstrappingKey,
};
use crate::shortint::{Ciphertext, MaxNoiseLevel};
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;

impl CompressionKey {
    pub fn compress_ciphertexts_into_list(
        &self,
        ciphertexts: &[Ciphertext],
    ) -> CompressedCiphertextList {
        let count = CiphertextCount(ciphertexts.len());

        let lwe_pksk = &self.packing_key_switching_key;

        let polynomial_size = lwe_pksk.output_polynomial_size();
        let ciphertext_modulus = lwe_pksk.ciphertext_modulus();
        let glwe_size = lwe_pksk.output_glwe_size();
        let lwe_size = lwe_pksk.input_key_lwe_dimension().to_lwe_size();

        let lwe_per_glwe = self.lwe_per_glwe;

        assert!(
            lwe_per_glwe.0 <= polynomial_size.0,
            "Cannot pack more than polynomial_size(={}) elements per glwe, {} requested",
            polynomial_size.0,
            lwe_per_glwe.0,
        );

        let first_ct = &ciphertexts[0];

        let message_modulus = first_ct.message_modulus;
        let carry_modulus = first_ct.carry_modulus;
        let atomic_pattern = first_ct.atomic_pattern;

        assert!(
            message_modulus.0 <= carry_modulus.0,
            "GLWE packing is implemented with messages in carries, so carry_modulus (={}) must be greater than or equal to message_modulus (={})",
            carry_modulus.0,
            message_modulus.0 ,
        );

        let glwe_ct_list: Vec<_> = ciphertexts
            .par_chunks(lwe_per_glwe.0)
            .map(|ct_list| {
                let mut list: Vec<_> = vec![];

                for ct in ct_list {
                    assert!(
                        ct.noise_level() == NoiseLevel::NOMINAL
                            || ct.noise_level() == NoiseLevel::ZERO,
                        "Ciphertexts must have a nominal (post PBS) noise to be compressed"
                    );

                    assert!(
                        ct.carry_is_empty(),
                        "Ciphertexts must have empty carries to be compressed"
                    );

                    assert_eq!(
                        lwe_size,
                        ct.ct.lwe_size(),
                        "All ciphertexts do not have the same lwe size as the packing keyswitch key"
                    );

                    assert_eq!(
                        message_modulus, ct.message_modulus,
                        "All ciphertexts do not have the same message modulus"
                    );
                    assert_eq!(
                        carry_modulus, ct.carry_modulus,
                        "All ciphertexts do not have the same carry modulus"
                    );
                    assert_eq!(
                        atomic_pattern, ct.atomic_pattern,
                        "All ciphertexts do not have the same pbs order"
                    );

                    let mut ct = ct.clone();
                    let max_noise_level =
                        MaxNoiseLevel::new((ct.noise_level() * message_modulus.0).get());
                    unchecked_scalar_mul_assign(&mut ct, message_modulus.0 as u8, max_noise_level);

                    list.extend(ct.ct.as_ref());
                }

                let list = LweCiphertextList::from_container(list, lwe_size, ciphertext_modulus);

                let bodies_count = LweCiphertextCount(ct_list.len());

                let mut out =
                    GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);

                par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                    lwe_pksk, &list, &mut out,
                );

                CompressedModulusSwitchedGlweCiphertext::compress(
                    &out,
                    self.storage_log_modulus,
                    bodies_count,
                )
            })
            .collect();

        CompressedCiphertextList {
            modulus_switched_glwe_ciphertext_list: glwe_ct_list,
            message_modulus,
            carry_modulus,
            atomic_pattern,
            lwe_per_glwe,
            count,
            ciphertext_modulus,
        }
    }
}

impl DecompressionKey {
    pub fn unpack(
        &self,
        packed: &CompressedCiphertextList,
        index: usize,
    ) -> Result<Ciphertext, crate::Error> {
        // if packed.message_modulus.0 != packed.carry_modulus.0 {
        //     return Err(crate::Error::new(format!(
        //         "Tried to unpack values from a list where message modulus \
        //         ({:?}) is != carry modulus ({:?}), this is not supported.",
        //         packed.message_modulus, packed.carry_modulus,
        //     )));
        // }

        if index >= packed.count.0 {
            return Err(crate::Error::new(format!(
                "Tried getting index {index} for CompressedCiphertextList \
                with {} elements, out of bound access.",
                packed.count.0
            )));
        }

        let encryption_cleartext_modulus = packed.message_modulus.0 * packed.carry_modulus.0;
        // We multiply by message_modulus during compression so the actual modulus for the
        // compression is smaller
        let compression_cleartext_modulus = encryption_cleartext_modulus / packed.message_modulus.0;
        let effective_compression_message_modulus = MessageModulus(compression_cleartext_modulus);
        let effective_compression_carry_modulus = CarryModulus(1);
        let lut_size = LookupTableSize::new(self.out_glwe_size(), self.out_polynomial_size());

        let decompression_rescale = generate_lookup_table_with_output_encoding(
            lut_size,
            packed.ciphertext_modulus,
            // Input moduli are the effective compression ones
            effective_compression_message_modulus,
            effective_compression_carry_modulus,
            // Output moduli are directly the ones stored in the list
            packed.message_modulus,
            packed.carry_modulus,
            // Here we do not divide by message_modulus
            // Example: in the 2_2 case we are mapping a 2 bits message onto a 4 bits space, we
            // want to keep the original 2 bits value in the 4 bits space, so we apply the identity
            // and the encoding will rescale it for us.
            |x| x,
        );

        let polynomial_size = packed.modulus_switched_glwe_ciphertext_list[0].polynomial_size();
        let ciphertext_modulus = packed.ciphertext_modulus;
        let glwe_dimension = packed.modulus_switched_glwe_ciphertext_list[0].glwe_dimension();

        let lwe_per_glwe = packed.lwe_per_glwe.0;

        let lwe_size = glwe_dimension
            .to_equivalent_lwe_dimension(polynomial_size)
            .to_lwe_size();

        let glwe_index = index / lwe_per_glwe;

        let packed_glwe = packed.modulus_switched_glwe_ciphertext_list[glwe_index].extract();

        let monomial_degree = MonomialDegree(index % lwe_per_glwe);

        let mut intermediate_lwe = LweCiphertext::new(0, lwe_size, ciphertext_modulus);

        extract_lwe_sample_from_glwe_ciphertext(
            &packed_glwe,
            &mut intermediate_lwe,
            monomial_degree,
        );

        let mut output_br = LweCiphertext::new(
            0,
            self.blind_rotate_key.output_lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );

        match &self.blind_rotate_key {
            ShortintBootstrappingKey::Classic {
                bsk: _,
                modulus_switch_noise_reduction_key,
            } => {
                assert!(
                    modulus_switch_noise_reduction_key.is_none(),
                    "Decompression key should not do modulus switch noise reduction"
                );
            }
            ShortintBootstrappingKey::MultiBit { .. } => {
                panic!("Decompression can't use a multi bit PBS")
            }
        }

        ShortintEngine::with_thread_local_mut(|engine| {
            let buffers = engine.get_computation_buffers();

            apply_programmable_bootstrap_no_ms_noise_reduction(
                &self.blind_rotate_key,
                &intermediate_lwe,
                &mut output_br,
                &decompression_rescale.acc,
                buffers,
            );
        });

        Ok(Ciphertext::new(
            output_br,
            decompression_rescale.degree,
            NoiseLevel::NOMINAL,
            packed.message_modulus,
            packed.carry_modulus,
            packed.atomic_pattern,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::shortint::parameters::test_params::*;
    use crate::shortint::{gen_keys, ClientKey, ShortintParameterSet};
    use rayon::iter::IntoParallelIterator;

    #[test]
    fn test_packing_ci_run_filter() {
        for (params, comp_params) in [
            (
                TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
            (
                TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                TEST_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        ] {
            // Generate the client key and the server key:
            let (cks, _sks) = gen_keys::<ShortintParameterSet>(params);

            let private_compression_key: crate::shortint::list_compression::CompressionPrivateKeys =
                cks.new_compression_private_key(comp_params);

            let (compression_key, decompression_key) =
                cks.new_compression_decompression_keys(&private_compression_key);

            for number_to_pack in [1, 128] {
                let f = |x| (x + 1) % params.message_modulus().0;

                test_packing_(
                    &compression_key,
                    &decompression_key,
                    &cks,
                    f,
                    number_to_pack,
                );
            }
        }
    }

    fn test_packing_(
        comp_key: &CompressionKey,
        decomp_key: &DecompressionKey,
        cks: &ClientKey,
        f: impl Fn(u64) -> u64 + Sync,
        number_to_pack: usize,
    ) {
        let ct: Vec<_> = (0..number_to_pack)
            .map(|i| cks.encrypt(f(i as u64)))
            .collect();

        let packed = comp_key.compress_ciphertexts_into_list(&ct);

        (0..number_to_pack).into_par_iter().for_each(|i| {
            let unpacked = decomp_key.unpack(&packed, i).unwrap();

            let res = cks.decrypt_message_and_carry(&unpacked);

            assert_eq!(f(i as u64), res);
        });
    }
}
