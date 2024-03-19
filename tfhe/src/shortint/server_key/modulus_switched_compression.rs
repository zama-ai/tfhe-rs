use super::ShortintBootstrappingKey;
use crate::core_crypto::prelude::compressed_modulus_switched_lwe_ciphertext::CompressedModulusSwitchedLweCiphertext;
use crate::core_crypto::prelude::{keyswitch_lwe_ciphertext, CiphertextModulusLog, LweCiphertext};
use crate::shortint::ciphertext::{CompressedModulusSwitchedCiphertext, NoiseLevel};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::server_key::{apply_programmable_bootstrap, LookupTableOwned};
use crate::shortint::{Ciphertext, PBSOrder, ServerKey};

impl ServerKey {
    /// Compresses a ciphertext to have a smaller serialization size
    ///
    /// See [`CompressedModulusSwitchedCiphertext#example`] for usage
    pub fn switch_modulus_and_compress(
        &self,
        ct: &Ciphertext,
    ) -> CompressedModulusSwitchedCiphertext {
        if let ShortintBootstrappingKey::MultiBit { .. } = &self.bootstrapping_key {
            panic!("Modulus switch compression and multi bit PBS are currently not compatible")
        }

        let compressed_modulus_switched_lwe_ciphertext = match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => {
                let ms_ed = ShortintEngine::with_thread_local_mut(|engine| {
                    let (mut ciphertext_buffers, _) = engine.get_buffers(self);

                    keyswitch_lwe_ciphertext(
                        &self.key_switching_key,
                        &ct.ct,
                        &mut ciphertext_buffers.buffer_lwe_after_ks,
                    );

                    CompressedModulusSwitchedLweCiphertext::compress(
                        &ciphertext_buffers.buffer_lwe_after_ks,
                        CiphertextModulusLog(self.bootstrapping_key.polynomial_size().log2().0 + 1),
                    )
                });

                ms_ed
            }
            PBSOrder::BootstrapKeyswitch => CompressedModulusSwitchedLweCiphertext::compress(
                &ct.ct,
                CiphertextModulusLog(self.bootstrapping_key.polynomial_size().log2().0 + 1),
            ),
        };

        CompressedModulusSwitchedCiphertext {
            compressed_modulus_switched_lwe_ciphertext,
            degree: ct.degree,
            message_modulus: ct.message_modulus,
            carry_modulus: ct.carry_modulus,
            pbs_order: ct.pbs_order,
        }
    }

    /// Decompresses a compressed ciphertext
    /// The degree from before the compression is conserved.
    /// This operation uses a PBS. Fot the same cost, it's possible to apply a lookup table by
    /// calling `decompress_and_apply_lookup_table` instead.
    ///
    /// See [`CompressedModulusSwitchedCiphertext#example`] for usage
    pub fn decompress(&self, compressed_ct: &CompressedModulusSwitchedCiphertext) -> Ciphertext {
        let acc = self.generate_lookup_table(|a| a);

        let mut result = self.decompress_and_apply_lookup_table(compressed_ct, &acc);

        result.degree = compressed_ct.degree;

        result
    }

    /// Decompresses a compressed ciphertext
    /// This operation uses a PBS so we can apply a lookup table
    /// An identity lookup table may be applied to get the pre compression ciphertext with a nominal
    /// noise, however, it's better to call `decompress` for that because it conserves the degree
    /// instead of setting it to the  max of the lookup table
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear = 3;
    ///
    /// let ctxt = cks.unchecked_encrypt(clear);
    ///
    /// // Can be serialized in a smaller buffer
    /// let compressed_ct = sks.switch_modulus_and_compress(&ctxt);
    ///
    /// let lut = sks.generate_lookup_table(|a| a + 1);
    ///
    /// let decompressed_ct = sks.decompress_and_apply_lookup_table(&compressed_ct, &lut);
    ///
    /// let dec = cks.decrypt_message_and_carry(&decompressed_ct);
    ///
    /// assert_eq!(clear + 1, dec);
    /// ```
    pub fn decompress_and_apply_lookup_table(
        &self,
        compressed_ct: &CompressedModulusSwitchedCiphertext,
        acc: &LookupTableOwned,
    ) -> Ciphertext {
        if let ShortintBootstrappingKey::MultiBit { .. } = &self.bootstrapping_key {
            panic!("Modulus switch compression and multi bit PBS are currently not compatible")
        }

        let ct = compressed_ct
            .compressed_modulus_switched_lwe_ciphertext
            .extract();

        let mut output = LweCiphertext::from_container(
            vec![0; self.ciphertext_lwe_dimension().to_lwe_size().0],
            self.ciphertext_modulus,
        );

        ShortintEngine::with_thread_local_mut(|engine| {
            let (mut ciphertext_buffers, buffers) = engine.get_buffers(self);
            match self.pbs_order {
                PBSOrder::KeyswitchBootstrap => {
                    apply_programmable_bootstrap(
                        &self.bootstrapping_key,
                        &ct,
                        &mut output,
                        acc,
                        buffers,
                    );
                }
                PBSOrder::BootstrapKeyswitch => {
                    apply_programmable_bootstrap(
                        &self.bootstrapping_key,
                        &ct,
                        &mut ciphertext_buffers.buffer_lwe_after_pbs,
                        acc,
                        buffers,
                    );

                    keyswitch_lwe_ciphertext(
                        &self.key_switching_key,
                        &ciphertext_buffers.buffer_lwe_after_pbs,
                        &mut output,
                    );
                }
            }
        });

        Ciphertext::new(
            output,
            acc.degree,
            NoiseLevel::NOMINAL,
            compressed_ct.message_modulus,
            compressed_ct.carry_modulus,
            compressed_ct.pbs_order,
        )
    }
}
