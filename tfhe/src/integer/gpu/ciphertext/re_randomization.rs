use crate::core_crypto::gpu::lwe_compact_ciphertext_list::CudaLweCompactCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::ciphertext::ReRandomizationSeed;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{
    CudaRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::key_switching_key::CudaKeySwitchingKeyMaterial;
use crate::integer::gpu::{
    cuda_backend_rerand_assign, cuda_backend_rerand_without_keyswitch_assign,
};
use crate::integer::CompactPublicKey;
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::PBSOrder;

#[derive(Clone, Copy)]
pub enum CudaReRandomizationKey<'key> {
    LegacyDedicatedCPK {
        cpk: &'key CompactPublicKey,
        ksk: &'key CudaKeySwitchingKeyMaterial,
    },
    DerivedCPKWithoutKeySwitch {
        cpk: &'key CompactPublicKey,
    },
}

impl CudaUnsignedRadixCiphertext {
    pub fn re_randomize(
        &mut self,
        re_randomization_key: CudaReRandomizationKey<'_>,
        seed: ReRandomizationSeed,
        streams: &CudaStreams,
    ) -> crate::Result<()> {
        self.ciphertext
            .re_randomize(re_randomization_key, seed, streams)
    }
}

impl CudaSignedRadixCiphertext {
    pub fn re_randomize(
        &mut self,
        re_randomization_key: CudaReRandomizationKey<'_>,
        seed: ReRandomizationSeed,
        streams: &CudaStreams,
    ) -> crate::Result<()> {
        self.ciphertext
            .re_randomize(re_randomization_key, seed, streams)
    }
}

impl CudaBooleanBlock {
    pub fn re_randomize(
        &mut self,
        re_randomization_key: CudaReRandomizationKey<'_>,
        seed: ReRandomizationSeed,
        streams: &CudaStreams,
    ) -> crate::Result<()> {
        self.0.re_randomize(re_randomization_key, seed, streams)
    }
}

impl CudaRadixCiphertext {
    pub fn re_randomize(
        &mut self,
        re_randomization_key: CudaReRandomizationKey<'_>,
        seed: ReRandomizationSeed,
        streams: &CudaStreams,
    ) -> crate::Result<()> {
        match re_randomization_key {
            CudaReRandomizationKey::LegacyDedicatedCPK {
                cpk: compact_public_key,
                ksk: key_switching_key_material,
            } => self.re_randomize_ciphertexts_with_keyswitch(
                compact_public_key,
                key_switching_key_material,
                seed,
                streams,
            ),
            CudaReRandomizationKey::DerivedCPKWithoutKeySwitch {
                cpk: compact_public_key,
            } => self.re_randomize_ciphertexts_without_keyswitch(compact_public_key, seed, streams),
        }
    }

    fn re_randomize_ciphertexts_with_keyswitch(
        &mut self,
        compact_public_key: &CompactPublicKey,
        key_switching_key_material: &CudaKeySwitchingKeyMaterial,
        seed: ReRandomizationSeed,
        streams: &CudaStreams,
    ) -> crate::Result<()> {
        let ksk_pbs_order = key_switching_key_material.destination_key.into_pbs_order();
        let ksk_output_lwe_size = key_switching_key_material
            .lwe_keyswitch_key
            .output_key_lwe_size();

        if let Some(msg) = self.info.blocks.iter().find_map(|ct| {
            if ct.atomic_pattern.pbs_order() != ksk_pbs_order {
                Some(
                    "Mismatched PBSOrder between Ciphertext being re-randomized and provided \
                KeySwitchingKeyMaterialView.",
                )
            } else if ksk_output_lwe_size != self.d_blocks.0.lwe_dimension.to_lwe_size() {
                Some(
                    "Mismatched LweSize between Ciphertext being re-randomized and provided \
                KeySwitchingKeyMaterialView.",
                )
            } else if ct.noise_level > NoiseLevel::NOMINAL {
                Some("Tried to re-randomize a Ciphertext with non-nominal NoiseLevel.")
            } else {
                None
            }
        }) {
            return Err(crate::error!("{}", msg));
        }

        if ksk_pbs_order != PBSOrder::KeyswitchBootstrap {
            // message is ok since we know that ksk order == cts order
            return Err(crate::error!(
                "Tried to re-randomize a Ciphertext with unsupported PBSOrder. \
                Required PBSOrder::KeyswitchBootstrap.",
            ));
        }

        if key_switching_key_material.cast_rshift != 0 {
            return Err(crate::error!(
                "Tried to re-randomize a Ciphertext using KeySwitchingKeyMaterialView \
                with non-zero cast_rshift, this is unsupported.",
            ));
        }

        if key_switching_key_material
            .lwe_keyswitch_key
            .input_key_lwe_size()
            != compact_public_key
                .parameters()
                .encryption_lwe_dimension
                .to_lwe_size()
        {
            return Err(crate::error!(
                "Mismatched LweDimension between provided CompactPublicKey and \
                KeySwitchingKeyMaterialView input LweDimension.",
            ));
        }

        let lwe_ciphertext_count = self.d_blocks.lwe_ciphertext_count();

        let encryption_of_zero = compact_public_key
            .key
            .prepare_cpk_zero_for_rerand(seed, lwe_ciphertext_count);

        let d_zero_lwes = CudaLweCompactCiphertextList::from_lwe_compact_ciphertext_list(
            &encryption_of_zero,
            streams,
        );

        let first_info = self.info.blocks.first().unwrap();
        let message_modulus = first_info.message_modulus;
        let carry_modulus = first_info.carry_modulus;

        // SAFETY: we have exclusive mutable access to `d_blocks` via `&mut self`,
        // `d_zero_lwes` and `keyswitch_key` remain valid for the kernel duration,
        // and the function synchronizes before returning.
        unsafe {
            cuda_backend_rerand_assign(
                streams,
                &mut self.d_blocks,
                &d_zero_lwes,
                &key_switching_key_material.lwe_keyswitch_key,
                message_modulus,
                carry_modulus,
                key_switching_key_material
                    .lwe_keyswitch_key
                    .input_key_lwe_size()
                    .to_lwe_dimension(),
                key_switching_key_material
                    .lwe_keyswitch_key
                    .output_key_lwe_size()
                    .to_lwe_dimension(),
                key_switching_key_material
                    .lwe_keyswitch_key
                    .decomposition_level_count(),
                key_switching_key_material
                    .lwe_keyswitch_key
                    .decomposition_base_log(),
                u32::try_from(lwe_ciphertext_count.0).unwrap(),
            );
        }

        self.info.blocks.iter_mut().for_each(|ct| {
            ct.noise_level = NoiseLevel::NOMINAL;
        });

        Ok(())
    }

    fn re_randomize_ciphertexts_without_keyswitch(
        &mut self,
        compact_public_key: &CompactPublicKey,
        seed: ReRandomizationSeed,
        streams: &CudaStreams,
    ) -> crate::Result<()> {
        let key_lwe_size = compact_public_key.key.key.lwe_dimension().to_lwe_size();

        // We assume all LWEs in a CudaLweCiphertextList have the same LweSize, so this is ok
        if key_lwe_size != self.d_blocks.lwe_dimension().to_lwe_size() {
            let err = "Mismatched LweSize between Ciphertext being re-randomized and provided \
                CompactPublicKey.";
            return Err(crate::error!("{}", err));
        }

        if let Some(msg) = self.info.blocks.iter().find_map(|ct| {
            if ct.noise_level > NoiseLevel::NOMINAL {
                Some("Tried to re-randomize a Ciphertext with non-nominal NoiseLevel.")
            } else {
                None
            }
        }) {
            return Err(crate::error!("{}", msg));
        }

        let lwe_ciphertext_count = self.d_blocks.lwe_ciphertext_count();
        let encryption_of_zero = compact_public_key
            .key
            .prepare_cpk_zero_for_rerand(seed, lwe_ciphertext_count);

        let d_zero_lwes = CudaLweCompactCiphertextList::from_lwe_compact_ciphertext_list(
            &encryption_of_zero,
            streams,
        );

        let first_info = self.info.blocks.first().unwrap();
        let message_modulus = first_info.message_modulus;
        let carry_modulus = first_info.carry_modulus;

        // SAFETY: we have exclusive mutable access to `d_blocks` via `&mut self`,
        // `d_zero_lwes` remains valid for the kernel duration, and the function
        // synchronizes before returning.
        unsafe {
            cuda_backend_rerand_without_keyswitch_assign(
                streams,
                &mut self.d_blocks,
                &d_zero_lwes,
                message_modulus,
                carry_modulus,
                u32::try_from(lwe_ciphertext_count.0).unwrap(),
            );
        }

        self.info.blocks.iter_mut().for_each(|ct| {
            ct.noise_level = NoiseLevel::NOMINAL;
        });

        Ok(())
    }
}
