use crate::core_crypto::algorithms::lwe_encryption::re_randomization::rerand_encrypt_lwe_compact_ciphertext_list_with_compact_public_key;
use crate::core_crypto::commons::generators::NoiseRandomGenerator;
use crate::core_crypto::gpu::lwe_compact_ciphertext_list::CudaLweCompactCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{LweCompactCiphertextList, PlaintextCount, PlaintextList};
use crate::integer::ciphertext::ReRandomizationSeed;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{
    CudaRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::cuda_backend_rerand_assign;
use crate::integer::gpu::key_switching_key::CudaKeySwitchingKeyMaterial;
use crate::integer::CompactPublicKey;
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::PBSOrder;
use tfhe_csprng::generators::DefaultRandomGenerator;

impl CudaUnsignedRadixCiphertext {
    pub fn re_randomize(
        &mut self,
        compact_public_key: &CompactPublicKey,
        key_switching_key_material: &CudaKeySwitchingKeyMaterial,
        seed: ReRandomizationSeed,
        streams: &CudaStreams,
    ) -> crate::Result<()> {
        self.ciphertext.re_randomize(
            compact_public_key,
            key_switching_key_material,
            seed,
            streams,
        )
    }
}

impl CudaSignedRadixCiphertext {
    pub fn re_randomize(
        &mut self,
        compact_public_key: &CompactPublicKey,
        key_switching_key_material: &CudaKeySwitchingKeyMaterial,
        seed: ReRandomizationSeed,
        streams: &CudaStreams,
    ) -> crate::Result<()> {
        self.ciphertext.re_randomize(
            compact_public_key,
            key_switching_key_material,
            seed,
            streams,
        )
    }
}

impl CudaBooleanBlock {
    pub fn re_randomize(
        &mut self,
        compact_public_key: &CompactPublicKey,
        key_switching_key_material: &CudaKeySwitchingKeyMaterial,
        seed: ReRandomizationSeed,
        streams: &CudaStreams,
    ) -> crate::Result<()> {
        self.0.re_randomize(
            compact_public_key,
            key_switching_key_material,
            seed,
            streams,
        )
    }
}

impl CudaRadixCiphertext {
    pub fn re_randomize(
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
                println!("{:?} {:?}", ct.atomic_pattern.pbs_order(), ksk_pbs_order);
                Some(
                    "Mismatched PBSOrder between Ciphertext being re-randomized and provided \
                KeySwitchingKeyMaterialView.",
                )
            } else if ksk_output_lwe_size != self.d_blocks.0.lwe_dimension.to_lwe_size() {
                Some(
                    "Mismatched LweSwize between Ciphertext being re-randomized and provided \
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
            != self.d_blocks.lwe_dimension().to_lwe_size()
        {
            return Err(crate::error!(
                "Mismatched LweDimension between provided CompactPublicKey and \
                KeySwitchingKeyMaterialView input LweDimension.",
            ));
        }

        let mut encryption_generator =
            NoiseRandomGenerator::<DefaultRandomGenerator>::new_from_seed(seed.0);

        let lwe_ciphertext_count = self.d_blocks.lwe_ciphertext_count();
        let mut encryption_of_zero = LweCompactCiphertextList::new(
            0,
            self.d_blocks.lwe_dimension().to_lwe_size(),
            lwe_ciphertext_count,
            self.d_blocks.ciphertext_modulus(),
        );

        let plaintext_list = PlaintextList::new(
            0,
            PlaintextCount(encryption_of_zero.lwe_ciphertext_count().0),
        );

        let cpk_encryption_noise_distribution = compact_public_key
            .key
            .parameters()
            .encryption_noise_distribution;

        rerand_encrypt_lwe_compact_ciphertext_list_with_compact_public_key(
            &compact_public_key.key.key,
            &mut encryption_of_zero,
            &plaintext_list,
            cpk_encryption_noise_distribution,
            cpk_encryption_noise_distribution,
            &mut encryption_generator,
        );

        let d_zero_lwes = CudaLweCompactCiphertextList::from_lwe_compact_ciphertext_list(
            &encryption_of_zero,
            streams,
        );

        let first_info = self.info.blocks.first().unwrap();
        let message_modulus = first_info.message_modulus;
        let carry_modulus = first_info.carry_modulus;

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
                lwe_ciphertext_count.0 as u32,
            );
        }

        self.info.blocks.iter_mut().for_each(|ct| {
            ct.noise_level = NoiseLevel::NOMINAL;
        });

        Ok(())
    }
}
