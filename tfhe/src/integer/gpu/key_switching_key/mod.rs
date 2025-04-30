use crate::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::CudaServerKey;
use crate::integer::key_switching_key::KeySwitchingKey;
use crate::shortint::EncryptionKeyChoice;

#[derive(Clone)]
#[allow(dead_code)]
pub struct CudaKeySwitchingKeyMaterial {
    pub(crate) lwe_keyswitch_key: CudaLweKeyswitchKey<u64>,
    pub(crate) destination_key: EncryptionKeyChoice,
}

#[allow(dead_code)]
pub struct CudaKeySwitchingKey<'key> {
    pub(crate) key_switching_key_material: &'key CudaKeySwitchingKeyMaterial,
    pub(crate) dest_server_key: &'key CudaServerKey,
}

impl CudaKeySwitchingKeyMaterial {
    pub fn from_key_switching_key(
        key_switching_key: &KeySwitchingKey,
        streams: &CudaStreams,
    ) -> Self {
        let key_switching_key_material = &key_switching_key.key.key_switching_key_material;
        let d_lwe_keyswich_key = CudaLweKeyswitchKey::from_lwe_keyswitch_key(
            &key_switching_key_material.key_switching_key,
            streams,
        );
        Self {
            lwe_keyswitch_key: d_lwe_keyswich_key,
            destination_key: key_switching_key_material.destination_key,
        }
    }
}

impl<'key> CudaKeySwitchingKey<'key> {
    pub fn from_cuda_key_switching_key_material(
        key_switching_key_material: &'key CudaKeySwitchingKeyMaterial,
        dest_server_key: &'key CudaServerKey,
    ) -> Self {
        Self {
            key_switching_key_material,
            dest_server_key,
        }
    }
}
