use tfhe_versionable::Versionize;

use crate::boolean::engine::{BooleanEngine, WithThreadLocalEngine};
use crate::boolean::parameters::BooleanKeySwitchingParameters;
use crate::boolean::prelude::Ciphertext;
use crate::boolean::ClientKey;
use crate::core_crypto::prelude::{keyswitch_lwe_ciphertext, LweKeyswitchKeyOwned};

use super::backward_compatibility::key_switching_key::KeySwitchingKeyVersions;

#[cfg(test)]
mod test;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(KeySwitchingKeyVersions)]
pub struct KeySwitchingKey {
    pub(crate) key_switching_key: LweKeyswitchKeyOwned<u32>,
}

impl KeySwitchingKey {
    pub fn new(ck1: &ClientKey, ck2: &ClientKey, params: BooleanKeySwitchingParameters) -> Self {
        Self {
            key_switching_key: BooleanEngine::with_thread_local_mut(|engine| {
                engine.new_key_switching_key(ck1, ck2, params)
            }),
        }
    }

    /// Deconstruct a [`KeySwitchingKey`] into its constituents.
    pub fn into_raw_parts(self) -> LweKeyswitchKeyOwned<u32> {
        self.key_switching_key
    }

    /// Construct a [`KeySwitchingKey`] from its constituents.
    pub fn from_raw_parts(key_switching_key: LweKeyswitchKeyOwned<u32>) -> Self {
        Self { key_switching_key }
    }

    pub fn cast_into(&self, ct: &Ciphertext, ct_dest: &mut Ciphertext) {
        match ct {
            Ciphertext::Trivial(_) => *ct_dest = ct.clone(),
            Ciphertext::Encrypted(ref cipher) => {
                match ct_dest {
                    Ciphertext::Trivial(_) => {
                        let mut cipher_dest = cipher.clone();
                        keyswitch_lwe_ciphertext(&self.key_switching_key, cipher, &mut cipher_dest);
                        *ct_dest = Ciphertext::Encrypted(cipher_dest);
                    }
                    Ciphertext::Encrypted(ref mut cipher_dest) => {
                        keyswitch_lwe_ciphertext(&self.key_switching_key, cipher, cipher_dest);
                    }
                };
            }
        }
    }

    pub fn cast(&self, ct: &Ciphertext) -> Ciphertext {
        let mut ret = ct.clone();
        self.cast_into(ct, &mut ret);
        ret
    }
}
