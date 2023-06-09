use crate::boolean::engine::{BooleanEngine, WithThreadLocalEngine};
use crate::boolean::prelude::Ciphertext;
use crate::boolean::ClientKey;

use crate::core_crypto::prelude::{keyswitch_lwe_ciphertext, LweKeyswitchKeyOwned};

#[cfg(test)]
mod test_cast;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CastingKey {
    pub(crate) key_switching_key: LweKeyswitchKeyOwned<u32>,
}

impl CastingKey {
    pub fn new(ck1: &ClientKey, ck2: &ClientKey) -> Self {
        Self {
            key_switching_key: BooleanEngine::with_thread_local_mut(|engine| {
                engine.new_key_switching_key(ck1, ck2)
            }),
        }
    }

    pub fn cast_assign(&self, ct: &Ciphertext, ct_dest: &mut Ciphertext) {
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
                        keyswitch_lwe_ciphertext(&self.key_switching_key, cipher, cipher_dest)
                    }
                };
            }
        }
    }

    pub fn cast(&self, ct: &Ciphertext) -> Ciphertext {
        let mut ret = ct.clone();
        self.cast_assign(ct, &mut ret);
        ret
    }
}
