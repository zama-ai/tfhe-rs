use super::{ClientKey, ServerKey};

use crate::integer::IntegerCiphertext;
use crate::shortint::parameters::ShortintKeySwitchingParameters;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod test;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeySwitchingKey {
    key: crate::shortint::KeySwitchingKey,
}

impl KeySwitchingKey {
    pub fn new<ClientKeyType>(
        key_pair_1: (&ClientKeyType, &ServerKey),
        key_pair_2: (&ClientKeyType, &ServerKey),
        params: ShortintKeySwitchingParameters,
    ) -> Self
    where
        ClientKeyType: AsRef<ClientKey>,
    {
        let ret = Self {
            key: crate::shortint::KeySwitchingKey::new(
                (&key_pair_1.0.as_ref().key, &key_pair_1.1.key),
                (&key_pair_2.0.as_ref().key, &key_pair_2.1.key),
                params,
            ),
        };

        assert!(ret.key.cast_rshift == 0, "Attempt to build a KeySwitchingKey between integer key pairs with different message modulus and carry");

        ret
    }

    pub fn cast_into<Int: IntegerCiphertext>(&self, ct: &Int, ct_dest: &mut Int) {
        assert_eq!(ct.blocks().len(), ct_dest.blocks().len());

        ct.blocks()
            .par_iter()
            .zip(ct_dest.blocks_mut().par_iter_mut())
            .for_each(|(b1, b2)| self.key.cast_into(b1, b2));
    }

    pub fn cast<Int: IntegerCiphertext>(&self, ct: &Int) -> Int {
        Int::from_blocks(
            ct.blocks()
                .par_iter()
                .map(|b| {
                    let mut ret = self.key.cast(b);

                    // These next 2 lines are to handle Crt ciphertexts
                    ret.message_modulus = b.message_modulus;
                    ret.carry_modulus = b.carry_modulus;

                    ret
                })
                .collect::<Vec<_>>(),
        )
    }
}
