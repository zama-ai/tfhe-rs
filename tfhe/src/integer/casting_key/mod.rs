use super::{ClientKey, ServerKey};

use crate::integer::IntegerCiphertext;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod test_cast;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CastingKey {
    key: crate::shortint::CastingKey,
}

impl CastingKey {
    pub fn new<ClientKeyType>(
        key_pair_1: (&ClientKeyType, &ServerKey),
        key_pair_2: (&ClientKeyType, &ServerKey),
    ) -> Self
    where
        ClientKeyType: AsRef<ClientKey>,
    {
        let ret = Self {
            key: crate::shortint::CastingKey::new(
                (&key_pair_1.0.as_ref().key, &key_pair_1.1.key),
                (&key_pair_2.0.as_ref().key, &key_pair_2.1.key),
            ),
        };

        if ret.key.cast_rshift != 0 {
            panic!("Attempt to build a CastingKey between integer key pairs with different message modulus and carry");
        }

        ret
    }

    pub fn cast_assign<Int: IntegerCiphertext>(&self, ct: &Int, ct_dest: &mut Int) {
        assert_eq!(ct.blocks().len(), ct_dest.blocks().len());

        ct.blocks()
            .par_iter()
            .zip(ct_dest.blocks_mut().par_iter_mut())
            .for_each(|(b1, b2)| self.key.cast_assign(b1, b2));
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
