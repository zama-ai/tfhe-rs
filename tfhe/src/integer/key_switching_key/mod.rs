use super::{ClientKey, ServerKey};
use crate::integer::client_key::secret_encryption_key::SecretEncryptionKey;
use crate::integer::IntegerCiphertext;
use crate::shortint::parameters::ShortintKeySwitchingParameters;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod test;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeySwitchingKey {
    pub(crate) key: crate::shortint::KeySwitchingKey,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KeySwitchingKeyView<'keys> {
    pub(crate) key: crate::shortint::KeySwitchingKeyView<'keys>,
}

impl KeySwitchingKey {
    pub fn new<'input_key, InputEncryptionKey, ClientKeyType>(
        input_key_pair: (InputEncryptionKey, Option<&ServerKey>),
        output_key_pair: (&ClientKeyType, &ServerKey),
        params: ShortintKeySwitchingParameters,
    ) -> Self
    where
        InputEncryptionKey: Into<SecretEncryptionKey<&'input_key [u64]>>,
        ClientKeyType: AsRef<ClientKey>,
    {
        let input_secret_encryption_key: SecretEncryptionKey<&[u64]> = input_key_pair.0.into();
        let ret = Self {
            key: crate::shortint::KeySwitchingKey::new(
                (
                    input_secret_encryption_key.key,
                    input_key_pair.1.map(|k| &k.key),
                ),
                (&output_key_pair.0.as_ref().key, &output_key_pair.1.key),
                params,
            ),
        };

        assert!(ret.key.cast_rshift == 0, "Attempt to build a KeySwitchingKey between integer key pairs with different message modulus and carry");

        ret
    }

    /// Deconstruct a [`KeySwitchingKey`] into its constituents.
    pub fn into_raw_parts(self) -> crate::shortint::KeySwitchingKey {
        self.key
    }

    /// Construct a [`KeySwitchingKey`] from its constituents.
    pub fn from_raw_parts(key: crate::shortint::KeySwitchingKey) -> Self {
        Self { key }
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

    pub fn as_view(&self) -> KeySwitchingKeyView<'_> {
        KeySwitchingKeyView {
            key: self.key.as_view(),
        }
    }
}
