use super::{ClientKey, CompressedServerKey, ServerKey};
use crate::integer::client_key::secret_encryption_key::SecretEncryptionKey;
use crate::integer::IntegerCiphertext;
use crate::shortint::parameters::ShortintKeySwitchingParameters;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod test;

// This is used to have the ability to build a keyswitching key without owning the ServerKey
// It is a bit of a hack, but at this point it seems ok
pub(crate) struct KeySwitchingKeyBuildHelper<'keys> {
    pub(crate) build_helper: crate::shortint::key_switching_key::KeySwitchingKeyBuildHelper<'keys>,
}

impl<'keys> KeySwitchingKeyBuildHelper<'keys> {
    pub fn new<'input_key, InputEncryptionKey>(
        input_key_pair: (InputEncryptionKey, Option<&'keys ServerKey>),
        output_key_pair: (&'keys ClientKey, &'keys ServerKey),
        params: ShortintKeySwitchingParameters,
    ) -> Self
    where
        InputEncryptionKey: Into<SecretEncryptionKey<&'input_key [u64]>>,
    {
        let (secret_key, src_sks) = input_key_pair;
        let secret_key: SecretEncryptionKey<&[u64]> = secret_key.into();

        Self {
            build_helper: crate::shortint::key_switching_key::KeySwitchingKeyBuildHelper::new(
                (&secret_key.key, src_sks.map(AsRef::as_ref)),
                (output_key_pair.0.as_ref(), output_key_pair.1.as_ref()),
                params,
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeySwitchingKey {
    pub(crate) key: crate::shortint::KeySwitchingKey,
}

impl<'keys> From<KeySwitchingKeyBuildHelper<'keys>> for KeySwitchingKey {
    fn from(value: KeySwitchingKeyBuildHelper) -> Self {
        Self {
            key: value.build_helper.into(),
        }
    }
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

// This is used to have the ability to build a keyswitching key without owning the ServerKey
// It is a bit of a hack, but at this point it seems ok
pub(crate) struct CompressedKeySwitchingKeyBuildHelper<'keys> {
    pub(crate) build_helper:
        crate::shortint::key_switching_key::CompressedKeySwitchingKeyBuildHelper<'keys>,
}

impl<'keys> CompressedKeySwitchingKeyBuildHelper<'keys> {
    pub fn new<'input_key, InputEncryptionKey>(
        input_key_pair: (InputEncryptionKey, Option<&'keys CompressedServerKey>),
        output_key_pair: (&'keys ClientKey, &'keys CompressedServerKey),
        params: ShortintKeySwitchingParameters,
    ) -> Self
    where
        InputEncryptionKey: Into<SecretEncryptionKey<&'input_key [u64]>>,
    {
        let (secret_key, src_sks) = input_key_pair;
        let secret_key: SecretEncryptionKey<&[u64]> = secret_key.into();

        Self {
            build_helper:
                crate::shortint::key_switching_key::CompressedKeySwitchingKeyBuildHelper::new(
                    (&secret_key.key, src_sks.map(|k| &k.key)),
                    (output_key_pair.0.as_ref(), &output_key_pair.1.key),
                    params,
                ),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompressedKeySwitchingKey {
    pub(crate) key: crate::shortint::CompressedKeySwitchingKey,
}

impl<'keys> From<CompressedKeySwitchingKeyBuildHelper<'keys>> for CompressedKeySwitchingKey {
    fn from(value: CompressedKeySwitchingKeyBuildHelper) -> Self {
        Self {
            key: value.build_helper.into(),
        }
    }
}

impl CompressedKeySwitchingKey {
    pub fn new<'input_key, InputEncryptionKey, ClientKeyType>(
        input_key_pair: (InputEncryptionKey, Option<&CompressedServerKey>),
        output_key_pair: (&ClientKeyType, &CompressedServerKey),
        params: ShortintKeySwitchingParameters,
    ) -> Self
    where
        InputEncryptionKey: Into<SecretEncryptionKey<&'input_key [u64]>>,
        ClientKeyType: AsRef<ClientKey>,
    {
        let input_secret_encryption_key: SecretEncryptionKey<&[u64]> = input_key_pair.0.into();
        let ret = Self {
            key: crate::shortint::CompressedKeySwitchingKey::new(
                (
                    input_secret_encryption_key.key,
                    input_key_pair.1.map(|k| &k.key),
                ),
                (&output_key_pair.0.as_ref().key, &output_key_pair.1.key),
                params,
            ),
        };

        assert!(ret.key.cast_rshift == 0, "Attempt to build a CompressedKeySwitchingKey between integer key pairs with different message modulus and carry");

        ret
    }

    pub fn decompress(&self) -> KeySwitchingKey {
        KeySwitchingKey {
            key: self.key.decompress(),
        }
    }
}
