use crate::integer::client_key::secret_encryption_key::SecretEncryptionKeyView;
use crate::integer::key_switching_key::KeySwitchingKey;
use crate::integer::{ClientKey, ServerKey};
use crate::shortint::parameters::ShortintKeySwitchingParameters;

/// Test-only implementation of KeySwitchingKey::new that skips the cast_rshift assertion.
/// This is needed for pfail tests where we intentionally use different message modulus and carry.
pub fn new_key_switching_key_for_pfail_test<'input_key, InputEncryptionKey, ClientKeyType>(
    input_key_pair: (InputEncryptionKey, Option<&ServerKey>),
    output_key_pair: (&ClientKeyType, &ServerKey),
    params: ShortintKeySwitchingParameters,
) -> KeySwitchingKey
where
    InputEncryptionKey: Into<SecretEncryptionKeyView<'input_key>>,
    ClientKeyType: AsRef<ClientKey>,
{
    let input_secret_encryption_key: SecretEncryptionKeyView<'_> = input_key_pair.0.into();
    KeySwitchingKey {
        key: crate::shortint::KeySwitchingKey::new(
            (
                input_secret_encryption_key.key,
                input_key_pair.1.map(|k| &k.key),
            ),
            (&output_key_pair.0.as_ref().key, &output_key_pair.1.key),
            params,
        ),
    }
}
