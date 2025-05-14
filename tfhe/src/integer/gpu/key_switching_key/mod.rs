use crate::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::client_key::secret_encryption_key::SecretEncryptionKeyView;
use crate::integer::gpu::CudaServerKey;
use crate::integer::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::ShortintKeySwitchingParameters;
use crate::shortint::EncryptionKeyChoice;

#[allow(dead_code)]
pub struct CudaKeySwitchingKey<'keys> {
    pub(crate) key_switching_key: CudaLweKeyswitchKey<u64>,
    pub(crate) dest_server_key: &'keys CudaServerKey,
    pub(crate) destination_key: EncryptionKeyChoice,
}

impl<'keys> CudaKeySwitchingKey<'keys> {
    pub fn new<'input_key, InputEncryptionKey>(
        input_key_pair: (InputEncryptionKey, Option<&'keys CudaServerKey>),
        output_key_pair: (&'keys ClientKey, &'keys CudaServerKey),
        params: ShortintKeySwitchingParameters,
        streams: &CudaStreams,
    ) -> Self
    where
        InputEncryptionKey: Into<SecretEncryptionKeyView<'input_key>>,
    {
        let input_secret_key: SecretEncryptionKeyView<'_> = input_key_pair.0.into();

        let std_cks = output_key_pair
            .0
            .key
            .as_view()
            .try_into()
            .expect("Only the standard atomic pattern is supported on GPU");

        // Creation of the key switching key
        let key_switching_key = ShortintEngine::with_thread_local_mut(|engine| {
            engine.new_key_switching_key(&input_secret_key.key, std_cks, params)
        });
        let d_key_switching_key =
            CudaLweKeyswitchKey::from_lwe_keyswitch_key(&key_switching_key, streams);
        let full_message_modulus_input =
            input_secret_key.key.carry_modulus.0 * input_secret_key.key.message_modulus.0;
        let full_message_modulus_output = output_key_pair.0.key.parameters().carry_modulus().0
            * output_key_pair.0.key.parameters().message_modulus().0;
        assert!(
            full_message_modulus_input.is_power_of_two()
                && full_message_modulus_output.is_power_of_two(),
            "Cannot create casting key if the full messages moduli are not a power of 2"
        );
        if full_message_modulus_input > full_message_modulus_output {
            assert!(
                input_key_pair.1.is_some(),
                "Trying to build a integer::gpu::KeySwitchingKey \
                going from a large modulus {full_message_modulus_input} \
                to a smaller modulus {full_message_modulus_output} \
                without providing a source CudaServerKey, this is not supported"
            );
        }

        CudaKeySwitchingKey {
            key_switching_key: d_key_switching_key,
            dest_server_key: output_key_pair.1,
            destination_key: params.destination_key,
        }
    }
}
