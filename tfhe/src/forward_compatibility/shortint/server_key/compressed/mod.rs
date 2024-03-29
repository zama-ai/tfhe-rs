use crate::forward_compatibility::ConvertInto;

use crate::shortint::server_key::compressed::ShortintCompressedBootstrappingKey;
use next_tfhe::shortint::server_key::compressed::ShortintCompressedBootstrappingKey as NextShortintCompressedBootstrappingKey;

impl crate::forward_compatibility::ConvertFrom<ShortintCompressedBootstrappingKey>
    for NextShortintCompressedBootstrappingKey
{
    #[inline]
    fn convert_from(value: ShortintCompressedBootstrappingKey) -> Self {
        match value {
            ShortintCompressedBootstrappingKey::Classic(seeded_bsk) => {
                Self::Classic(seeded_bsk.convert_into())
            }
            ShortintCompressedBootstrappingKey::MultiBit {
                seeded_bsk,
                deterministic_execution,
            } => Self::MultiBit {
                seeded_bsk: seeded_bsk.convert_into(),
                deterministic_execution: deterministic_execution.convert_into(),
            },
        }
    }
}

use crate::shortint::server_key::compressed::CompressedServerKey;
use next_tfhe::shortint::ciphertext::MaxNoiseLevel as NextMaxNoiseLevel;
use next_tfhe::shortint::server_key::compressed::CompressedServerKey as NextCompressedServerKey;

impl crate::forward_compatibility::ConvertFrom<CompressedServerKey> for NextCompressedServerKey {
    #[inline]
    fn convert_from(value: CompressedServerKey) -> Self {
        let CompressedServerKey {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            ciphertext_modulus,
            pbs_order,
        } = value;

        Self::from_raw_parts(
            key_switching_key.convert_into(),
            bootstrapping_key.convert_into(),
            message_modulus.convert_into(),
            carry_modulus.convert_into(),
            max_degree.convert_into(),
            NextMaxNoiseLevel::from_msg_carry_modulus(
                message_modulus.convert_into(),
                carry_modulus.convert_into(),
            ),
            ciphertext_modulus.convert_into(),
            pbs_order.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_shortint_compressed_bootstrapping_key() {
        use next_tfhe::shortint::server_key::ShortintCompressedBootstrappingKey as NextCompressedShortintBootstrappingKey;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        use crate::shortint::server_key::compressed::CompressedServerKey;

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let compressed_sks = CompressedServerKey::new(&cks);

        let tfhe_struct = compressed_sks.bootstrapping_key;

        let _next_tfhe_struct: NextCompressedShortintBootstrappingKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_compressed_server_key() {
        use crate::shortint::server_key::compressed::CompressedServerKey;
        use next_tfhe::shortint::server_key::compressed::CompressedServerKey as NextCompressedServerKey;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let tfhe_struct = CompressedServerKey::new(&cks);
        let _next_tfhe_struct: NextCompressedServerKey = tfhe_struct.convert_into();
    }
}
