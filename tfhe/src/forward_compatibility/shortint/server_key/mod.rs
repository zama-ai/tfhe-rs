use crate::forward_compatibility::ConvertInto;

pub mod compressed;

use crate::shortint::server_key::ShortintBootstrappingKey;
use next_tfhe::shortint::server_key::ShortintBootstrappingKey as NextShortintBootstrappingKey;

impl crate::forward_compatibility::ConvertFrom<ShortintBootstrappingKey>
    for NextShortintBootstrappingKey
{
    #[inline]
    fn convert_from(value: ShortintBootstrappingKey) -> Self {
        let mut converted = match value {
            ShortintBootstrappingKey::Classic(fourier_bsk) => {
                Self::Classic(fourier_bsk.convert_into())
            }
            ShortintBootstrappingKey::MultiBit {
                fourier_bsk,
                thread_count,
                deterministic_execution,
            } => Self::MultiBit {
                fourier_bsk: fourier_bsk.convert_into(),
                thread_count: thread_count.convert_into(),
                deterministic_execution: deterministic_execution.convert_into(),
            },
        };
        converted.recompute_thread_count();
        converted
    }
}

use crate::shortint::ciphertext::MaxDegree;
use next_tfhe::shortint::ciphertext::MaxDegree as NextMaxDegree;

impl crate::forward_compatibility::ConvertFrom<MaxDegree> for NextMaxDegree {
    #[inline]
    fn convert_from(value: MaxDegree) -> Self {
        let field_0 = value.get();
        Self::new(field_0)
    }
}

use crate::shortint::server_key::ServerKey;
use next_tfhe::shortint::server_key::ServerKey as NextServerKey;

impl crate::forward_compatibility::ConvertFrom<ServerKey> for NextServerKey {
    #[inline]
    fn convert_from(value: ServerKey) -> Self {
        let ServerKey {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
            pbs_order,
        } = value;

        Self::from_raw_parts(
            key_switching_key.convert_into(),
            bootstrapping_key.convert_into(),
            message_modulus.convert_into(),
            carry_modulus.convert_into(),
            max_degree.convert_into(),
            max_noise_level.convert_into(),
            ciphertext_modulus.convert_into(),
            pbs_order.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_shortint_bootstrapping_key() {
        use next_tfhe::shortint::server_key::ShortintBootstrappingKey as NextShortintBootstrappingKey;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (_cks, tfhe_struct) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let tfhe_struct = tfhe_struct.bootstrapping_key;

        let _next_tfhe_struct: NextShortintBootstrappingKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_max_degree() {
        use crate::shortint::ciphertext::MaxDegree;
        use next_tfhe::shortint::ciphertext::MaxDegree as NextMaxDegree;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = MaxDegree::new(rng.gen());
        let next_tfhe_struct: NextMaxDegree = tfhe_struct.convert_into();

        assert_eq!(tfhe_struct.get(), next_tfhe_struct.get());
    }

    #[test]
    fn test_conversion_server_key() {
        use next_tfhe::shortint::server_key::ServerKey as NextServerKey;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (_cks, tfhe_struct) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let _next_tfhe_struct: NextServerKey = tfhe_struct.convert_into();
    }
}
