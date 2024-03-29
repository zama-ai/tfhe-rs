use crate::forward_compatibility::ConvertInto;
use crate::shortint::ciphertext::Degree;
use next_tfhe::shortint::ciphertext::Degree as NextDegree;

impl crate::forward_compatibility::ConvertFrom<Degree> for NextDegree {
    #[inline]
    fn convert_from(value: Degree) -> Self {
        let field_0 = value.get();
        Self::new(field_0)
    }
}

use crate::shortint::ciphertext::MaxNoiseLevel;
use next_tfhe::shortint::ciphertext::MaxNoiseLevel as NextMaxNoiseLevel;

impl crate::forward_compatibility::ConvertFrom<MaxNoiseLevel> for NextMaxNoiseLevel {
    #[inline]
    fn convert_from(value: MaxNoiseLevel) -> Self {
        let field_0 = value.get();
        Self::new(field_0)
    }
}

use crate::shortint::ciphertext::NoiseLevel;
use next_tfhe::shortint::ciphertext::NoiseLevel as NextNoiseLevel;

impl crate::forward_compatibility::ConvertFrom<NoiseLevel> for NextNoiseLevel {
    #[inline]
    fn convert_from(value: NoiseLevel) -> Self {
        let field_0 = value.get();
        // Apparently we cannot set any NoiseLevel we want
        Self::NOMINAL * field_0
    }
}

use crate::shortint::ciphertext::Ciphertext;
use next_tfhe::shortint::ciphertext::Ciphertext as NextCiphertext;

impl crate::forward_compatibility::ConvertFrom<Ciphertext> for NextCiphertext {
    #[inline]
    fn convert_from(value: Ciphertext) -> Self {
        let Ciphertext {
            ct,
            degree,
            noise_level,
            message_modulus,
            carry_modulus,
            pbs_order,
        } = value;

        Self::new(
            ct.convert_into(),
            degree.convert_into(),
            noise_level.convert_into(),
            message_modulus.convert_into(),
            carry_modulus.convert_into(),
            pbs_order.convert_into(),
        )
    }
}

use crate::shortint::ciphertext::CompressedCiphertext;
use next_tfhe::shortint::ciphertext::CompressedCiphertext as NextCompressedCiphertext;

impl crate::forward_compatibility::ConvertFrom<CompressedCiphertext> for NextCompressedCiphertext {
    #[inline]
    fn convert_from(value: CompressedCiphertext) -> Self {
        let CompressedCiphertext {
            ct,
            degree,
            noise_level,
            message_modulus,
            carry_modulus,
            pbs_order,
        } = value;

        // A CompressedCiphertext is just out of encryption so has a nominal noise level.
        Self::from_raw_parts(
            ct.convert_into(),
            degree.convert_into(),
            message_modulus.convert_into(),
            carry_modulus.convert_into(),
            pbs_order.convert_into(),
            noise_level.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_degree() {
        use crate::shortint::ciphertext::Degree;
        use next_tfhe::shortint::ciphertext::Degree as NextDegree;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = Degree::new(rng.gen());
        let next_tfhe_struct: NextDegree = tfhe_struct.convert_into();

        assert_eq!(tfhe_struct.get(), next_tfhe_struct.get());
    }

    #[test]
    fn test_conversion_max_noise_level() {
        use crate::shortint::ciphertext::MaxNoiseLevel;
        use next_tfhe::shortint::ciphertext::MaxNoiseLevel as NextMaxNoiseLevel;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = MaxNoiseLevel::new(rng.gen());
        let next_tfhe_struct: NextMaxNoiseLevel = tfhe_struct.convert_into();

        assert_eq!(tfhe_struct.get(), next_tfhe_struct.get());
    }

    #[test]
    fn test_conversion_noise_level() {
        use crate::shortint::ciphertext::NoiseLevel;
        use next_tfhe::shortint::ciphertext::NoiseLevel as NextNoiseLevel;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = NoiseLevel::NOMINAL * rng.gen::<usize>();
        let next_tfhe_struct: NextNoiseLevel = tfhe_struct.convert_into();

        assert_eq!(tfhe_struct.get(), next_tfhe_struct.get());
    }

    #[test]
    fn test_conversion_ciphertext() {
        use next_tfhe::shortint::ciphertext::Ciphertext as NextCiphertext;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let tfhe_struct = cks.encrypt(2);
        let next_tfhe_struct: NextCiphertext = tfhe_struct.clone().convert_into();

        assert_eq!(
            next_tfhe_struct.noise_level().get(),
            tfhe_struct.noise_level().get()
        );
    }

    #[test]
    fn test_conversion_compressed_ciphertext() {
        use next_tfhe::shortint::ciphertext::CompressedCiphertext as NextCompressedCiphertext;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let tfhe_struct = cks.encrypt_compressed(2);
        let next_tfhe_struct: NextCompressedCiphertext = tfhe_struct.convert_into();

        assert_eq!(
            next_tfhe_struct.noise_level,
            next_tfhe::shortint::ciphertext::NoiseLevel::NOMINAL
        );
    }
}
