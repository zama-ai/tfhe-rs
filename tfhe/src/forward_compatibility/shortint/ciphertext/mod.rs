use crate::forward_compatibility::ConvertInto;
use crate::shortint::ciphertext::Degree;
use next_tfhe::shortint::ciphertext::Degree as NextDegree;

impl crate::forward_compatibility::ConvertFrom<Degree> for NextDegree {
    #[inline]
    fn convert_from(value: Degree) -> Self {
        let Degree(field_0) = value;
        NextDegree::new(field_0)
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
            message_modulus,
            carry_modulus,
            pbs_order,
        } = value;

        use next_tfhe::shortint::ciphertext::NoiseLevel;

        Self::new(
            ct.convert_into(),
            degree.convert_into(),
            NoiseLevel::UNKNOWN, // The noise level of the ciphertext is unknown
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
            next_tfhe::shortint::ciphertext::NoiseLevel::NOMINAL,
        )
    }
}

use crate::shortint::ciphertext::CompactCiphertextList;
use next_tfhe::shortint::ciphertext::CompactCiphertextList as NextCompactCiphertextList;

impl crate::forward_compatibility::ConvertFrom<CompactCiphertextList>
    for NextCompactCiphertextList
{
    #[inline]
    fn convert_from(value: CompactCiphertextList) -> Self {
        let CompactCiphertextList {
            ct_list,
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
        } = value;

        // A CompactCiphertextList is just out of encryption so has a nominal noise level.
        Self::from_raw_parts(
            ct_list.convert_into(),
            degree.convert_into(),
            message_modulus.convert_into(),
            carry_modulus.convert_into(),
            pbs_order.convert_into(),
            next_tfhe::shortint::ciphertext::NoiseLevel::NOMINAL,
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

        let tfhe_struct = Degree(rng.gen());
        let next_tfhe_struct: NextDegree = tfhe_struct.convert_into();

        assert_eq!(tfhe_struct.0, next_tfhe_struct.get());
    }

    #[test]
    fn test_conversion_ciphertext() {
        use next_tfhe::shortint::ciphertext::Ciphertext as NextCiphertext;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let tfhe_struct = cks.encrypt(2);
        let next_tfhe_struct: NextCiphertext = tfhe_struct.convert_into();

        assert_eq!(
            next_tfhe_struct.noise_level(),
            next_tfhe::shortint::ciphertext::NoiseLevel::UNKNOWN
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

    #[test]
    fn test_conversion_compact_ciphertext_list() {
        use next_tfhe::shortint::ciphertext::CompactCiphertextList as NextCompactCiphertextList;

        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        use crate::shortint::{gen_keys, CompactPublicKey};

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let compact_pk = CompactPublicKey::new(&cks);

        let tfhe_struct = compact_pk.encrypt_slice(&[0, 1, 2, 3]);
        let next_tfhe_struct: NextCompactCiphertextList = tfhe_struct.convert_into();

        assert_eq!(
            next_tfhe_struct.noise_level,
            next_tfhe::shortint::ciphertext::NoiseLevel::NOMINAL
        );
    }
}
