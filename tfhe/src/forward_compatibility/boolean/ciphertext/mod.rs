use crate::forward_compatibility::ConvertInto;

use crate::boolean::ciphertext::CompressedCiphertext;
use next_tfhe::boolean::ciphertext::CompressedCiphertext as NextCompressedCiphertext;

impl crate::forward_compatibility::ConvertFrom<CompressedCiphertext> for NextCompressedCiphertext {
    #[inline]
    fn convert_from(value: CompressedCiphertext) -> Self {
        let CompressedCiphertext { ciphertext } = value;

        Self::from_raw_parts(ciphertext.convert_into())
    }
}

use crate::boolean::ciphertext::Ciphertext;
use next_tfhe::boolean::ciphertext::Ciphertext as NextCiphertext;

impl crate::forward_compatibility::ConvertFrom<Ciphertext> for NextCiphertext {
    #[inline]
    fn convert_from(value: Ciphertext) -> Self {
        match value {
            Ciphertext::Encrypted(encrypted) => Self::Encrypted(encrypted.convert_into()),
            Ciphertext::Trivial(trivial) => Self::Trivial(trivial),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_ciphertext() {
        use next_tfhe::boolean::ciphertext::Ciphertext as NextCiphertext;

        use crate::boolean::gen_keys;

        let (cks, sks) = gen_keys();

        {
            let tfhe_struct = cks.encrypt(true);
            let _next_tfhe_struct: NextCiphertext = tfhe_struct.convert_into();
        }

        {
            let tfhe_struct = sks.trivial_encrypt(true);
            let _next_tfhe_struct: NextCiphertext = tfhe_struct.convert_into();
        }
    }

    #[test]
    fn test_conversion_compressed_ciphertext() {
        use next_tfhe::boolean::ciphertext::CompressedCiphertext as NextCompressedCiphertext;

        use crate::boolean::gen_keys;

        let (cks, _sks) = gen_keys();

        {
            let tfhe_struct = cks.encrypt_compressed(true);
            let _next_tfhe_struct: NextCompressedCiphertext = tfhe_struct.convert_into();
        }
    }
}
