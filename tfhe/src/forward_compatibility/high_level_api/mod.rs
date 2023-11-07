use crate::forward_compatibility::ConvertInto;

use crate::high_level_api::ClientKey;
use next_tfhe::ClientKey as NextClientKey;

impl crate::forward_compatibility::ConvertFrom<ClientKey> for NextClientKey {
    #[inline]
    fn convert_from(value: ClientKey) -> Self {
        let ClientKey {
            #[cfg(feature = "boolean")]
                boolean_key: _,
            #[cfg(feature = "shortint")]
                shortint_key: _,
            #[cfg(feature = "integer")]
            integer_key,
        } = value;

        let crate::high_level_api::integers::keys::IntegerClientKey {
            key,
            wopbs_block_parameters,
        } = integer_key;
        Self::from_raw_parts(
            key.expect(
                "No tfhe 0.4 integer client key in tfhe::high_level_api::ClientKey, \
                unable to convert to tfhe 0.5",
            )
            .convert_into(),
            wopbs_block_parameters.map(|p| p.convert_into()),
        )
    }
}

use crate::high_level_api::CompactPublicKey;
use next_tfhe::CompactPublicKey as NextCompactPublicKey;

impl crate::forward_compatibility::ConvertFrom<CompactPublicKey> for NextCompactPublicKey {
    #[inline]
    fn convert_from(value: CompactPublicKey) -> Self {
        let integer_key = value
            .into_raw_parts()
            .expect("Conversion requires an integer public key in the input CompactPublicKey");

        Self::from_raw_parts(integer_key.convert_into())
    }
}

use crate::high_level_api::CompressedCompactPublicKey;
use next_tfhe::CompressedCompactPublicKey as NextCompressedCompactPublicKey;

impl crate::forward_compatibility::ConvertFrom<CompressedCompactPublicKey>
    for NextCompressedCompactPublicKey
{
    #[inline]
    fn convert_from(value: CompressedCompactPublicKey) -> Self {
        let key = value.into_raw_parts().expect(
            "Conversion requires an integer public key in the input CompressedCompactPublicKey",
        );

        Self::from_raw_parts(key.convert_into())
    }
}

use crate::high_level_api::CompressedPublicKey;
use next_tfhe::CompressedPublicKey as NextCompressedPublicKey;

impl crate::forward_compatibility::ConvertFrom<CompressedPublicKey> for NextCompressedPublicKey {
    #[inline]
    fn convert_from(value: CompressedPublicKey) -> Self {
        let base_integer_key = value
            .base_integer_key()
            .expect("Conversion requires an integer public key in the input CompressedPublicKey")
            .to_owned();

        Self::from_raw_parts(base_integer_key.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_client_key() {
        use crate::{ClientKey, ConfigBuilder};
        use next_tfhe::ClientKey as NextClientKey;

        let config = ConfigBuilder::all_disabled().enable_default_integers();
        let tfhe_struct = ClientKey::generate(config);

        let _next_tfhe_struct: NextClientKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_compact_public_key() {
        use crate::{ClientKey, CompactPublicKey, ConfigBuilder};
        use next_tfhe::CompactPublicKey as NextCompactPublicKey;

        let config = ConfigBuilder::all_disabled().enable_default_integers();
        let cks = ClientKey::generate(config);

        let tfhe_struct = CompactPublicKey::new(&cks);
        let _next_tfhe_struct: NextCompactPublicKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_compressed_compact_public_key() {
        use crate::{ClientKey, CompressedCompactPublicKey, ConfigBuilder};
        use next_tfhe::CompressedCompactPublicKey as NextCompressedCompactPublicKey;

        let config = ConfigBuilder::all_disabled().enable_default_integers();
        let cks = ClientKey::generate(config);

        let tfhe_struct = CompressedCompactPublicKey::new(&cks);
        let _next_tfhe_struct: NextCompressedCompactPublicKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_compressed_public_key() {
        use crate::{ClientKey, CompressedPublicKey, ConfigBuilder};
        use next_tfhe::CompressedPublicKey as NextCompressedPublicKey;

        let config = ConfigBuilder::all_disabled().enable_default_integers();
        let cks = ClientKey::generate(config);

        let tfhe_struct = CompressedPublicKey::new(&cks);
        let _next_tfhe_struct: NextCompressedPublicKey = tfhe_struct.convert_into();
    }
}
