use crate::forward_compatibility::ConvertInto;

use crate::high_level_api::ClientKey;
use next_tfhe::ClientKey as NextClientKey;

impl crate::forward_compatibility::ConvertFrom<ClientKey> for NextClientKey {
    #[inline]
    fn convert_from(value: ClientKey) -> Self {
        let (key, wopbs_block_parameters) = value.into_raw_parts();

        Self::from_raw_parts(
            key.convert_into(),
            wopbs_block_parameters.map(ConvertInto::convert_into),
        )
    }
}

use crate::high_level_api::CompactPublicKey;
use next_tfhe::CompactPublicKey as NextCompactPublicKey;

impl crate::forward_compatibility::ConvertFrom<CompactPublicKey> for NextCompactPublicKey {
    #[inline]
    fn convert_from(value: CompactPublicKey) -> Self {
        let integer_key = value.into_raw_parts();

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
        let key = value.into_raw_parts();

        Self::from_raw_parts(key.convert_into())
    }
}

use crate::high_level_api::CompressedPublicKey;
use next_tfhe::CompressedPublicKey as NextCompressedPublicKey;

impl crate::forward_compatibility::ConvertFrom<CompressedPublicKey> for NextCompressedPublicKey {
    #[inline]
    fn convert_from(value: CompressedPublicKey) -> Self {
        let base_integer_key = value.into_raw_parts();

        Self::from_raw_parts(base_integer_key.convert_into())
    }
}

use crate::high_level_api::CompressedServerKey;
use next_tfhe::CompressedServerKey as NextCompressedServerKey;

impl crate::forward_compatibility::ConvertFrom<CompressedServerKey> for NextCompressedServerKey {
    #[inline]
    fn convert_from(value: CompressedServerKey) -> Self {
        let integer_key = value.into_raw_parts();

        Self::from_raw_parts(integer_key.convert_into())
    }
}

use crate::high_level_api::PublicKey;
use next_tfhe::PublicKey as NextPublicKey;

impl crate::forward_compatibility::ConvertFrom<PublicKey> for NextPublicKey {
    #[inline]
    fn convert_from(value: PublicKey) -> Self {
        let base_integer_key = value.into_raw_parts();

        Self::from_raw_parts(base_integer_key.convert_into())
    }
}

use crate::high_level_api::ServerKey;
use next_tfhe::ServerKey as NextServerKey;

impl crate::forward_compatibility::ConvertFrom<ServerKey> for NextServerKey {
    #[inline]
    fn convert_from(value: ServerKey) -> Self {
        let (key, wopbs_key) = value.into_raw_parts();

        Self::from_raw_parts(key.convert_into(), wopbs_key.map(ConvertInto::convert_into))
    }
}

macro_rules! impl_convert_from_uint_hl_type {
    ($($num_bits: literal),* $(,)?) => {
        $(
            ::paste::paste! {
                impl_convert_from_uint_hl_type!(
                    [<FheUint $num_bits>] {
                        [<FheUint $num_bits Id>]
                    }
                );
                impl_convert_from_uint_hl_type!(
                    compressed =>
                    [<CompressedFheUint $num_bits>] {
                        [<FheUint $num_bits Id>]
                    }
                );
            }
        )*
    };
    ($old_ty: ident { $old_id: ident } ) => {
        impl crate::forward_compatibility::ConvertFrom<crate::high_level_api::$old_ty>
        for next_tfhe::$old_ty
        {
            fn convert_from(value: crate::high_level_api::$old_ty) -> Self {
                let (inner, _id) = value.into_raw_parts();

                Self::from_raw_parts(inner.convert_into(), next_tfhe::$old_id)
            }
        }
    };
    (compressed => $old_ty: ident { $old_id: ident } ) => {
        impl crate::forward_compatibility::ConvertFrom<crate::high_level_api::$old_ty>
        for next_tfhe::$old_ty
        {
            fn convert_from(value: crate::high_level_api::$old_ty) -> Self {
                let (inner, _id) = value.into_raw_parts();

                Self::from_integer_compressed_radix_ciphertext(
                    inner.convert_into(),
                    next_tfhe::$old_id
                )
            }
        }
    };
}

impl_convert_from_uint_hl_type!(8, 10, 12, 14, 16, 32, 64, 128, 256);

macro_rules! impl_convert_from_int_hl_type {
    ($($num_bits: literal),* $(,)?) => {
        $(
            ::paste::paste! {
                impl_convert_from_int_hl_type!(
                    [<FheInt $num_bits>] {
                        [<FheInt $num_bits Id>]
                    }
                );
                impl_convert_from_int_hl_type!(
                    compressed =>
                    [<CompressedFheInt $num_bits>] {
                        [<FheInt $num_bits Id>]
                    }
                );
            }
        )*
    };
    ($old_ty: ident { $old_id: ident } ) => {
        impl crate::forward_compatibility::ConvertFrom<crate::high_level_api::$old_ty>
        for next_tfhe::$old_ty
        {
            fn convert_from(value: crate::high_level_api::$old_ty) -> Self {
                let (inner, _id) = value.into_raw_parts();

                Self::from_raw_parts(inner.convert_into(), next_tfhe::$old_id)
            }
        }
    };
    (compressed => $old_ty: ident { $old_id: ident } ) => {
        impl crate::forward_compatibility::ConvertFrom<crate::high_level_api::$old_ty>
        for next_tfhe::$old_ty
        {
            fn convert_from(value: crate::high_level_api::$old_ty) -> Self {
                let (inner, _id) = value.into_raw_parts();

                Self::from_integer_compressed_signed_radix_ciphertext(
                    inner.convert_into(),
                    next_tfhe::$old_id
                )
            }
        }
    };
}

impl_convert_from_int_hl_type!(8, 16, 32, 64, 128, 256);

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_client_key() {
        use crate::{ClientKey, ConfigBuilder};
        use next_tfhe::ClientKey as NextClientKey;

        let config = ConfigBuilder::default();
        let tfhe_struct = ClientKey::generate(config);

        let _next_tfhe_struct: NextClientKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_compact_public_key() {
        use crate::{ClientKey, CompactPublicKey, ConfigBuilder};
        use next_tfhe::CompactPublicKey as NextCompactPublicKey;

        let config = ConfigBuilder::default();
        let cks = ClientKey::generate(config);

        let tfhe_struct = CompactPublicKey::new(&cks);
        let _next_tfhe_struct: NextCompactPublicKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_compressed_compact_public_key() {
        use crate::{ClientKey, CompressedCompactPublicKey, ConfigBuilder};
        use next_tfhe::CompressedCompactPublicKey as NextCompressedCompactPublicKey;

        let config = ConfigBuilder::default();
        let cks = ClientKey::generate(config);

        let tfhe_struct = CompressedCompactPublicKey::new(&cks);
        let _next_tfhe_struct: NextCompressedCompactPublicKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_compressed_public_key() {
        use crate::{ClientKey, CompressedPublicKey, ConfigBuilder};
        use next_tfhe::CompressedPublicKey as NextCompressedPublicKey;

        let config = ConfigBuilder::default();
        let cks = ClientKey::generate(config);

        let tfhe_struct = CompressedPublicKey::new(&cks);
        let _next_tfhe_struct: NextCompressedPublicKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_compressed_server_key() {
        use crate::{ClientKey, CompressedServerKey, ConfigBuilder};
        use next_tfhe::CompressedServerKey as NextCompressedServerKey;

        let config = ConfigBuilder::default();
        let cks = ClientKey::generate(config);

        let tfhe_struct = CompressedServerKey::new(&cks);
        let _next_tfhe_struct: NextCompressedServerKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_public_key() {
        use crate::{ClientKey, ConfigBuilder, PublicKey};
        use next_tfhe::PublicKey as NextPublicKey;

        let config = ConfigBuilder::default();
        let cks = ClientKey::generate(config);

        let tfhe_struct = PublicKey::new(&cks);
        let _next_tfhe_struct: NextPublicKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_server_key() {
        use crate::{ClientKey, ConfigBuilder, ServerKey};
        use next_tfhe::ServerKey as NextServerKey;

        let config = ConfigBuilder::default();
        let cks = ClientKey::generate(config);

        let tfhe_struct = ServerKey::new(&cks);
        let _next_tfhe_struct: NextServerKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_ciphertexts() {
        use crate::prelude::*;
        use crate::*;
        use next_tfhe::{
            CompressedFheInt64 as NextCompressedFheInt64,
            CompressedFheUint64 as NextCompressedFheUint64, FheInt64 as NextFheInt64,
            FheUint64 as NextFheUint64,
        };

        let config = ConfigBuilder::default();
        let cks = ClientKey::generate(config);

        {
            let tfhe_struct = FheUint64::encrypt(42u64, &cks);
            let _next_tfhe_struct: NextFheUint64 = tfhe_struct.convert_into();
        }

        {
            let tfhe_struct = FheInt64::encrypt(-42i64, &cks);
            let _next_tfhe_struct: NextFheInt64 = tfhe_struct.convert_into();
        }

        {
            let tfhe_struct = CompressedFheUint64::encrypt(42u64, &cks);
            let _next_tfhe_struct: NextCompressedFheUint64 = tfhe_struct.convert_into();
        }

        {
            let tfhe_struct = CompressedFheInt64::encrypt(-42i64, &cks);
            let _next_tfhe_struct: NextCompressedFheInt64 = tfhe_struct.convert_into();
        }
    }
}
