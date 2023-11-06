use wasm_bindgen::prelude::*;
use wasm_bindgen::JsError;

use crate::high_level_api::prelude::*;
use crate::integer::{I256, U256};
use crate::js_on_wasm_api::js_high_level_api::{catch_panic, catch_panic_result, into_js_error};

const U128_MAX_AS_STR: &str = "340282366920938463463374607431768211455";

impl From<U256> for JsValue {
    fn from(value: U256) -> Self {
        let (low_rs, high_rs) = value.to_low_high_u128();

        let low_js = Self::from(low_rs);
        let high_js = Self::from(high_rs);
        (high_js << Self::bigint_from_str("128")) + low_js
    }
}

impl TryFrom<JsValue> for U256 {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        let low_js = &value & JsValue::bigint_from_str(U128_MAX_AS_STR);
        let high_js = value >> JsValue::bigint_from_str("128");

        // Since we masked the low value it will fit in u128
        let low_rs = u128::try_from(low_js).unwrap();
        // If high does not fit in u128, that means the value is > 256::MAX
        let high_rs =
            u128::try_from(high_js).map_err(|_| JsError::new("value is out of range for u256"))?;

        let value = Self::from((low_rs, high_rs));
        Ok(value)
    }
}

impl From<I256> for JsValue {
    fn from(mut value: I256) -> Self {
        let was_neg = if value < I256::ZERO {
            value = -value;
            true
        } else {
            false
        };
        let shift = Self::bigint_from_str("64");
        let mut result = Self::bigint_from_str("0");
        for v in value.0.iter().rev() {
            result = result << &shift;
            result = result | Self::from(*v);
        }

        if was_neg {
            -result
        } else {
            result
        }
    }
}

impl TryFrom<JsValue> for I256 {
    type Error = JsError;

    fn try_from(mut value: JsValue) -> Result<Self, Self::Error> {
        let was_neg = if value.lt(&JsValue::from(0)) {
            value = -value;
            true
        } else {
            false
        };

        let low_js = &value & JsValue::bigint_from_str(U128_MAX_AS_STR);
        let high_js =
            (&value >> JsValue::bigint_from_str("128")) & JsValue::bigint_from_str(U128_MAX_AS_STR);

        // Since we masked the low value it will fit in u128
        let low_rs = u128::try_from(low_js).unwrap();
        // Since we masked the low value it will fit in u128
        let high_rs = u128::try_from(high_js).unwrap();
        let rs_value = Self::from((low_rs, high_rs));
        Ok(if was_neg { -rs_value } else { rs_value })
    }
}

// We use this macro to define wasm wrapper for
// FheUint types which maps to a type that is not native
// to wasm-bindgen such as u128 (rust native) and our U256
// and requires conversions using TryFrom
macro_rules! create_wrapper_type_non_native_type(
    (
        {
            type_name: $type_name:ident,
            compressed_type_name: $compressed_type_name:ident,
            compact_type_name: $compact_type_name:ident,
            compact_list_type_name: $compact_list_type_name:ident,
            rust_type: $rust_type:ty $(,)?
        }
    ) => {
        #[wasm_bindgen]
        pub struct $type_name(pub(crate) crate::high_level_api::$type_name);

        #[wasm_bindgen]
        impl $type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_client_key(
                value: JsValue,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheClientKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    let value = <$rust_type>::try_from(value)
                        .map_err(|_| JsError::new(&format!("Failed to convert the value to a {}", stringify!($rust_type))))?;
                    crate::high_level_api::$type_name::try_encrypt(value, &client_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn encrypt_with_public_key(
                value: JsValue,
                public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfhePublicKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    let value = <$rust_type>::try_from(value)
                        .map_err(|_| JsError::new(&format!("Failed to convert the value to a {}", stringify!($rust_type))))?;
                    crate::high_level_api::$type_name::try_encrypt(value, &public_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn encrypt_with_compressed_public_key(
                value: JsValue,
                compressed_public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompressedPublicKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    let value = <$rust_type>::try_from(value)
                        .map_err(|_| JsError::new(&format!("Failed to convert the value to a {}", stringify!($rust_type))))?;
                    crate::high_level_api::$type_name::try_encrypt(value, &compressed_public_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn encrypt_with_compact_public_key(
                value: JsValue,
                compact_public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    let value = <$rust_type>::try_from(value)
                        .map_err(|_| JsError::new(&format!("Failed to convert the value to a {}", stringify!($rust_type))))?;
                    crate::high_level_api::$type_name::try_encrypt(value, &compact_public_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn decrypt(
                &self,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheClientKey,
            ) -> Result<JsValue, JsError> {
                catch_panic_result(|| {
                    let value: $rust_type = self.0.decrypt(&client_key.0);

                    JsValue::try_from(value)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_deserialization::safe_serialize(&self.0, &mut buffer, serialized_size_limit)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_deserialization::safe_deserialize(buffer, serialized_size_limit)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }
        }

        #[wasm_bindgen]
        pub struct $compressed_type_name(pub(crate) crate::high_level_api::$compressed_type_name);

        #[wasm_bindgen]
        impl $compressed_type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_client_key(
                value: JsValue,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheClientKey,
            ) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    let value = <$rust_type>::try_from(value)
                        .map_err(|_| JsError::new(&format!("Failed to convert the value to a {}", stringify!($rust_type))))?;
                    crate::high_level_api::$compressed_type_name::try_encrypt(value, &client_key.0)
                        .map($compressed_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn decompress(
                &self,
            ) -> Result<$type_name, JsError> {
                catch_panic(||{
                    $type_name(self.0.clone().decompress())
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($compressed_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_deserialization::safe_serialize(&self.0, &mut buffer, serialized_size_limit)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_deserialization::safe_deserialize(buffer, serialized_size_limit)
                        .map($compressed_type_name)
                        .map_err(into_js_error)
                })
            }
        }

        #[wasm_bindgen]
        pub struct $compact_type_name(pub(crate) crate::high_level_api::$compact_type_name);

        #[wasm_bindgen]
        impl $compact_type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_compact_public_key(
                value: JsValue,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey,
            ) -> Result<$compact_type_name, JsError> {
                catch_panic_result(|| {
                    let value = <$rust_type>::try_from(value)
                        .map_err(|_| JsError::new(&format!("Failed to convert the value to a {}", stringify!($rust_type))))?;
                    crate::high_level_api::$compact_type_name::try_encrypt(value, &client_key.0)
                        .map($compact_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn expand(
                &self,
            ) -> Result<$type_name, JsError> {
                catch_panic(||{
                    $type_name(self.0.expand())
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$compact_type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($compact_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_deserialization::safe_serialize(&self.0, &mut buffer, serialized_size_limit)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$compact_type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_deserialization::safe_deserialize(buffer, serialized_size_limit)
                        .map($compact_type_name)
                        .map_err(into_js_error)
                })
            }
        }

        #[wasm_bindgen]
        pub struct $compact_list_type_name(pub(crate) crate::high_level_api::$compact_list_type_name);

        #[wasm_bindgen]
        impl $compact_list_type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_compact_public_key(
                values: Vec<JsValue>,
                public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey,
            ) -> Result<$compact_list_type_name, JsError> {
                catch_panic_result(|| {
                    let values = values
                        .into_iter()
                        .map(|value| {
                            <$rust_type>::try_from(value)
                                .map_err(|_| {
                                    JsError::new(&format!("Failed to convert the value to a {}", stringify!($rust_type)))
                                })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    crate::high_level_api::$compact_list_type_name::try_encrypt(&values, &public_key.0)
                        .map($compact_list_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn expand(
                &self,
            ) -> Result<Vec<JsValue>, JsError> {
                catch_panic(||{
                    self.0.expand()
                        .into_iter()
                        .map($type_name)
                        .map(JsValue::from)
                        .collect::<Vec<_>>()
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$compact_list_type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($compact_list_type_name)
                        .map_err(into_js_error)
                })
            }
        }
    };

    (
        $(
            {
                type_name: $type_name:ident,
                compressed_type_name: $compressed_type_name:ident,
                compact_type_name: $compact_type_name:ident,
                compact_list_type_name: $compact_list_type_name:ident,
                rust_type: $rust_type:ty $(,)?
            }
        ),*
        $(,)?
    ) => {
        $(
            create_wrapper_type_non_native_type!(
                {
                    type_name: $type_name,
                    compressed_type_name: $compressed_type_name,
                    compact_type_name: $compact_type_name,
                    compact_list_type_name: $compact_list_type_name,
                    rust_type: $rust_type
                }
            );
        )*
    }
);

create_wrapper_type_non_native_type!(
    {
        type_name: FheUint128,
        compressed_type_name: CompressedFheUint128,
        compact_type_name: CompactFheUint128,
        compact_list_type_name: CompactFheUint128List,
        rust_type: u128,
    },
    {
        type_name: FheUint256,
        compressed_type_name: CompressedFheUint256,
        compact_type_name: CompactFheUint256,
        compact_list_type_name: CompactFheUint256List,
        rust_type: U256,
    },
    {
        type_name: FheInt128,
        compressed_type_name: CompressedFheInt128,
        compact_type_name: CompactFheInt128,
        compact_list_type_name: CompactFheInt128List,
        rust_type: i128,
    },
    {
        type_name: FheInt256,
        compressed_type_name: CompressedFheInt256,
        compact_type_name: CompactFheInt256,
        compact_list_type_name: CompactFheInt256List,
        rust_type: I256,
    },
);

// We use this macro to define wasm wrapper for
// FheUint types which maps to an unsigned integer type
// that is natively compative to wasm (u8, u16, etc)
macro_rules! create_wrapper_type_that_has_native_type(
    (
        {
            type_name: $type_name:ident,
            compressed_type_name: $compressed_type_name:ident,
            compact_type_name: $compact_type_name:ident,
            compact_list_type_name: $compact_list_type_name:ident,
            native_type: $native_type:ty $(,)?
        }
    ) => {
        #[wasm_bindgen]
        pub struct $type_name(pub(crate) crate::high_level_api::$type_name);

        #[wasm_bindgen]
        impl $type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_client_key(
                value: $native_type,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheClientKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    crate::high_level_api::$type_name::try_encrypt(value, &client_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn encrypt_with_public_key(
                value: $native_type,
                public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfhePublicKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    crate::high_level_api::$type_name::try_encrypt(value, &public_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn encrypt_with_compressed_public_key(
                value: $native_type,
                compressed_public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompressedPublicKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    crate::high_level_api::$type_name::try_encrypt(value, &compressed_public_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn encrypt_with_compact_public_key(
                value: $native_type,
                compact_public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    crate::high_level_api::$type_name::try_encrypt(value, &compact_public_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }


            #[wasm_bindgen]
            pub fn decrypt(
                &self,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheClientKey,
            ) -> Result<$native_type, JsError> {
                catch_panic(|| self.0.decrypt(&client_key.0))
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_deserialization::safe_serialize(&self.0, &mut buffer, serialized_size_limit)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_deserialization::safe_deserialize(buffer, serialized_size_limit)
                        .map(Self)
                        .map_err(into_js_error)
                })
            }
        }
        #[wasm_bindgen]
        pub struct $compressed_type_name(pub(crate) crate::high_level_api::$compressed_type_name);

        #[wasm_bindgen]
        impl $compressed_type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_client_key(
                value: $native_type,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheClientKey,
            ) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    crate::high_level_api::$compressed_type_name::try_encrypt(value, &client_key.0)
                        .map($compressed_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn decompress(
                &self,
            ) -> Result<$type_name, JsError> {
                catch_panic(||{
                    $type_name(self.0.clone().decompress())
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($compressed_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_deserialization::safe_serialize(&self.0, &mut buffer, serialized_size_limit)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_deserialization::safe_deserialize(buffer, serialized_size_limit)
                        .map($compressed_type_name)
                        .map_err(into_js_error)
                })
            }
        }

        #[wasm_bindgen]
        pub struct $compact_type_name(pub(crate) crate::high_level_api::$compact_type_name);

        #[wasm_bindgen]
        impl $compact_type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_compact_public_key(
                value: $native_type,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey,
            ) -> Result<$compact_type_name, JsError> {
                catch_panic_result(|| {
                    crate::high_level_api::$compact_type_name::try_encrypt(value, &client_key.0)
                        .map($compact_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn expand(
                &self,
            ) -> Result<$type_name, JsError> {
                catch_panic(||{
                    $type_name(self.0.expand())
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$compact_type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($compact_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_deserialization::safe_serialize(&self.0, &mut buffer, serialized_size_limit)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$compact_type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_deserialization::safe_deserialize(buffer, serialized_size_limit)
                        .map($compact_type_name)
                        .map_err(into_js_error)
                })
            }
        }

        #[wasm_bindgen]
        pub struct $compact_list_type_name(pub(crate) crate::high_level_api::$compact_list_type_name);

        #[wasm_bindgen]
        impl $compact_list_type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_compact_public_key(
                values: Vec<$native_type>,
                public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey,
            ) -> Result<$compact_list_type_name, JsError> {
                catch_panic_result(|| {
                    crate::high_level_api::$compact_list_type_name::try_encrypt(&values, &public_key.0)
                        .map($compact_list_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn expand(
                &self,
            ) -> Result<Vec<JsValue>, JsError> {
                catch_panic(||{
                    self.0.expand()
                        .into_iter()
                        .map($type_name)
                        .map(JsValue::from)
                        .collect::<Vec<_>>()
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$compact_list_type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($compact_list_type_name)
                        .map_err(into_js_error)
                })
            }
        }

    };
    (
        $(
            {
                type_name: $type_name:ident,
                compressed_type_name: $compressed_type_name:ident,
                compact_type_name: $compact_type_name:ident,
                compact_list_type_name: $compact_list_type_name:ident,
                native_type: $native_type:ty $(,)?
            }
        ),*
        $(,)?
    ) => {
        $(
            create_wrapper_type_that_has_native_type!(
                {
                    type_name: $type_name,
                    compressed_type_name: $compressed_type_name,
                    compact_type_name: $compact_type_name,
                    compact_list_type_name: $compact_list_type_name,
                    native_type: $native_type
                }
            );
        )*
    }
);

create_wrapper_type_that_has_native_type!(
    {
        type_name: FheUint8,
        compressed_type_name: CompressedFheUint8,
        compact_type_name: CompactFheUint8,
        compact_list_type_name: CompactFheUint8List,
        native_type: u8,
    },
    {
        type_name: FheUint16,
        compressed_type_name: CompressedFheUint16,
        compact_type_name: CompactFheUint16,
        compact_list_type_name: CompactFheUint16List,
        native_type: u16,
    },
    {
        type_name: FheUint32,
        compressed_type_name: CompressedFheUint32,
        compact_type_name: CompactFheUint32,
        compact_list_type_name: CompactFheUint32List,
        native_type: u32,
    },
    {
        type_name: FheUint64,
        compressed_type_name: CompressedFheUint64,
        compact_type_name: CompactFheUint64,
        compact_list_type_name: CompactFheUint64List,
        native_type: u64,
    },
    {
        type_name: FheInt8,
        compressed_type_name: CompressedFheInt8,
        compact_type_name: CompactFheInt8,
        compact_list_type_name: CompactFheInt8List,
        native_type: i8,
    },
    {
        type_name: FheInt16,
        compressed_type_name: CompressedFheInt16,
        compact_type_name: CompactFheInt16,
        compact_list_type_name: CompactFheInt16List,
        native_type: i16,
    },
        {
        type_name: FheInt32,
        compressed_type_name: CompressedFheInt32,
        compact_type_name: CompactFheInt32,
        compact_list_type_name: CompactFheInt32List,
        native_type: i32,
    },
    {
        type_name: FheInt64,
        compressed_type_name: CompressedFheInt64,
        compact_type_name: CompactFheInt64,
        compact_list_type_name: CompactFheInt64List,
        native_type: i64,
    },
);
