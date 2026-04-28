#![allow(clippy::use_self)]
use crate::high_level_api::prelude::*;
use crate::integer::bigint::{I1024, I2048, I512, U1024, U2048, U512};
use crate::integer::{I256, U256};
use crate::js_on_wasm_api::client::*;
use crate::js_on_wasm_api::{catch_panic, catch_panic_result, into_js_error};
use wasm_bindgen::prelude::*;

#[cfg(all(feature = "zk-pok", feature = "cross-origin-wasm-api"))]
use wasm_par_mq::{execute_async, register_fn, sync_fn};

#[wasm_bindgen]
impl ProvenCompactCiphertextList {
    #[wasm_bindgen]
    pub fn verify_and_expand(
        &self,
        crs: &CompactPkeCrs,
        public_key: &TfheCompactPublicKey,
        metadata: &[u8],
    ) -> Result<CompactCiphertextListExpander, JsError> {
        catch_panic_result(|| {
            let inner = self
                .0
                .verify_and_expand(&crs.0, &public_key.0, metadata)
                .map_err(into_js_error)?;
            Ok(CompactCiphertextListExpander(inner))
        })
    }

    #[wasm_bindgen]
    pub fn expand_without_verification(&self) -> Result<CompactCiphertextListExpander, JsError> {
        catch_panic_result(|| {
            let inner = self
                .0
                .expand_without_verification()
                .map_err(into_js_error)?;
            Ok(CompactCiphertextListExpander(inner))
        })
    }
}

// We use this macro to define wasm wrapper for
// FheUint types which maps to a type that is not native
// to wasm-bindgen such as u128 (rust native) and our U256
// and requires conversions using TryFrom
macro_rules! create_wrapper_type_non_native_type (
    (
        {
            type_name: $type_name:ident,
            compressed_type_name: $compressed_type_name:ident,
            proven_type: $proven_type:ident,
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
                client_key: &crate::js_on_wasm_api::client::TfheClientKey,
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
            pub fn decrypt(
                &self,
                client_key: &crate::js_on_wasm_api::client::TfheClientKey,
            ) -> Result<JsValue, JsError> {
                catch_panic_result(|| {
                    let value: $rust_type = self.0.decrypt(&client_key.0);

                    JsValue::try_from(value)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                    .serialize_into(&self.0, &mut buffer)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                        .disable_conformance()
                        .deserialize_from(buffer)
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
                client_key: &crate::js_on_wasm_api::client::TfheClientKey,
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
                    $type_name(self.0.decompress())
                })
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                    .serialize_into(&self.0, &mut buffer)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                        .disable_conformance()
                        .deserialize_from(buffer)
                        .map($compressed_type_name)
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
                proven_type: $proven_type:ident,
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
                    proven_type: $proven_type,
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
        proven_type: ProvenFheUint128,
        rust_type: u128,
    },
    {
        type_name: FheUint160,
        compressed_type_name: CompressedFheUint160,
        proven_type: ProvenFheUint160,
        rust_type: U256,
    },
    {
        type_name: FheUint256,
        compressed_type_name: CompressedFheUint256,
        proven_type: ProvenFheUint256,
        rust_type: U256,
    },
    {
        type_name: FheUint512,
        compressed_type_name: CompressedFheUint512,
        proven_type: ProvenFheUint512,
        rust_type: U512,
    },
    {
        type_name: FheUint1024,
        compressed_type_name: CompressedFheUint1024,
        proven_type: ProvenFheUint1024,
        rust_type: U1024,
    },
    {
        type_name: FheUint2048,
        compressed_type_name: CompressedFheUint2048,
        proven_type: ProvenFheUint2048,
        rust_type: U2048,
    },
    {
        type_name: FheInt128,
        compressed_type_name: CompressedFheInt128,
        proven_type: ProvenFheInt128,
        rust_type: i128,
    },
    {
        type_name: FheInt160,
        compressed_type_name: CompressedFheInt160,
        proven_type: ProvenFheInt160,
        rust_type: I256,
    },
    {
        type_name: FheInt256,
        compressed_type_name: CompressedFheInt256,
        proven_type: ProvenFheInt256,
        rust_type: I256,
    },
    {
        type_name: FheInt512,
        compressed_type_name: CompressedFheInt512,
        proven_type: ProvenFheInt512,
        rust_type: I512,
    },
    {
        type_name: FheInt1024,
        compressed_type_name: CompressedFheInt1024,
        proven_type: ProvenFheInt1024,
        rust_type: I1024,
    },
    {
        type_name: FheInt2048,
        compressed_type_name: CompressedFheInt2048,
        proven_type: ProvenFheInt2048,
        rust_type: I2048,
    },
);

#[cfg(feature = "extended-types")]
create_wrapper_type_non_native_type!(
    {
        type_name: FheUint72,
        compressed_type_name: CompressedFheUint72,
        proven_type: ProvenFheUint72,
        rust_type: u128,
    },
    {
        type_name: FheUint80,
        compressed_type_name: CompressedFheUint80,
        proven_type: ProvenFheUint80,
        rust_type: u128,
    },
    {
        type_name: FheUint88,
        compressed_type_name: CompressedFheUint88,
        proven_type: ProvenFheUint88,
        rust_type: u128,
    },
    {
        type_name: FheUint96,
        compressed_type_name: CompressedFheUint96,
        proven_type: ProvenFheUint96,
        rust_type: u128,
    },
    {
        type_name: FheUint104,
        compressed_type_name: CompressedFheUint104,
        proven_type: ProvenFheUint104,
        rust_type: u128,
    },
    {
        type_name: FheUint112,
        compressed_type_name: CompressedFheUint112,
        proven_type: ProvenFheUint112,
        rust_type: u128,
    },
    {
        type_name: FheUint120,
        compressed_type_name: CompressedFheUint120,
        proven_type: ProvenFheUint120,
        rust_type: u128,
    },
    {
        type_name: FheUint136,
        compressed_type_name: CompressedFheUint136,
        proven_type: ProvenFheUint136,
        rust_type: U256,
    },
    {
        type_name: FheUint144,
        compressed_type_name: CompressedFheUint144,
        proven_type: ProvenFheUint144,
        rust_type: U256,
    },
    {
        type_name: FheUint152,
        compressed_type_name: CompressedFheUint152,
        proven_type: ProvenFheUint152,
        rust_type: U256,
    },
    {
        type_name: FheUint168,
        compressed_type_name: CompressedFheUint168,
        proven_type: ProvenFheUint168,
        rust_type: U256,
    },
    {
        type_name: FheUint176,
        compressed_type_name: CompressedFheUint176,
        proven_type: ProvenFheUint176,
        rust_type: U256,
    },
    {
        type_name: FheUint184,
        compressed_type_name: CompressedFheUint184,
        proven_type: ProvenFheUint184,
        rust_type: U256,
    },
    {
        type_name: FheUint192,
        compressed_type_name: CompressedFheUint192,
        proven_type: ProvenFheUint192,
        rust_type: U256,
    },
    {
        type_name: FheUint200,
        compressed_type_name: CompressedFheUint200,
        proven_type: ProvenFheUint200,
        rust_type: U256,
    },
    {
        type_name: FheUint208,
        compressed_type_name: CompressedFheUint208,
        proven_type: ProvenFheUint208,
        rust_type: U256,
    },
    {
        type_name: FheUint216,
        compressed_type_name: CompressedFheUint216,
        proven_type: ProvenFheUint216,
        rust_type: U256,
    },
    {
        type_name: FheUint224,
        compressed_type_name: CompressedFheUint224,
        proven_type: ProvenFheUint224,
        rust_type: U256,
    },
    {
        type_name: FheUint232,
        compressed_type_name: CompressedFheUint232,
        proven_type: ProvenFheUint232,
        rust_type: U256,
    },
    {
        type_name: FheUint240,
        compressed_type_name: CompressedFheUint240,
        proven_type: ProvenFheUint240,
        rust_type: U256,
    },
    {
        type_name: FheUint248,
        compressed_type_name: CompressedFheUint248,
        proven_type: ProvenFheUint248,
        rust_type: U256,
    },
    // Signed
    {
        type_name: FheInt72,
        compressed_type_name: CompressedFheInt72,
        proven_type: ProvenFheInt72,
        rust_type: i128,
    },
    {
        type_name: FheInt80,
        compressed_type_name: CompressedFheInt80,
        proven_type: ProvenFheInt80,
        rust_type: i128,
    },
    {
        type_name: FheInt88,
        compressed_type_name: CompressedFheInt88,
        proven_type: ProvenFheInt88,
        rust_type: i128,
    },
    {
        type_name: FheInt96,
        compressed_type_name: CompressedFheInt96,
        proven_type: ProvenFheInt96,
        rust_type: i128,
    },
    {
        type_name: FheInt104,
        compressed_type_name: CompressedFheInt104,
        proven_type: ProvenFheInt104,
        rust_type: i128,
    },
    {
        type_name: FheInt112,
        compressed_type_name: CompressedFheInt112,
        proven_type: ProvenFheInt112,
        rust_type: i128,
    },
    {
        type_name: FheInt120,
        compressed_type_name: CompressedFheInt120,
        proven_type: ProvenFheInt120,
        rust_type: i128,
    },
    {
        type_name: FheInt136,
        compressed_type_name: CompressedFheInt136,
        proven_type: ProvenFheInt136,
        rust_type: I256,
    },
    {
        type_name: FheInt144,
        compressed_type_name: CompressedFheInt144,
        proven_type: ProvenFheInt144,
        rust_type: I256,
    },
    {
        type_name: FheInt152,
        compressed_type_name: CompressedFheInt152,
        proven_type: ProvenFheInt152,
        rust_type: I256,
    },
    {
        type_name: FheInt168,
        compressed_type_name: CompressedFheInt168,
        proven_type: ProvenFheInt168,
        rust_type: I256,
    },
    {
        type_name: FheInt176,
        compressed_type_name: CompressedFheInt176,
        proven_type: ProvenFheInt176,
        rust_type: I256,
    },
    {
        type_name: FheInt184,
        compressed_type_name: CompressedFheInt184,
        proven_type: ProvenFheInt184,
        rust_type: I256,
    },
    {
        type_name: FheInt192,
        compressed_type_name: CompressedFheInt192,
        proven_type: ProvenFheInt192,
        rust_type: I256,
    },
    {
        type_name: FheInt200,
        compressed_type_name: CompressedFheInt200,
        proven_type: ProvenFheInt200,
        rust_type: I256,
    },
    {
        type_name: FheInt208,
        compressed_type_name: CompressedFheInt208,
        proven_type: ProvenFheInt208,
        rust_type: I256,
    },
    {
        type_name: FheInt216,
        compressed_type_name: CompressedFheInt216,
        proven_type: ProvenFheInt216,
        rust_type: I256,
    },
    {
        type_name: FheInt224,
        compressed_type_name: CompressedFheInt224,
        proven_type: ProvenFheInt224,
        rust_type: I256,
    },
    {
        type_name: FheInt232,
        compressed_type_name: CompressedFheInt232,
        proven_type: ProvenFheInt232,
        rust_type: I256,
    },
    {
        type_name: FheInt240,
        compressed_type_name: CompressedFheInt240,
        proven_type: ProvenFheInt240,
        rust_type: I256,
    },
    {
        type_name: FheInt248,
        compressed_type_name: CompressedFheInt248,
        proven_type: ProvenFheInt248,
        rust_type: I256,
    },
);

// We use this macro to define wasm wrapper for
// FheUint types which maps to an unsigned integer type
// that is natively compatible to wasm (u8, u16, etc)
macro_rules! create_wrapper_type_that_has_native_type (
    (
        {
            type_name: $type_name:ident,
            compressed_type_name: $compressed_type_name:ident,
            proven_type: $proven_type:ident,
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
                client_key: &crate::js_on_wasm_api::client::TfheClientKey,
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
            pub fn decrypt(
                &self,
                client_key: &crate::js_on_wasm_api::client::TfheClientKey,
            ) -> Result<$native_type, JsError> {
                catch_panic(|| self.0.decrypt(&client_key.0))
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                    .serialize_into(&self.0, &mut buffer)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                        .disable_conformance()
                        .deserialize_from(buffer)
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
                client_key: &crate::js_on_wasm_api::client::TfheClientKey,
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
                    $type_name(self.0.decompress())
                })
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                    .serialize_into(&self.0, &mut buffer)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                        .disable_conformance()
                        .deserialize_from(buffer)
                        .map($compressed_type_name)
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
                proven_type: $proven_type:ident,
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
                    proven_type: $proven_type,
                    native_type: $native_type
                }
            );
        )*
    }
);

#[cfg(feature = "extended-types")]
create_wrapper_type_that_has_native_type!(
    {
        type_name: FheUint24,
        compressed_type_name: CompressedFheUint24,
        proven_type: ProvenFheUint24,
        native_type: u32,
    },
    {
        type_name: FheUint40,
        compressed_type_name: CompressedFheUint40,
        proven_type: ProvenFheUint40,
        native_type: u64,
    },
    {
        type_name: FheUint48,
        compressed_type_name: CompressedFheUint48,
        proven_type: ProvenFheUint48,
        native_type: u64,
    },
    {
        type_name: FheUint56,
        compressed_type_name: CompressedFheUint56,
        proven_type: ProvenFheUint56,
        native_type: u64,
    },
    {
        type_name: FheInt24,
        compressed_type_name: CompressedFheInt24,
        proven_type: ProvenFheInt24,
        native_type: i32,
    },
    {
        type_name: FheInt40,
        compressed_type_name: CompressedFheInt40,
        proven_type: ProvenFheInt40,
        native_type: i64,
    },
    {
        type_name: FheInt48,
        compressed_type_name: CompressedFheInt48,
        proven_type: ProvenFheInt48,
        native_type: i64,
    },
    {
        type_name: FheInt56,
        compressed_type_name: CompressedFheInt56,
        proven_type: ProvenFheInt56,
        native_type: i64,
    },
);

create_wrapper_type_that_has_native_type!(
    {
        type_name: FheBool,
        compressed_type_name: CompressedFheBool,
        proven_type: ProvenFheBool,
        native_type: bool,
    },
    {
        type_name: FheUint2,
        compressed_type_name: CompressedFheUint2,
        proven_type: ProvenFheUint2,
        native_type: u8,
    },
    {
        type_name: FheUint4,
        compressed_type_name: CompressedFheUint4,
        proven_type: ProvenFheUint4,
        native_type: u8,
    },
    {
        type_name: FheUint6,
        compressed_type_name: CompressedFheUint6,
        proven_type: ProvenFheUint6,
        native_type: u8,
    },
    {
        type_name: FheUint8,
        compressed_type_name: CompressedFheUint8,
        proven_type: ProvenFheUint8,
        native_type: u8,
    },
    {
        type_name: FheUint10,
        compressed_type_name: CompressedFheUint10,
        proven_type: ProvenFheUint10,
        native_type: u16,
    },
    {
        type_name: FheUint12,
        compressed_type_name: CompressedFheUint12,
        proven_type: ProvenFheUint12,
        native_type: u16,
    },
    {
        type_name: FheUint14,
        compressed_type_name: CompressedFheUint14,
        proven_type: ProvenFheUint14,
        native_type: u16,
    },
    {
        type_name: FheUint16,
        compressed_type_name: CompressedFheUint16,
        proven_type: ProvenFheUint16,
        native_type: u16,
    },
    {
        type_name: FheUint32,
        compressed_type_name: CompressedFheUint32,
        proven_type: ProvenFheUint32,
        native_type: u32,
    },
    {
        type_name: FheUint64,
        compressed_type_name: CompressedFheUint64,
        proven_type: ProvenFheUint64,
        native_type: u64,
    },
    {
        type_name: FheInt2,
        compressed_type_name: CompressedFheInt2,
        proven_type: ProvenFheInt2,
        native_type: i8,
    },
    {
        type_name: FheInt4,
        compressed_type_name: CompressedFheInt4,
        proven_type: ProvenFheInt4,
        native_type: i8,
    },
    {
        type_name: FheInt6,
        compressed_type_name: CompressedFheInt6,
        proven_type: ProvenFheInt6,
        native_type: i8,
    },
    {
        type_name: FheInt8,
        compressed_type_name: CompressedFheInt8,
        proven_type: ProvenFheInt8,
        native_type: i8,
    },
    {
        type_name: FheInt10,
        compressed_type_name: CompressedFheInt10,
        proven_type: ProvenFheInt10,
        native_type: i16,
    },
    {
        type_name: FheInt12,
        compressed_type_name: CompressedFheInt12,
        proven_type: ProvenFheInt12,
        native_type: i16,
    },
    {
        type_name: FheInt14,
        compressed_type_name: CompressedFheInt14,
        proven_type: ProvenFheInt14,
        native_type: i16,
    },
    {
        type_name: FheInt16,
        compressed_type_name: CompressedFheInt16,
        proven_type: ProvenFheInt16,
        native_type: i16,
    },
    {
        type_name: FheInt32,
        compressed_type_name: CompressedFheInt32,
        proven_type: ProvenFheInt32,
        native_type: i32,
    },
    {
        type_name: FheInt64,
        compressed_type_name: CompressedFheInt64,
        proven_type: ProvenFheInt64,
        native_type: i64,
    },
);

#[wasm_bindgen]
impl CompactCiphertextList {
    #[wasm_bindgen]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[wasm_bindgen]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[wasm_bindgen]
    pub fn get_kind_of(&self, index: usize) -> Option<FheTypes> {
        self.0.get_kind_of(index).map(Into::into)
    }

    #[wasm_bindgen]
    pub fn expand(&self) -> Result<CompactCiphertextListExpander, JsError> {
        catch_panic_result(|| {
            self.0
                .expand()
                .map_err(into_js_error)
                .map(CompactCiphertextListExpander)
        })
    }

    #[wasm_bindgen]
    pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
        let mut buffer = vec![];
        catch_panic_result(|| {
            crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                .serialize_into(&self.0, &mut buffer)
                .map_err(into_js_error)
        })?;

        Ok(buffer)
    }

    #[wasm_bindgen]
    pub fn safe_deserialize(
        buffer: &[u8],
        serialized_size_limit: u64,
    ) -> Result<CompactCiphertextList, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(CompactCiphertextList)
                .map_err(into_js_error)
        })
    }
}

/// Helper macro to define push methods for the builder
///
/// The js_type must be a type that is "native" between rust and wasm_bindgen
#[cfg(feature = "extended-types")]
macro_rules! define_builder_push_method {
    (
        unsigned: {
            $($num_bits:literal <= $js_type:ty),*
            $(,)?
        }
    ) => {
        ::paste::paste!{
            #[wasm_bindgen]
            impl CompactCiphertextListBuilder {
                $(
                    #[wasm_bindgen]
                    pub fn [<push_u $num_bits>] (&mut self, value: $js_type) -> Result<(), JsError> {
                        catch_panic(|| {
                            self.0.push_with_num_bits(value, $num_bits).unwrap();
                        })
                    }
                )*
            }
        }
    };
    (
        signed: {
            $($num_bits:literal <= $js_type:ty),*
            $(,)?
        }
    ) => {
        ::paste::paste!{
            #[wasm_bindgen]
            impl CompactCiphertextListBuilder {
                $(
                    #[wasm_bindgen]
                    pub fn [<push_i $num_bits>] (&mut self, value: $js_type) -> Result<(), JsError> {
                        catch_panic(|| {
                            self.0.push_with_num_bits(value, $num_bits).unwrap();
                        })
                    }
                )*
            }
        }
    };
}

#[cfg(feature = "extended-types")]
define_builder_push_method!(unsigned: {
    24 <= u32,
    40 <= u64,
    48 <= u64,
    56 <= u64,
});

#[cfg(feature = "extended-types")]
define_builder_push_method!(signed: {
    24 <= i32,
    40 <= i64,
    48 <= i64,
    56 <= i64,
});

#[wasm_bindgen]
impl CompactCiphertextListBuilder {
    /// This function is like build_with_proof_packed, but can be called in cross origin
    /// from the main thread
    #[cfg(all(feature = "zk-pok", feature = "cross-origin-wasm-api"))]
    #[wasm_bindgen]
    pub async fn build_with_proof_packed_async(
        &self,
        crs: &CompactPkeCrs,
        metadata: &[u8],
        compute_load: ZkComputeLoad,
    ) -> Result<ProvenCompactCiphertextList, JsError> {
        use sync_executor::*;

        let input = ProofInput {
            builder: (&self.0).into(),
            crs: crs.0.clone(),
            metadata: metadata.to_vec(),
            compute_load: compute_load.into(),
        };

        execute_async(sync_fn!(build_with_proof_packed_sync_fn), &input)
            .await
            .flatten()
            .map_err(into_js_error)
            .map(ProvenCompactCiphertextList)
    }
}

/// Helper module for the sync-executor mode of wasm-par-mq.
/// This allows users to run the encryption code from the main js thread without blocking it
#[cfg(all(feature = "zk-pok", feature = "cross-origin-wasm-api"))]
mod sync_executor {
    use serde::{Deserialize, Serialize};

    use crate::integer::ciphertext::DataKind;
    use crate::integer::CompactPublicKey;
    use crate::Tag;

    use super::*;

    // These short lived types are only made serializable to be sent between threads of the same
    // binary, running the same tfhe-rs version.
    // There is no point in making them versionable.
    #[derive(Serialize, Deserialize)]
    #[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
    pub struct ProofInput {
        pub(super) builder: SerializableCompactCiphertextListBuilder,
        pub(super) crs: crate::core_crypto::entities::CompactPkeCrs,
        pub(super) metadata: Vec<u8>,
        pub(super) compute_load: crate::zk::ZkComputeLoad,
    }

    #[derive(Serialize, Deserialize)]
    #[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
    pub(super) struct SerializableCompactCiphertextListBuilder {
        messages: Vec<u64>,
        info: Vec<DataKind>,
        pk: CompactPublicKey,
        tag: Tag,
    }

    impl From<&crate::CompactCiphertextListBuilder> for SerializableCompactCiphertextListBuilder {
        fn from(value: &crate::CompactCiphertextListBuilder) -> Self {
            SerializableCompactCiphertextListBuilder {
                messages: value.inner.messages.clone(),
                info: value.inner.info.clone(),
                pk: value.inner.pk.clone(),
                tag: value.tag.clone(),
            }
        }
    }

    impl From<SerializableCompactCiphertextListBuilder> for crate::CompactCiphertextListBuilder {
        fn from(value: SerializableCompactCiphertextListBuilder) -> Self {
            Self {
                inner: crate::integer::ciphertext::CompactCiphertextListBuilder {
                    messages: value.messages,
                    info: value.info,
                    pk: value.pk,
                },
                tag: value.tag,
            }
        }
    }

    /// Wrapper function used to be able to call build_with_proof_packed on the sync executor
    #[allow(clippy::needless_pass_by_value)] // Required by the sync executor
    pub(super) fn build_with_proof_packed_sync_fn(
        input: ProofInput,
    ) -> Result<crate::high_level_api::ProvenCompactCiphertextList, String> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let builder = crate::CompactCiphertextListBuilder::from(input.builder);
            builder
                .build_with_proof_packed(&input.crs, &input.metadata, input.compute_load)
                .map_err(|e| e.to_string())
        }))
        .map_err(|_| "Operation Failed".to_string())
        .flatten()
    }
    register_fn!(build_with_proof_packed_sync_fn, ProofInput,
    Result<crate::high_level_api::ProvenCompactCiphertextList, String>);
}

#[cfg(feature = "extended-types")]
#[wasm_bindgen]
impl CompactCiphertextListBuilder {
    #[wasm_bindgen]
    pub fn push_u72(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 72)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u80(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 80)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u88(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 88)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u96(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 96)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u104(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 104)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u112(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 112)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u120(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 120)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u136(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 136)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u144(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 144)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u152(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 152)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u168(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 168)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u176(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 176)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u184(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 184)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u192(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 192)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u200(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 200)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u208(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 208)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u216(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 216)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u224(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 224)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u232(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 232)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u240(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 240)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u248(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 248)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i72(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 72)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i80(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 80)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i88(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 88)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i96(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 96)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i104(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 104)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i112(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 112)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i120(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 120)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i136(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 136)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i144(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 144)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i152(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 152)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i168(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 168)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i176(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 176)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i184(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 184)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i192(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 192)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i200(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 200)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i208(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 208)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i216(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 216)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i224(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 224)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i232(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 232)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i240(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 240)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i248(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 248)?;
            Ok(())
        })
    }
}

/// Helper macro to define get methods for the expander
/// one method per Fhe type possible as JS is not a typed language as Rust is
macro_rules! define_expander_get_method {
    (
        unsigned: {
            $($num_bits:literal),*
            $(,)?
        }
    ) => {
        ::paste::paste!{
            #[wasm_bindgen]
            impl CompactCiphertextListExpander {
                $(
                    #[wasm_bindgen]
                    pub fn [<get_uint $num_bits>] (&mut self, index: usize) -> Result<[<FheUint $num_bits>], JsError> {
                        catch_panic_result(|| {
                            self.0.get::<crate::[<FheUint $num_bits>]>(index)
                                .map_err(into_js_error)
                                .map(|val|
                                      val.map_or_else(
                                          || Err(JsError::new(&format!("Index {index} is out of bounds"))),
                                          |val| Ok([<FheUint $num_bits>](val))
                                    ))?
                        })
                    }
                )*
            }
        }
    };
    (
        signed: {
            $($num_bits:literal),*
            $(,)?
        }
    ) => {
        ::paste::paste!{
            #[wasm_bindgen]
            impl CompactCiphertextListExpander {
                $(
                    #[wasm_bindgen]
                    pub fn [<get_int $num_bits>] (&mut self, index: usize) -> Result<[<FheInt $num_bits>], JsError> {
                        catch_panic_result(|| {
                           self.0.get::<crate::[<FheInt $num_bits>]>(index)
                                .map_err(into_js_error)
                                .map(|val|
                                      val.map_or_else(
                                          || Err(JsError::new(&format!("Index {index} is out of bounds"))),
                                          |val| Ok([<FheInt $num_bits>](val))
                                    ))?
                        })
                    }
                )*
            }
        }
    };
}

#[cfg(feature = "extended-types")]
define_expander_get_method!(
    unsigned: { 24, 40, 48, 56, 72, 80, 88, 96, 104, 112, 120, 136, 144, 152, 168, 176, 184,
                192, 200, 208, 216, 224, 232, 240, 248, 256 }
);

define_expander_get_method!(
    unsigned: { 2, 4, 6, 8, 10, 12, 14, 16, 32, 64, 128, 160, 512, 1024, 2048 }
);

#[cfg(feature = "extended-types")]
define_expander_get_method!(
    signed: { 24, 40, 48, 56, 72, 80, 88, 96, 104, 112, 120, 136, 144, 152, 168, 176, 184, 192,
              200, 208, 216, 224, 232, 240, 248 }
);

define_expander_get_method!(
    signed: { 2, 4, 6, 8, 10, 12, 14, 16, 32, 64, 128, 160, 256, 512, 1024, 2048 }
);

#[wasm_bindgen]
impl CompactCiphertextListExpander {
    #[wasm_bindgen]
    pub fn get_bool(&self, index: usize) -> Result<FheBool, JsError> {
        catch_panic_result(|| {
            self.0
                .get::<crate::FheBool>(index)
                .map_err(into_js_error)
                .map(|val| {
                    val.map_or_else(
                        || Err(JsError::new(&format!("Index {index} is out of bounds"))),
                        |val| Ok(FheBool(val)),
                    )
                })?
        })
    }

    #[wasm_bindgen]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[wasm_bindgen]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[wasm_bindgen]
    pub fn get_kind_of(&self, index: usize) -> Option<FheTypes> {
        self.0.get_kind_of(index).map(Into::into)
    }
}
