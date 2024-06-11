#![allow(clippy::use_self)]
use crate::high_level_api::prelude::*;
use crate::integer::bigint::{StaticUnsignedBigInt, U1024, U2048, U512};
use crate::integer::{I256, U256};
use crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey;
#[cfg(feature = "zk-pok-experimental")]
use crate::js_on_wasm_api::js_high_level_api::zk::{CompactPkePublicParams, ZkComputeLoad};
use crate::js_on_wasm_api::js_high_level_api::{catch_panic, catch_panic_result, into_js_error};
use js_sys::BigInt;
use wasm_bindgen::prelude::*;

const U128_MAX_AS_STR: &str = "340282366920938463463374607431768211455";

impl<const N: usize> From<StaticUnsignedBigInt<N>> for JsValue {
    fn from(value: StaticUnsignedBigInt<N>) -> Self {
        if N == 0 {
            return Self::from(0);
        }

        let shift = BigInt::from(64u64);
        let mut js_value = BigInt::from(0);

        for v in value.0.iter().copied().rev() {
            js_value = js_value << &shift;
            js_value = js_value | BigInt::from(v);
        }

        js_value.into()
    }
}

impl<const N: usize> TryFrom<JsValue> for StaticUnsignedBigInt<N> {
    type Error = JsError;

    fn try_from(js_value: JsValue) -> Result<Self, Self::Error> {
        let mut js_bigint = BigInt::new(&js_value).map_err(|err| {
            JsError::new(&format!("Failed to convert the value: {}", err.to_string()))
        })?;
        let mask = BigInt::from(u64::MAX);
        let shift = BigInt::from(u64::BITS);

        let mut data = [0u64; N];
        for word in data.iter_mut() {
            // Since we masked the low value it will fit in u64
            *word = (&js_bigint & &mask).try_into().unwrap();
            js_bigint = js_bigint >> &shift;
        }

        if js_bigint == 0 {
            Ok(Self(data))
        } else {
            Err(JsError::new(&format!(
                "Value is out of range for U{}",
                N * u64::BITS as usize
            )))
        }
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
                    $type_name(self.0.decompress())
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
    // Signed
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
                    $type_name(self.0.decompress())
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
    // Signed
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
pub struct CompactCiphertextListBuilder(crate::high_level_api::CompactCiphertextListBuilder);

#[wasm_bindgen]
pub struct CompactCiphertextListExpander(crate::high_level_api::CompactCiphertextListExpander);

#[wasm_bindgen]
pub struct CompactCiphertextList(crate::high_level_api::CompactCiphertextList);

#[cfg(feature = "zk-pok-experimental")]
#[wasm_bindgen]
pub struct ProvenCompactCiphertextList(crate::high_level_api::ProvenCompactCiphertextList);

#[wasm_bindgen]
impl CompactCiphertextList {
    #[wasm_bindgen]
    pub fn builder(
        public_key: &TfheCompactPublicKey,
    ) -> Result<CompactCiphertextListBuilder, JsError> {
        catch_panic(|| {
            let inner = crate::high_level_api::CompactCiphertextList::builder(&public_key.0);
            CompactCiphertextListBuilder(inner)
        })
    }

    pub fn expand(&self) -> Result<CompactCiphertextListExpander, JsError> {
        catch_panic_result(|| {
            self.0
                .expand()
                .map_err(into_js_error)
                .map(CompactCiphertextListExpander)
        })
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<CompactCiphertextList, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(CompactCiphertextList)
                .map_err(into_js_error)
        })
    }

    #[wasm_bindgen]
    pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
        let mut buffer = vec![];
        catch_panic_result(|| {
            crate::safe_deserialization::safe_serialize(&self.0, &mut buffer, serialized_size_limit)
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
            crate::safe_deserialization::safe_deserialize(buffer, serialized_size_limit)
                .map(CompactCiphertextList)
                .map_err(into_js_error)
        })
    }
}

#[cfg(feature = "zk-pok-experimental")]
#[wasm_bindgen]
impl ProvenCompactCiphertextList {
    #[wasm_bindgen]
    pub fn builder(
        public_key: &TfheCompactPublicKey,
    ) -> Result<CompactCiphertextListBuilder, JsError> {
        catch_panic(|| {
            let inner = crate::high_level_api::ProvenCompactCiphertextList::builder(&public_key.0);
            CompactCiphertextListBuilder(inner)
        })
    }

    pub fn verify_and_expand(
        &self,
        public_params: &CompactPkePublicParams,
        public_key: &TfheCompactPublicKey,
    ) -> Result<CompactCiphertextListExpander, JsError> {
        catch_panic_result(|| {
            let inner = self
                .0
                .verify_and_expand(&public_params.0, &public_key.0)
                .map_err(into_js_error)?;
            Ok(CompactCiphertextListExpander(inner))
        })
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<ProvenCompactCiphertextList, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(ProvenCompactCiphertextList)
                .map_err(into_js_error)
        })
    }

    #[wasm_bindgen]
    pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
        let mut buffer = vec![];
        catch_panic_result(|| {
            crate::safe_deserialization::safe_serialize(&self.0, &mut buffer, serialized_size_limit)
                .map_err(into_js_error)
        })?;

        Ok(buffer)
    }

    #[wasm_bindgen]
    pub fn safe_deserialize(
        buffer: &[u8],
        serialized_size_limit: u64,
    ) -> Result<ProvenCompactCiphertextList, JsError> {
        catch_panic_result(|| {
            crate::safe_deserialization::safe_deserialize(buffer, serialized_size_limit)
                .map(ProvenCompactCiphertextList)
                .map_err(into_js_error)
        })
    }
}

/// Helper macro to define push methods for the builder
///
/// The js_type must be a type that is "native" between rust and wasm_bindgen
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

define_builder_push_method!(unsigned: {
    2 <= u8,
    4 <= u8,
    6 <= u8,
    8 <= u8,
    10 <= u16,
    12 <= u16,
    14 <= u16,
    16 <= u16,
    32 <= u32,
    64 <= u64,
});

define_builder_push_method!(signed: {
    2 <= i8,
    4 <= i8,
    6 <= i8,
    8 <= i8,
    10 <= i16,
    12 <= i16,
    14 <= i16,
    16 <= i16,
    32 <= i32,
    64 <= i64,
});

#[wasm_bindgen]
impl CompactCiphertextListBuilder {
    #[wasm_bindgen]
    pub fn push_u128(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u160(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 160)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u256(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i128(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i160(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 160)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i256(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_boolean(&mut self, value: bool) -> Result<(), JsError> {
        catch_panic(|| {
            self.0.push(value);
        })
    }

    #[wasm_bindgen]
    pub fn build(&self) -> Result<CompactCiphertextList, JsError> {
        catch_panic(|| {
            let inner = self.0.build();
            CompactCiphertextList(inner)
        })
    }

    #[wasm_bindgen]
    pub fn build_packed(&self) -> Result<CompactCiphertextList, JsError> {
        catch_panic(|| {
            let inner = self.0.build_packed();
            CompactCiphertextList(inner)
        })
    }

    #[cfg(feature = "zk-pok-experimental")]
    pub fn build_with_proof(
        &self,
        public_params: &CompactPkePublicParams,
        compute_load: ZkComputeLoad,
    ) -> Result<ProvenCompactCiphertextList, JsError> {
        catch_panic_result(|| {
            self.0
                .build_with_proof(&public_params.0, compute_load.into())
                .map_err(into_js_error)
                .map(ProvenCompactCiphertextList)
        })
    }

    #[cfg(feature = "zk-pok-experimental")]
    pub fn build_with_proof_packed(
        &self,
        public_params: &CompactPkePublicParams,
        compute_load: ZkComputeLoad,
    ) -> Result<ProvenCompactCiphertextList, JsError> {
        catch_panic_result(|| {
            self.0
                .build_with_proof_packed(&public_params.0, compute_load.into())
                .map_err(into_js_error)
                .map(ProvenCompactCiphertextList)
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
                                .unwrap()
                                .map_err(into_js_error)
                                .map([<FheUint $num_bits>])
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
                                .unwrap()
                                .map_err(into_js_error)
                                .map([<FheInt $num_bits>])
                        })
                    }
                )*
            }
        }
    };
}
define_expander_get_method!(
    unsigned: { 2, 4, 6, 8, 10, 12, 14, 16, 32, 64, 128, 160, 256 }
);
define_expander_get_method!(
    signed: { 2, 4, 6, 8, 10, 12, 14, 16, 32, 64, 128, 160, 256 }
);
#[wasm_bindgen]
impl CompactCiphertextListExpander {
    #[wasm_bindgen]
    pub fn get_bool(&mut self, index: usize) -> Result<FheBool, JsError> {
        catch_panic_result(|| {
            self.0
                .get::<crate::FheBool>(index)
                .unwrap()
                .map_err(into_js_error)
                .map(FheBool)
        })
    }
}
