use crate::high_level_api::prelude::*;
use crate::integer::bigint::{StaticUnsignedBigInt, U2048};
use crate::integer::{I256, U256};
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
            compact_type_name: $compact_type_name:ident,
            compact_list_type_name: $compact_list_type_name:ident,
            proven_type: $proven_type:ident,
            proven_compact_type_name: $proven_compact_type_name:ident,
            proven_compact_list_type_name: $proven_compact_list_type_name:ident,
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

        #[cfg(feature = "zk-pok-experimental")]
        #[wasm_bindgen]
        pub struct $proven_compact_type_name(pub(crate) crate::high_level_api::$proven_compact_type_name);

        #[cfg(feature = "zk-pok-experimental")]
        #[wasm_bindgen]
        impl $proven_compact_type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_compact_public_key(
                value: JsValue,
                public_params: &crate::js_on_wasm_api::js_high_level_api::zk::CompactPkePublicParams,
                public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey,
                compute_load: crate::js_on_wasm_api::js_high_level_api::zk::ZkComputeLoad,
            ) -> Result<$proven_compact_type_name, JsError> {
                catch_panic_result(|| {
                    let value = <$rust_type>::try_from(value)
                        .map_err(|_| JsError::new(&format!("Failed to convert the value to a {}", stringify!($rust_type))))?;
                    crate::high_level_api::$proven_compact_type_name::try_encrypt(
                        value,
                        &public_params.0,
                        &public_key.0,
                        compute_load.into()
                    ).map($proven_compact_type_name)
                     .map_err(into_js_error)
                })
            }

           #[wasm_bindgen]
           pub fn verifies(
               &self,
               public_parameters: &crate::js_on_wasm_api::js_high_level_api::zk::CompactPkePublicParams,
               public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey
           ) -> bool {
               self.0.verify(&public_parameters.0, &public_key.0).is_valid()
           }

            #[wasm_bindgen]
            pub fn verify_and_expand(
                &self,
                public_parameters: &crate::js_on_wasm_api::js_high_level_api::zk::CompactPkePublicParams,
                public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey
            ) -> Result<$type_name, JsError> {
                catch_panic(||{
                   self.0
                   .clone()
                   .verify_and_expand(&public_parameters.0, &public_key.0)
                   .map($type_name)
                   .unwrap()
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$proven_compact_type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($proven_compact_type_name)
                        .map_err(into_js_error)
                })
            }
        }

        #[cfg(feature = "zk-pok-experimental")]
        #[wasm_bindgen]
        pub struct $proven_compact_list_type_name(pub(crate) crate::high_level_api::$proven_compact_list_type_name);

        #[cfg(feature = "zk-pok-experimental")]
        #[wasm_bindgen]
        impl $proven_compact_list_type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_compact_public_key(
                values: Vec<JsValue>,
                public_params: &crate::js_on_wasm_api::js_high_level_api::zk::CompactPkePublicParams,
                public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey,
                compute_load: crate::js_on_wasm_api::js_high_level_api::zk::ZkComputeLoad,
            ) -> Result<$proven_compact_list_type_name, JsError> {
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
                    crate::high_level_api::$proven_compact_list_type_name::try_encrypt(
                        &values,
                        &public_params.0,
                        &public_key.0,
                        compute_load.into()
                    ).map($proven_compact_list_type_name)
                     .map_err(into_js_error)
                })
            }

           #[wasm_bindgen]
           pub fn verifies(
               &self,
               public_parameters: &crate::js_on_wasm_api::js_high_level_api::zk::CompactPkePublicParams,
               public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey
           ) -> bool {
               self.0.verify(&public_parameters.0, &public_key.0).is_valid()
           }

           #[wasm_bindgen]
            pub fn verify_and_expand(
                &self,
                public_parameters: &crate::js_on_wasm_api::js_high_level_api::zk::CompactPkePublicParams,
                public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey
            ) -> Result<Vec<$type_name>, JsError> {
                catch_panic(||{
                   self.0
                   .clone()
                   .verify_and_expand(&public_parameters.0, &public_key.0)
                   .map(|vec| vec.into_iter().map($type_name).collect::<Vec<_>>())
                   .unwrap()
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$proven_compact_list_type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($proven_compact_list_type_name)
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
                proven_type: $proven_type:ident,
                proven_compact_type_name: $proven_compact_type_name:ident,
                proven_compact_list_type_name: $proven_compact_list_type_name:ident,
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
                    proven_type: $proven_type,
                    proven_compact_type_name: $proven_compact_type_name,
                    proven_compact_list_type_name: $proven_compact_list_type_name,
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
        proven_type: ProvenFheUint128,
        proven_compact_type_name: ProvenCompactFheUint128,
        proven_compact_list_type_name: ProvenCompactFheUint128List,
        rust_type: u128,
    },
    {
        type_name: FheUint160,
        compressed_type_name: CompressedFheUint160,
        compact_type_name: CompactFheUint160,
        compact_list_type_name: CompactFheUint160List,
        proven_type: ProvenFheUint160,
        proven_compact_type_name: ProvenCompactFheUint160,
        proven_compact_list_type_name: ProvenCompactFheUint160List,
        rust_type: U256,
    },
    {
        type_name: FheUint256,
        compressed_type_name: CompressedFheUint256,
        compact_type_name: CompactFheUint256,
        compact_list_type_name: CompactFheUint256List,
        proven_type: ProvenFheUint256,
        proven_compact_type_name: ProvenCompactFheUint256,
        proven_compact_list_type_name: ProvenCompactFheUint256List,
        rust_type: U256,
    },
    {
        type_name: FheUint2048,
        compressed_type_name: CompressedFheUint2048,
        compact_type_name: CompactFheUint2048,
        compact_list_type_name: CompactFheUint2048List,
        proven_type: ProvenFheUint2048,
        proven_compact_type_name: ProvenCompactFheUint2048,
        proven_compact_list_type_name: ProvenCompactFheUint2048List,
        rust_type: U2048,
    },
    // Signed
    {
        type_name: FheInt128,
        compressed_type_name: CompressedFheInt128,
        compact_type_name: CompactFheInt128,
        compact_list_type_name: CompactFheInt128List,
        proven_type: ProvenFheInt128,
        proven_compact_type_name: ProvenCompactFheInt128,
        proven_compact_list_type_name: ProvenCompactFheInt128List,
        rust_type: i128,
    },
    {
        type_name: FheInt160,
        compressed_type_name: CompressedFheInt160,
        compact_type_name: CompactFheInt160,
        compact_list_type_name: CompactFheInt160List,
        proven_type: ProvenFheInt160,
        proven_compact_type_name: ProvenCompactFheInt160,
        proven_compact_list_type_name: ProvenCompactFheInt160List,
        rust_type: I256,
    },
    {
        type_name: FheInt256,
        compressed_type_name: CompressedFheInt256,
        compact_type_name: CompactFheInt256,
        compact_list_type_name: CompactFheInt256List,
        proven_type: ProvenFheInt256,
        proven_compact_type_name: ProvenCompactFheInt256,
        proven_compact_list_type_name: ProvenCompactFheInt256List,
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
            compact_type_name: $compact_type_name:ident,
            compact_list_type_name: $compact_list_type_name:ident,
            proven_type: $proven_type:ident,
            proven_compact_type_name: $proven_compact_type_name:ident,
            proven_compact_list_type_name: $proven_compact_list_type_name:ident,
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

        #[cfg(feature = "zk-pok-experimental")]
        #[wasm_bindgen]
        pub struct $proven_compact_type_name(pub(crate) crate::high_level_api::$proven_compact_type_name);

        #[cfg(feature = "zk-pok-experimental")]
        #[wasm_bindgen]
        impl $proven_compact_type_name {
           #[wasm_bindgen]
            pub fn encrypt_with_compact_public_key(
                value: $native_type,
                public_params: &crate::js_on_wasm_api::js_high_level_api::zk::CompactPkePublicParams,
                public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey,
                compute_load: crate::js_on_wasm_api::js_high_level_api::zk::ZkComputeLoad,
            ) -> Result<$proven_compact_type_name, JsError> {
                catch_panic_result(|| {
                    crate::high_level_api::$proven_compact_type_name::try_encrypt(
                        value,
                        &public_params.0,
                        &public_key.0,
                        compute_load.into()
                    ).map($proven_compact_type_name)
                     .map_err(into_js_error)
                })
            }

           #[wasm_bindgen]
           pub fn verifies(
               &self,
               public_parameters: &crate::js_on_wasm_api::js_high_level_api::zk::CompactPkePublicParams,
               public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey
           ) -> bool {
               self.0.verify(&public_parameters.0, &public_key.0).is_valid()
           }

            #[wasm_bindgen]
            pub fn verify_and_expand(
                &self,
                public_parameters: &crate::js_on_wasm_api::js_high_level_api::zk::CompactPkePublicParams,
                public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey
            ) -> Result<$type_name, JsError> {
                catch_panic(||{
                   self.0
                   .clone()
                   .verify_and_expand(&public_parameters.0, &public_key.0)
                   .map($type_name)
                   .unwrap()
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$proven_compact_type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($proven_compact_type_name)
                        .map_err(into_js_error)
                })
            }
        }

        #[cfg(feature = "zk-pok-experimental")]
        #[wasm_bindgen]
        pub struct $proven_compact_list_type_name(pub(crate) crate::high_level_api::$proven_compact_list_type_name);

        #[cfg(feature = "zk-pok-experimental")]
        #[wasm_bindgen]
        impl $proven_compact_list_type_name {
           #[wasm_bindgen]
           pub fn verifies(
               &self,
               public_parameters: &crate::js_on_wasm_api::js_high_level_api::zk::CompactPkePublicParams,
               public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey
           ) -> bool {
               self.0.verify(&public_parameters.0, &public_key.0).is_valid()
           }

           #[wasm_bindgen]
            pub fn verify_and_expand(
                &self,
                public_parameters: &crate::js_on_wasm_api::js_high_level_api::zk::CompactPkePublicParams,
                public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey
            ) -> Result<Vec<$type_name>, JsError> {
                catch_panic(||{
                   self.0
                   .clone()
                   .verify_and_expand(&public_parameters.0, &public_key.0)
                   .map(|vec| vec.into_iter().map($type_name).collect::<Vec<_>>())
                   .unwrap()
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$proven_compact_list_type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($proven_compact_list_type_name)
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
                proven_type: $proven_type:ident,
                proven_compact_type_name: $proven_compact_type_name:ident,
                proven_compact_list_type_name: $proven_compact_list_type_name:ident,
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
                    proven_type: $proven_type,
                    proven_compact_type_name: $proven_compact_type_name,
                    proven_compact_list_type_name: $proven_compact_list_type_name,
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
        compact_type_name: CompactFheBool,
        compact_list_type_name: CompactFheBoolList,
        proven_type: ProvenFheBool,
        proven_compact_type_name: ProvenCompactFheBool,
        proven_compact_list_type_name: ProvenCompactFheBoolList,
        native_type: bool,
    },
    {
        type_name: FheUint2,
        compressed_type_name: CompressedFheUint2,
        compact_type_name: CompactFheUint2,
        compact_list_type_name: CompactFheUint2List,
        proven_type: ProvenFheUint2,
        proven_compact_type_name: ProvenCompactFheUint2,
        proven_compact_list_type_name: ProvenCompactFheUint2List,
        native_type: u8,
    },
    {
        type_name: FheUint4,
        compressed_type_name: CompressedFheUint4,
        compact_type_name: CompactFheUint4,
        compact_list_type_name: CompactFheUint4List,
        proven_type: ProvenFheUint4,
        proven_compact_type_name: ProvenCompactFheUint4,
        proven_compact_list_type_name: ProvenCompactFheUint4List,
        native_type: u8,
    },
    {
        type_name: FheUint6,
        compressed_type_name: CompressedFheUint6,
        compact_type_name: CompactFheUint6,
        compact_list_type_name: CompactFheUint6List,
        proven_type: ProvenFheUint6,
        proven_compact_type_name: ProvenCompactFheUint6,
        proven_compact_list_type_name: ProvenCompactFheUint6List,
        native_type: u8,
    },
    {
        type_name: FheUint8,
        compressed_type_name: CompressedFheUint8,
        compact_type_name: CompactFheUint8,
        compact_list_type_name: CompactFheUint8List,
        proven_type: ProvenFheUint8,
        proven_compact_type_name: ProvenCompactFheUint8,
        proven_compact_list_type_name: ProvenCompactFheUint8List,
        native_type: u8,
    },
    {
        type_name: FheUint10,
        compressed_type_name: CompressedFheUint10,
        compact_type_name: CompactFheUint10,
        compact_list_type_name: CompactFheUint10List,
        proven_type: ProvenFheUint10,
        proven_compact_type_name: ProvenCompactFheUint10,
        proven_compact_list_type_name: ProvenCompactFheUint10List,
        native_type: u16,
    },
    {
        type_name: FheUint12,
        compressed_type_name: CompressedFheUint12,
        compact_type_name: CompactFheUint12,
        compact_list_type_name: CompactFheUint12List,
        proven_type: ProvenFheUint12,
        proven_compact_type_name: ProvenCompactFheUint12,
        proven_compact_list_type_name: ProvenCompactFheUint12List,
        native_type: u16,
    },
    {
        type_name: FheUint14,
        compressed_type_name: CompressedFheUint14,
        compact_type_name: CompactFheUint14,
        compact_list_type_name: CompactFheUint14List,
        proven_type: ProvenFheUint14,
        proven_compact_type_name: ProvenCompactFheUint14,
        proven_compact_list_type_name: ProvenCompactFheUint14List,
        native_type: u16,
    },
    {
        type_name: FheUint16,
        compressed_type_name: CompressedFheUint16,
        compact_type_name: CompactFheUint16,
        compact_list_type_name: CompactFheUint16List,
        proven_type: ProvenFheUint16,
        proven_compact_type_name: ProvenCompactFheUint16,
        proven_compact_list_type_name: ProvenCompactFheUint16List,
        native_type: u16,
    },
    {
        type_name: FheUint32,
        compressed_type_name: CompressedFheUint32,
        compact_type_name: CompactFheUint32,
        compact_list_type_name: CompactFheUint32List,
        proven_type: ProvenFheUint32,
        proven_compact_type_name: ProvenCompactFheUint32,
        proven_compact_list_type_name: ProvenCompactFheUint32List,
        native_type: u32,
    },
    {
        type_name: FheUint64,
        compressed_type_name: CompressedFheUint64,
        compact_type_name: CompactFheUint64,
        compact_list_type_name: CompactFheUint64List,
        proven_type: ProvenFheUint64,
        proven_compact_type_name: ProvenCompactFheUint64,
        proven_compact_list_type_name: ProvenCompactFheUint64List,
        native_type: u64,
    },
    // Signed
    {
        type_name: FheInt2,
        compressed_type_name: CompressedFheInt2,
        compact_type_name: CompactFheInt2,
        compact_list_type_name: CompactFheInt2List,
        proven_type: ProvenFheInt2,
        proven_compact_type_name: ProvenCompactFheInt2,
        proven_compact_list_type_name: ProvenCompactFheInt2List,
        native_type: i8,
    },
    {
        type_name: FheInt4,
        compressed_type_name: CompressedFheInt4,
        compact_type_name: CompactFheInt4,
        compact_list_type_name: CompactFheInt4List,
        proven_type: ProvenFheInt4,
        proven_compact_type_name: ProvenCompactFheInt4,
        proven_compact_list_type_name: ProvenCompactFheInt4List,
        native_type: i8,
    },
    {
        type_name: FheInt6,
        compressed_type_name: CompressedFheInt6,
        compact_type_name: CompactFheInt6,
        compact_list_type_name: CompactFheInt6List,
        proven_type: ProvenFheInt6,
        proven_compact_type_name: ProvenCompactFheInt6,
        proven_compact_list_type_name: ProvenCompactFheInt6List,
        native_type: i8,
    },
    {
        type_name: FheInt8,
        compressed_type_name: CompressedFheInt8,
        compact_type_name: CompactFheInt8,
        compact_list_type_name: CompactFheInt8List,
        proven_type: ProvenFheInt8,
        proven_compact_type_name: ProvenCompactFheInt8,
        proven_compact_list_type_name: ProvenCompactFheInt8List,
        native_type: i8,
    },
    {
        type_name: FheInt10,
        compressed_type_name: CompressedFheInt10,
        compact_type_name: CompactFheInt10,
        compact_list_type_name: CompactFheInt10List,
        proven_type: ProvenFheInt10,
        proven_compact_type_name: ProvenCompactFheInt10,
        proven_compact_list_type_name: ProvenCompactFheInt10List,
        native_type: i16,
    },
    {
        type_name: FheInt12,
        compressed_type_name: CompressedFheInt12,
        compact_type_name: CompactFheInt12,
        compact_list_type_name: CompactFheInt12List,
        proven_type: ProvenFheInt12,
        proven_compact_type_name: ProvenCompactFheInt12,
        proven_compact_list_type_name: ProvenCompactFheInt12List,
        native_type: i16,
    },
    {
        type_name: FheInt14,
        compressed_type_name: CompressedFheInt14,
        compact_type_name: CompactFheInt14,
        compact_list_type_name: CompactFheInt14List,
        proven_type: ProvenFheInt14,
        proven_compact_type_name: ProvenCompactFheInt14,
        proven_compact_list_type_name: ProvenCompactFheInt14List,
        native_type: i16,
    },
    {
        type_name: FheInt16,
        compressed_type_name: CompressedFheInt16,
        compact_type_name: CompactFheInt16,
        compact_list_type_name: CompactFheInt16List,
        proven_type: ProvenFheInt16,
        proven_compact_type_name: ProvenCompactFheInt16,
        proven_compact_list_type_name: ProvenCompactFheInt16List,
        native_type: i16,
    },
        {
        type_name: FheInt32,
        compressed_type_name: CompressedFheInt32,
        compact_type_name: CompactFheInt32,
        compact_list_type_name: CompactFheInt32List,
        proven_type: ProvenFheInt32,
        proven_compact_type_name: ProvenCompactFheInt32,
        proven_compact_list_type_name: ProvenCompactFheInt32List,
        native_type: i32,
    },
    {
        type_name: FheInt64,
        compressed_type_name: CompressedFheInt64,
        compact_type_name: CompactFheInt64,
        compact_list_type_name: CompactFheInt64List,
        proven_type: ProvenFheInt64,
        proven_compact_type_name: ProvenCompactFheInt64,
        proven_compact_list_type_name: ProvenCompactFheInt64List,
        native_type: i64,
    },
);

// Note this used to be defined in "create_wrapper_type_that_has_native_type",
// however, 'bool' does not implement JsObject which seems to prohibit having Vec<bool> as input
// param.
//
// So this was moved out
macro_rules! define_encrypt_list_with_compact_public_key {
    (
        $(
            {$compact_list_type_name:ident, $native_type:ty}
        ),*
        $(,)?
    ) => {
        $(
            #[wasm_bindgen]
            impl $compact_list_type_name {

                #[wasm_bindgen]
                pub fn encrypt_with_compact_public_key(
                    values: Vec<$native_type>,
                    public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey,
                ) -> Result<$compact_list_type_name, JsError> {
                    catch_panic_result(|| {
                        $crate::high_level_api::$compact_list_type_name::try_encrypt(&values, &public_key.0)
                            .map($compact_list_type_name)
                            .map_err(into_js_error)
                    })
                }
            }
        )*
    };
}

define_encrypt_list_with_compact_public_key!(
    {CompactFheUint2List, u8},
    {CompactFheUint4List, u8},
    {CompactFheUint6List, u8},
    {CompactFheUint8List, u8},
    {CompactFheUint12List, u16},
    {CompactFheUint14List, u16},
    {CompactFheUint16List, u16},
    {CompactFheUint32List, u32},
    {CompactFheUint64List, u64},
    // Signed
    {CompactFheInt2List, i8},
    {CompactFheInt4List, i8},
    {CompactFheInt6List, i8},
    {CompactFheInt8List, i8},
    {CompactFheInt12List, i16},
    {CompactFheInt14List, i16},
    {CompactFheInt16List, i16},
    {CompactFheInt32List, i32},
    {CompactFheInt64List, i64},
);

// Since Vec<bool> is not wasm compatible, we handle conversions ourselves
// clippy has some complaints to make, but we can't fulfill them, otherwise
// wasm_bindgen fails to compile
#[allow(clippy::use_self)]
#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen]
impl CompactFheBoolList {
    #[wasm_bindgen]
    pub fn encrypt_with_compact_public_key(
        values: Vec<JsValue>,
        public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey,
    ) -> Result<CompactFheBoolList, JsError> {
        catch_panic_result(|| {
            let booleans = values
                .iter()
                .map(|jsvalue| {
                    jsvalue
                        .as_bool()
                        .ok_or_else(|| JsError::new("Value is not a boolean"))
                })
                .collect::<Result<Vec<_>, JsError>>()?;
            crate::high_level_api::CompactFheBoolList::try_encrypt(&booleans, &public_key.0)
                .map(CompactFheBoolList)
                .map_err(into_js_error)
        })
    }
}

#[cfg(feature = "zk-pok-experimental")]
macro_rules! define_prove_and_encrypt_list_with_compact_public_key {
    (
        $(
            {$proven_compact_list_type_name:ident, $native_type:ty}
        ),*
        $(,)?
    ) => {
        $(
            #[wasm_bindgen]
            impl $proven_compact_list_type_name {

                #[wasm_bindgen]
                pub fn encrypt_with_compact_public_key(
                    values: Vec<$native_type>,
                    public_params: &crate::js_on_wasm_api::js_high_level_api::zk::CompactPkePublicParams,
                    public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey,
                    compute_load: crate::js_on_wasm_api::js_high_level_api::zk::ZkComputeLoad,
                ) -> Result<$proven_compact_list_type_name, JsError> {
                    catch_panic_result(|| {
                        $crate::high_level_api::$proven_compact_list_type_name::try_encrypt(
                            &values,
                            &public_params.0,
                            &public_key.0,
                            compute_load.into(),
                        ).map($proven_compact_list_type_name)
                         .map_err(into_js_error)
                    })
                }
            }
        )*
    };
}

#[cfg(feature = "zk-pok-experimental")]
define_prove_and_encrypt_list_with_compact_public_key!(
    {ProvenCompactFheUint2List, u8},
    {ProvenCompactFheUint4List, u8},
    {ProvenCompactFheUint6List, u8},
    {ProvenCompactFheUint8List, u8},
    {ProvenCompactFheUint12List, u16},
    {ProvenCompactFheUint14List, u16},
    {ProvenCompactFheUint16List, u16},
    {ProvenCompactFheUint32List, u32},
    {ProvenCompactFheUint64List, u64},
    // Signed
    {ProvenCompactFheInt2List, i8},
    {ProvenCompactFheInt4List, i8},
    {ProvenCompactFheInt6List, i8},
    {ProvenCompactFheInt8List, i8},
    {ProvenCompactFheInt12List, i16},
    {ProvenCompactFheInt14List, i16},
    {ProvenCompactFheInt16List, i16},
    {ProvenCompactFheInt32List, i32},
    {ProvenCompactFheInt64List, i64},
);

#[cfg(feature = "zk-pok-experimental")]
#[allow(clippy::use_self)]
#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen]
impl ProvenCompactFheBoolList {
    #[wasm_bindgen]
    pub fn encrypt_with_compact_public_key(
        values: Vec<JsValue>,
        public_params: &crate::js_on_wasm_api::js_high_level_api::zk::CompactPkePublicParams,
        public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey,
        compute_load: crate::js_on_wasm_api::js_high_level_api::zk::ZkComputeLoad,
    ) -> Result<ProvenCompactFheBoolList, JsError> {
        catch_panic_result(|| {
            let booleans = values
                .iter()
                .map(|jsvalue| {
                    jsvalue
                        .as_bool()
                        .ok_or_else(|| JsError::new("Value is not a boolean"))
                })
                .collect::<Result<Vec<_>, JsError>>()?;
            crate::high_level_api::ProvenCompactFheBoolList::try_encrypt(
                &booleans,
                &public_params.0,
                &public_key.0,
                compute_load.into(),
            )
            .map(ProvenCompactFheBoolList)
            .map_err(into_js_error)
        })
    }
}
