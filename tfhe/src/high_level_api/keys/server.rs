use crate::high_level_api::keys::{IntegerCompressedServerKey, IntegerServerKey};

use std::sync::Arc;

use super::ClientKey;

/// Key of the server
///
/// This key contains the different keys needed to be able to do computations for
/// each data type.
///
/// For a server to be able to do some FHE computations, the client needs to send this key
/// beforehand.
// Keys are stored in an Arc, so that cloning them is cheap
// (compared to an actual clone hundreds of MB / GB), and cheap cloning is needed for
// multithreading with less overhead)
#[derive(Clone)]
pub struct ServerKey {
    pub(crate) key: Arc<IntegerServerKey>,
}

impl ServerKey {
    pub fn new(keys: &ClientKey) -> Self {
        Self {
            key: Arc::new(IntegerServerKey::new(&keys.key)),
        }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::ServerKey,
        Option<crate::integer::wopbs::WopbsKey>,
    ) {
        let IntegerServerKey { key, wopbs_key } = (*self.key).clone();

        (key, wopbs_key)
    }

    pub fn from_raw_parts(
        key: crate::integer::ServerKey,
        wopbs_key: Option<crate::integer::wopbs::WopbsKey>,
    ) -> Self {
        Self {
            key: Arc::new(IntegerServerKey { key, wopbs_key }),
        }
    }
}

impl AsRef<crate::integer::ServerKey> for ServerKey {
    fn as_ref(&self) -> &crate::integer::ServerKey {
        &self.key.key
    }
}

// By default, serde does not derives Serialize/Deserialize for `Rc` and `Arc` types
// as they can result in multiple copies, since serializing has to serialize the actual data
// not the pointer.
//
// serde has a `rc` feature to allow deriving on Arc and Rc types
// but activating it in our lib would mean also activate it for all the dependency stack,
// so tfhe-rs users would have this feature enabled on our behalf and we don't want that
// so we implement the serialization / deserialization ourselves.
//
// In the case of our ServerKey, this is fine, we expect programs to only
// serialize and deserialize the same server key only once.
// The inner `Arc` are used to make copying a server key more performant before a `set_server_key`
// in multi-threading scenarios.
#[derive(serde::Serialize)]
struct SerializableServerKey<'a> {
    pub(crate) integer_key: &'a IntegerServerKey,
}

impl serde::Serialize for ServerKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerializableServerKey {
            integer_key: &self.key,
        }
        .serialize(serializer)
    }
}

#[derive(serde::Deserialize)]
struct DeserializableServerKey {
    pub(crate) integer_key: IntegerServerKey,
}

impl<'de> serde::Deserialize<'de> for ServerKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DeserializableServerKey::deserialize(deserializer).map(|deserialized| Self {
            key: Arc::new(deserialized.integer_key),
        })
    }
}

/// Compressed ServerKey
///
/// A CompressedServerKey takes much less disk space / memory space than a
/// ServerKey.
///
/// It has to be decompressed into a ServerKey in order to be usable.
///
/// Once decompressed, it is not possible to recompress the key.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CompressedServerKey {
    pub(crate) integer_key: IntegerCompressedServerKey,
}

impl CompressedServerKey {
    pub fn new(keys: &ClientKey) -> Self {
        Self {
            integer_key: IntegerCompressedServerKey::new(&keys.key),
        }
    }

    pub fn into_raw_parts(self) -> crate::integer::CompressedServerKey {
        self.integer_key.into_raw_parts()
    }

    pub fn from_raw_parts(integer_key: crate::integer::CompressedServerKey) -> Self {
        Self {
            integer_key: IntegerCompressedServerKey::from_raw_parts(integer_key),
        }
    }

    pub fn decompress(self) -> ServerKey {
        ServerKey {
            key: Arc::new(self.integer_key.decompress()),
        }
    }

    #[cfg(feature = "gpu")]
    pub fn decompress_to_gpu(&self) -> CudaServerKey {
        // TODO Maybe all this implementation should be its own function in the integer module
        let crate::shortint::CompressedServerKey {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            ciphertext_modulus,
            pbs_order,
        } = self.integer_key.key.key.clone();

        use crate::core_crypto::gpu::{CudaDevice, CudaStream};
        let device = CudaDevice::new(0);
        let stream = CudaStream::new_unchecked(device);

        let h_key_switching_key = key_switching_key.par_decompress_into_lwe_keyswitch_key();
        let key_switching_key =
            crate::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey::from_lwe_keyswitch_key(
                &h_key_switching_key,
                &stream,
            );
        let bootstrapping_key =  match bootstrapping_key {
                crate::shortint::server_key::compressed::ShortintCompressedBootstrappingKey::Classic(h_bootstrap_key) => {
                    let standard_bootstrapping_key =
                        h_bootstrap_key.par_decompress_into_lwe_bootstrap_key();

                    let d_bootstrap_key =
                        crate::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey::from_lwe_bootstrap_key(&standard_bootstrapping_key, &stream);

                    crate::integer::gpu::server_key::CudaBootstrappingKey::Classic(d_bootstrap_key)
                }
                crate::shortint::server_key::compressed::ShortintCompressedBootstrappingKey::MultiBit {
                    seeded_bsk: bootstrapping_key,
                    deterministic_execution: _,
                } => {
                    let standard_bootstrapping_key =
                        bootstrapping_key.par_decompress_into_lwe_multi_bit_bootstrap_key();

                    let d_bootstrap_key =
                        crate::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(
                            &standard_bootstrapping_key, &stream);

                    crate::integer::gpu::server_key::CudaBootstrappingKey::MultiBit(d_bootstrap_key)
                }
            };

        CudaServerKey {
            key: Arc::new(crate::integer::gpu::CudaServerKey {
                key_switching_key,
                bootstrapping_key,
                message_modulus,
                carry_modulus,
                max_degree,
                ciphertext_modulus,
                pbs_order,
            }),
        }
    }
}

impl From<CompressedServerKey> for ServerKey {
    fn from(value: CompressedServerKey) -> Self {
        value.decompress()
    }
}

#[cfg(feature = "gpu")]
#[derive(Clone)]
pub struct CudaServerKey {
    pub(crate) key: Arc<crate::integer::gpu::CudaServerKey>,
}

pub enum InternalServerKey {
    Cpu(Arc<IntegerServerKey>),
    #[cfg(feature = "gpu")]
    Cuda(CudaServerKey),
}

impl From<ServerKey> for InternalServerKey {
    fn from(value: ServerKey) -> Self {
        Self::Cpu(value.key)
    }
}
#[cfg(feature = "gpu")]
impl From<CudaServerKey> for InternalServerKey {
    fn from(value: CudaServerKey) -> Self {
        Self::Cuda(value)
    }
}
