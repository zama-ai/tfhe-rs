use tfhe_versionable::Versionize;

use super::ClientKey;
use crate::backward_compatibility::keys::{CompressedServerKeyVersions, ServerKeyVersions};
#[cfg(feature = "gpu")]
use crate::core_crypto::gpu::{synchronize_devices, CudaStreams};
use crate::high_level_api::keys::{IntegerCompressedServerKey, IntegerServerKey};
use crate::integer::compression_keys::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionKey, DecompressionKey,
};
use crate::prelude::Tagged;
use crate::shortint::MessageModulus;
use crate::Tag;
use std::sync::Arc;

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
#[derive(Clone, Versionize)]
#[versionize(ServerKeyVersions)]
pub struct ServerKey {
    pub(crate) key: Arc<IntegerServerKey>,
    pub(crate) tag: Tag,
}

impl ServerKey {
    pub fn new(keys: &ClientKey) -> Self {
        Self {
            key: Arc::new(IntegerServerKey::new(&keys.key)),
            tag: keys.tag.clone(),
        }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::ServerKey,
        Option<crate::integer::key_switching_key::KeySwitchingKeyMaterial>,
        Option<CompressionKey>,
        Option<DecompressionKey>,
        Tag,
    ) {
        let IntegerServerKey {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
        } = (*self.key).clone();

        (
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            self.tag,
        )
    }

    pub fn from_raw_parts(
        key: crate::integer::ServerKey,
        cpk_key_switching_key_material: Option<
            crate::integer::key_switching_key::KeySwitchingKeyMaterial,
        >,
        compression_key: Option<CompressionKey>,
        decompression_key: Option<DecompressionKey>,
        tag: Tag,
    ) -> Self {
        Self {
            key: Arc::new(IntegerServerKey {
                key,
                cpk_key_switching_key_material,
                compression_key,
                decompression_key,
            }),
            tag,
        }
    }

    pub(in crate::high_level_api) fn pbs_key(&self) -> &crate::integer::ServerKey {
        self.key.pbs_key()
    }

    pub(in crate::high_level_api) fn cpk_casting_key(
        &self,
    ) -> Option<crate::integer::key_switching_key::KeySwitchingKeyView> {
        self.key.cpk_casting_key()
    }

    pub(in crate::high_level_api) fn message_modulus(&self) -> MessageModulus {
        self.key.message_modulus()
    }
}

impl Tagged for ServerKey {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
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
// We directly versionize the `ServerKey` without having to use this intermediate type.
#[cfg_attr(tfhe_lints, allow(tfhe_lints::serialize_without_versionize))]
struct SerializableServerKey<'a> {
    pub(crate) integer_key: &'a IntegerServerKey,
    pub(crate) tag: &'a Tag,
}

impl serde::Serialize for ServerKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerializableServerKey {
            integer_key: &self.key,
            tag: &self.tag,
        }
        .serialize(serializer)
    }
}

#[derive(serde::Deserialize)]
struct DeserializableServerKey {
    pub(crate) integer_key: IntegerServerKey,
    pub(crate) tag: Tag,
}

impl<'de> serde::Deserialize<'de> for ServerKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DeserializableServerKey::deserialize(deserializer).map(|deserialized| Self {
            key: Arc::new(deserialized.integer_key),
            tag: deserialized.tag,
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
#[derive(Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedServerKeyVersions)]
pub struct CompressedServerKey {
    pub(crate) integer_key: IntegerCompressedServerKey,
    pub(crate) tag: Tag,
}

impl CompressedServerKey {
    pub fn new(keys: &ClientKey) -> Self {
        Self {
            integer_key: IntegerCompressedServerKey::new(&keys.key),
            tag: keys.tag.clone(),
        }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::CompressedServerKey,
        Option<crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial>,
        Option<CompressedCompressionKey>,
        Option<CompressedDecompressionKey>,
        Tag,
    ) {
        let (a, b, c, d) = self.integer_key.into_raw_parts();
        (a, b, c, d, self.tag)
    }

    pub fn from_raw_parts(
        integer_key: crate::integer::CompressedServerKey,
        cpk_key_switching_key_material: Option<
            crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial,
        >,
        compression_key: Option<CompressedCompressionKey>,
        decompression_key: Option<CompressedDecompressionKey>,
        tag: Tag,
    ) -> Self {
        Self {
            integer_key: IntegerCompressedServerKey::from_raw_parts(
                integer_key,
                cpk_key_switching_key_material,
                compression_key,
                decompression_key,
            ),
            tag,
        }
    }

    pub fn decompress(&self) -> ServerKey {
        ServerKey {
            key: Arc::new(self.integer_key.decompress()),
            tag: self.tag.clone(),
        }
    }

    #[cfg(feature = "gpu")]
    pub fn decompress_to_gpu(&self) -> CudaServerKey {
        let streams = CudaStreams::new_multi_gpu();
        synchronize_devices(streams.len() as u32);
        let cuda_key = crate::integer::gpu::CudaServerKey::decompress_from_cpu(
            &self.integer_key.key,
            &streams,
        );
        synchronize_devices(streams.len() as u32);
        CudaServerKey {
            key: Arc::new(cuda_key),
            tag: self.tag.clone(),
        }
    }
}

impl Tagged for CompressedServerKey {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

#[cfg(feature = "gpu")]
#[derive(Clone)]
pub struct CudaServerKey {
    pub(crate) key: Arc<crate::integer::gpu::CudaServerKey>,
    pub(crate) tag: Tag,
}

#[cfg(feature = "gpu")]
impl CudaServerKey {
    pub(crate) fn message_modulus(&self) -> crate::shortint::MessageModulus {
        self.key.message_modulus
    }
}

#[cfg(feature = "gpu")]
impl Tagged for CudaServerKey {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

pub enum InternalServerKey {
    Cpu(ServerKey),
    #[cfg(feature = "gpu")]
    Cuda(CudaServerKey),
}

impl From<ServerKey> for InternalServerKey {
    fn from(value: ServerKey) -> Self {
        Self::Cpu(value)
    }
}
#[cfg(feature = "gpu")]
impl From<CudaServerKey> for InternalServerKey {
    fn from(value: CudaServerKey) -> Self {
        Self::Cuda(value)
    }
}
