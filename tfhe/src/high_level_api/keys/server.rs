#[cfg(feature = "boolean")]
use crate::high_level_api::booleans::{BooleanCompressedServerKey, BooleanServerKey};
#[cfg(feature = "integer")]
use crate::high_level_api::integers::{IntegerCompressedServerKey, IntegerServerKey};
#[cfg(feature = "shortint")]
use crate::high_level_api::shortints::{ShortIntCompressedServerKey, ShortIntServerKey};

#[cfg(any(feature = "boolean", feature = "shortint", feature = "integer"))]
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
#[derive(Clone, Default)]
pub struct ServerKey {
    #[cfg(feature = "boolean")]
    pub(crate) boolean_key: Arc<BooleanServerKey>,
    #[cfg(feature = "shortint")]
    pub(crate) shortint_key: Arc<ShortIntServerKey>,
    #[cfg(feature = "integer")]
    pub(crate) integer_key: Arc<IntegerServerKey>,
}

impl ServerKey {
    pub fn new(keys: &ClientKey) -> Self {
        Self {
            #[cfg(feature = "boolean")]
            boolean_key: Arc::new(BooleanServerKey::new(&keys.boolean_key)),
            #[cfg(feature = "shortint")]
            shortint_key: Arc::new(ShortIntServerKey::new(&keys.shortint_key)),
            #[cfg(feature = "integer")]
            integer_key: Arc::new(IntegerServerKey::new(&keys.integer_key)),
        }
    }
}

#[cfg(feature = "integer")]
impl AsRef<crate::integer::ServerKey> for ServerKey {
    fn as_ref(&self) -> &crate::integer::ServerKey {
        self.integer_key.key.as_ref().unwrap()
    }
}

// By default, serde does not derives Serialize/Deserialize for `Rc` and `Arc` types
// as they can result in multiple copies, since serializing has to serialize the actual data
// not the pointer.
//
// serde has a `rc` feature to allow deriving on Arc and Rc types
// but activating it in our lib would mean also activate it for all the dependency stack,
// so tfhe-rs users would have this feature enabled on our behalf and we don't want that
// so we implement the serialization / deseriazation ourselves.
//
// In the case of our ServerKey, this is fine, we expect programs to only
// serialize and deserialize the same server key only once.
// The inner `Arc` are used to make copying a server key more performant before a `set_server_key`
// in multi-threading scenarios.
#[derive(serde::Serialize)]
struct SerializableServerKey<'a> {
    #[cfg(feature = "boolean")]
    pub(crate) boolean_key: &'a BooleanServerKey,
    #[cfg(feature = "shortint")]
    pub(crate) shortint_key: &'a ShortIntServerKey,
    #[cfg(feature = "integer")]
    pub(crate) integer_key: &'a IntegerServerKey,
}

impl serde::Serialize for ServerKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerializableServerKey {
            #[cfg(feature = "boolean")]
            boolean_key: &self.boolean_key,
            #[cfg(feature = "shortint")]
            shortint_key: &self.shortint_key,
            #[cfg(feature = "integer")]
            integer_key: &self.integer_key,
        }
        .serialize(serializer)
    }
}

#[derive(serde::Deserialize)]
struct DeserializableServerKey {
    #[cfg(feature = "boolean")]
    pub(crate) boolean_key: BooleanServerKey,
    #[cfg(feature = "shortint")]
    pub(crate) shortint_key: ShortIntServerKey,
    #[cfg(feature = "integer")]
    pub(crate) integer_key: IntegerServerKey,
}

impl<'de> serde::Deserialize<'de> for ServerKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DeserializableServerKey::deserialize(deserializer).map(|deserialized| Self {
            #[cfg(feature = "boolean")]
            boolean_key: Arc::new(deserialized.boolean_key),
            #[cfg(feature = "shortint")]
            shortint_key: Arc::new(deserialized.shortint_key),
            #[cfg(feature = "integer")]
            integer_key: Arc::new(deserialized.integer_key),
        })
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CompressedServerKey {
    #[cfg(feature = "boolean")]
    pub(crate) boolean_key: BooleanCompressedServerKey,
    #[cfg(feature = "shortint")]
    pub(crate) shortint_key: ShortIntCompressedServerKey,
    #[cfg(feature = "integer")]
    pub(crate) integer_key: IntegerCompressedServerKey,
}

impl CompressedServerKey {
    pub fn new(keys: &ClientKey) -> Self {
        Self {
            #[cfg(feature = "boolean")]
            boolean_key: BooleanCompressedServerKey::new(&keys.boolean_key),
            #[cfg(feature = "shortint")]
            shortint_key: ShortIntCompressedServerKey::new(&keys.shortint_key),
            #[cfg(feature = "integer")]
            integer_key: IntegerCompressedServerKey::new(&keys.integer_key),
        }
    }

    pub fn decompress(self) -> ServerKey {
        ServerKey {
            #[cfg(feature = "boolean")]
            boolean_key: Arc::new(self.boolean_key.decompress()),
            #[cfg(feature = "shortint")]
            shortint_key: Arc::new(self.shortint_key.decompress()),
            #[cfg(feature = "integer")]
            integer_key: Arc::new(self.integer_key.decompress()),
        }
    }
}

impl From<CompressedServerKey> for ServerKey {
    fn from(value: CompressedServerKey) -> Self {
        value.decompress()
    }
}
