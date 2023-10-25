use crate::high_level_api::integers::{IntegerCompressedServerKey, IntegerServerKey};

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
    pub(crate) integer_key: Arc<IntegerServerKey>,
}

impl ServerKey {
    pub fn new(keys: &ClientKey) -> Self {
        Self {
            integer_key: Arc::new(IntegerServerKey::new(&keys.key)),
        }
    }
}

impl AsRef<crate::integer::ServerKey> for ServerKey {
    fn as_ref(&self) -> &crate::integer::ServerKey {
        &self.integer_key.key
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
            integer_key: &self.integer_key,
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
            integer_key: Arc::new(deserialized.integer_key),
        })
    }
}

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

    pub fn decompress(self) -> ServerKey {
        ServerKey {
            integer_key: Arc::new(self.integer_key.decompress()),
        }
    }
}

impl From<CompressedServerKey> for ServerKey {
    fn from(value: CompressedServerKey) -> Self {
        value.decompress()
    }
}
