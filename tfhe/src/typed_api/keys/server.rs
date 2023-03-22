#[cfg(feature = "boolean")]
use crate::typed_api::booleans::BooleanServerKey;
#[cfg(feature = "integer")]
use crate::typed_api::integers::IntegerServerKey;
#[cfg(feature = "shortint")]
use crate::typed_api::shortints::ShortIntServerKey;

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
    #[allow(unused_variables)]
    pub(crate) fn new(keys: &ClientKey) -> Self {
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
