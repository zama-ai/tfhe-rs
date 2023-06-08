use crate::{ClientKey, ServerKey};

#[cfg(feature = "integer")]
use crate::high_level_api::integers::IntegerCastingKey;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CastingKey {
    // #[cfg(feature = "boolean")]
    // pub(crate) boolean_key: BooleanClientKey,
    // #[cfg(feature = "shortint")]
    // pub(crate) shortint_key: ShortIntClientKey,
    #[cfg(feature = "integer")]
    pub(crate) integer_key: IntegerCastingKey,
}

impl CastingKey {
    pub fn new(key_pair_1: (&ClientKey, &ServerKey), key_pair_2: (&ClientKey, &ServerKey)) -> Self {
        Self {
            // #[cfg(feature = "boolean")]
            // boolean_key: Arc::new(BooleanServerKey::new(&keys.boolean_key)),
            // #[cfg(feature = "shortint")]
            // shortint_key: Arc::new(ShortIntServerKey::new(&keys.shortint_key)),
            #[cfg(feature = "integer")]
            integer_key: IntegerCastingKey::new(
                (&key_pair_1.0.integer_key, &key_pair_1.1.integer_key),
                (&key_pair_2.0.integer_key, &key_pair_2.1.integer_key),
            ),
        }
    }
}
