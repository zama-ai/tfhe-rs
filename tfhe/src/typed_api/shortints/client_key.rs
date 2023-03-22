use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

#[cfg(feature = "internal-keycache")]
use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::ClientKey;

use super::parameters::ShortIntegerParameter;

/// The key associated to a short integer type
///
/// Can encrypt and decrypt it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericShortIntClientKey<P: ShortIntegerParameter> {
    pub(super) key: ClientKey,
    _marker: PhantomData<P>,
}

impl<P> From<P> for GenericShortIntClientKey<P>
where
    P: ShortIntegerParameter,
{
    fn from(parameters: P) -> Self {
        #[cfg(feature = "internal-keycache")]
        let key = KEY_CACHE
            .get_from_param(parameters.into())
            .client_key()
            .clone();
        #[cfg(not(feature = "internal-keycache"))]
        let key = ClientKey::new(parameters.into());

        Self {
            key,
            _marker: Default::default(),
        }
    }
}
