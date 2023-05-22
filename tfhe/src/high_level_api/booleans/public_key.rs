use crate::high_level_api::booleans::client_key::GenericBoolClientKey;
use crate::high_level_api::booleans::parameters::BooleanParameterSet;

use serde::{Deserialize, Serialize};

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericBoolPublicKey<P>
where
    P: BooleanParameterSet,
{
    pub(in crate::high_level_api::booleans) key: crate::boolean::public_key::PublicKey,
    _marker: std::marker::PhantomData<P>,
}

impl<P> GenericBoolPublicKey<P>
where
    P: BooleanParameterSet,
{
    pub fn new(client_key: &GenericBoolClientKey<P>) -> Self {
        let key = crate::boolean::public_key::PublicKey::new(&client_key.key);
        Self {
            key,
            _marker: Default::default(),
        }
    }
}

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericBoolCompressedPublicKey<P>
where
    P: BooleanParameterSet,
{
    pub(in crate::high_level_api::booleans) key: crate::boolean::public_key::CompressedPublicKey,
    _marker: std::marker::PhantomData<P>,
}

impl<P> GenericBoolCompressedPublicKey<P>
where
    P: BooleanParameterSet,
{
    pub fn new(client_key: &GenericBoolClientKey<P>) -> Self {
        let key = crate::boolean::public_key::CompressedPublicKey::new(&client_key.key);
        Self {
            key,
            _marker: Default::default(),
        }
    }

    pub fn decompress(self) -> GenericBoolPublicKey<P> {
        GenericBoolPublicKey {
            key: crate::boolean::public_key::PublicKey::from(self.key),
            _marker: Default::default(),
        }
    }
}
