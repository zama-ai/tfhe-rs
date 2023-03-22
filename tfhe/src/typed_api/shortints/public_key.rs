use crate::typed_api::shortints::client_key::GenericShortIntClientKey;

use crate::typed_api::shortints::parameters::ShortIntegerParameter;
use serde::{Deserialize, Serialize};

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "shortint"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericShortIntPublicKey<P>
where
    P: ShortIntegerParameter,
{
    pub(in crate::typed_api::shortints) key: crate::shortint::public_key::PublicKey,
    _marker: std::marker::PhantomData<P>,
}

impl<P> GenericShortIntPublicKey<P>
where
    P: ShortIntegerParameter,
{
    pub fn new(client_key: &GenericShortIntClientKey<P>) -> Self {
        let key = crate::shortint::public_key::PublicKey::new(&client_key.key);
        Self {
            key,
            _marker: Default::default(),
        }
    }
}
