use crate::typed_api::shortints::client_key::GenericShortIntClientKey;

use crate::typed_api::shortints::parameters::ShortIntegerParameter;
use serde::{Deserialize, Serialize};

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "shortint"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericShortIntPublicKey<P>
where
    P: ShortIntegerParameter,
{
    pub(in crate::typed_api::shortints) key: crate::shortint::public_key::PublicKeyBig,
    _marker: std::marker::PhantomData<P>,
}

impl<P> GenericShortIntPublicKey<P>
where
    P: ShortIntegerParameter,
{
    pub fn new(client_key: &GenericShortIntClientKey<P>) -> Self {
        let key = crate::shortint::public_key::PublicKeyBig::new(&client_key.key);
        Self {
            key,
            _marker: Default::default(),
        }
    }
}

pub(in crate::typed_api::shortints) mod compressed {
    use serde::{Deserialize, Serialize};

    use crate::typed_api::shortints::client_key::GenericShortIntClientKey;
    use crate::typed_api::shortints::parameters::ShortIntegerParameter;

    #[cfg_attr(all(doc, not(doctest)), cfg(feature = "shortint"))]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct GenericShortIntCompressedPublicKey<P>
    where
        P: ShortIntegerParameter,
    {
        pub(in crate::typed_api::shortints) key:
            crate::shortint::public_key::CompressedPublicKeyBig,
        _marker: std::marker::PhantomData<P>,
    }

    impl<P> GenericShortIntCompressedPublicKey<P>
    where
        P: ShortIntegerParameter,
    {
        pub fn new(client_key: &GenericShortIntClientKey<P>) -> Self {
            let key = crate::shortint::public_key::CompressedPublicKeyBig::new(&client_key.key);
            Self {
                key,
                _marker: Default::default(),
            }
        }
    }
}
