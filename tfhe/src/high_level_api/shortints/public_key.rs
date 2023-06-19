use crate::high_level_api::shortints::client_key::GenericShortIntClientKey;

use crate::high_level_api::shortints::parameters::ShortIntegerParameter;
use serde::{Deserialize, Serialize};

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "shortint"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericShortIntPublicKey<P>
where
    P: ShortIntegerParameter,
{
    pub(in crate::high_level_api::shortints) key: crate::shortint::public_key::PublicKey,
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

pub(in crate::high_level_api::shortints) mod compressed {
    use serde::{Deserialize, Serialize};

    use crate::high_level_api::shortints::client_key::GenericShortIntClientKey;
    use crate::high_level_api::shortints::parameters::ShortIntegerParameter;

    #[cfg_attr(all(doc, not(doctest)), cfg(feature = "shortint"))]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct GenericShortIntCompressedPublicKey<P>
    where
        P: ShortIntegerParameter,
    {
        pub(in crate::high_level_api::shortints) key:
            crate::shortint::public_key::CompressedPublicKey,
        _marker: std::marker::PhantomData<P>,
    }

    impl<P> GenericShortIntCompressedPublicKey<P>
    where
        P: ShortIntegerParameter,
    {
        pub fn new(client_key: &GenericShortIntClientKey<P>) -> Self {
            let key = crate::shortint::public_key::CompressedPublicKey::new(&client_key.key);
            Self {
                key,
                _marker: Default::default(),
            }
        }

        pub(crate) fn decompress(self) -> super::GenericShortIntPublicKey<P> {
            super::GenericShortIntPublicKey {
                key: self.key.into(),
                _marker: std::marker::PhantomData,
            }
        }
    }
}
