use super::client_key::GenericShortIntClientKey;
use super::parameters::ShortIntegerParameter;
use super::server_key::GenericShortIntServerKey;
use crate::shortint::CastingKey;

use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// The casting key of a short integer type
///
/// A wrapper around `tfhe-shortint` `CastingKey`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericShortIntCastingKey<P: ShortIntegerParameter> {
    pub(super) key: CastingKey,
    _marker: PhantomData<P>,
}

impl<P: ShortIntegerParameter> GenericShortIntCastingKey<P> {
    pub(crate) fn new(
        key_pair_1: (&GenericShortIntClientKey<P>, &GenericShortIntServerKey<P>),
        key_pair_2: (&GenericShortIntClientKey<P>, &GenericShortIntServerKey<P>),
    ) -> Self {
        Self {
            key: CastingKey::new(
                (&key_pair_1.0.key, &key_pair_1.1.key),
                (&key_pair_2.0.key, &key_pair_2.1.key),
            ),
            _marker: Default::default(),
        }
    }
}
