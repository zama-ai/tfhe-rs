use super::client_key::GenericShortIntClientKey;
use super::parameters::ShortIntegerParameter;
use super::server_key::GenericShortIntServerKey;
use crate::shortint::parameters::ShortintKeySwitchingParameters;
use crate::shortint::KeySwitchingKey;

use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Clone, Debug, ::serde::Deserialize, ::serde::Serialize)]
pub(crate) struct GenericShortIntKeySwitchingParameters<P: ShortIntegerParameter> {
    pub(crate) params: ShortintKeySwitchingParameters,
    _marker: PhantomData<P>,
}

impl<P: ShortIntegerParameter> From<ShortintKeySwitchingParameters>
    for GenericShortIntKeySwitchingParameters<P>
{
    fn from(params: ShortintKeySwitchingParameters) -> Self {
        Self {
            params,
            _marker: Default::default(),
        }
    }
}

/// The key switching key of a short integer type
///
/// A wrapper around `tfhe-shortint` `KeySwitchingKey`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericShortIntKeySwitchingKey<P: ShortIntegerParameter> {
    pub(super) key: KeySwitchingKey,
    _marker: PhantomData<P>,
}

impl<P: ShortIntegerParameter> GenericShortIntKeySwitchingKey<P> {
    pub(crate) fn new(
        key_pair_1: (&GenericShortIntClientKey<P>, &GenericShortIntServerKey<P>),
        key_pair_2: (&GenericShortIntClientKey<P>, &GenericShortIntServerKey<P>),
        parameters: GenericShortIntKeySwitchingParameters<P>,
    ) -> Self {
        Self {
            key: KeySwitchingKey::new(
                (&key_pair_1.0.key, &key_pair_1.1.key),
                (&key_pair_2.0.key, &key_pair_2.1.key),
                parameters.params,
            ),
            _marker: Default::default(),
        }
    }

    pub(crate) fn for_same_parameters(
        key_pair_1: (&GenericShortIntClientKey<P>, &GenericShortIntServerKey<P>),
        key_pair_2: (&GenericShortIntClientKey<P>, &GenericShortIntServerKey<P>),
    ) -> Option<Self> {
        if key_pair_1.0.key.parameters != key_pair_2.0.key.parameters {
            return None;
        }
        let ksk_params = ShortintKeySwitchingParameters::new(
            key_pair_2.0.key.parameters.ks_base_log(),
            key_pair_2.0.key.parameters.ks_level(),
        );
        Some(Self {
            key: KeySwitchingKey::new(
                (&key_pair_1.0.key, &key_pair_1.1.key),
                (&key_pair_2.0.key, &key_pair_2.1.key),
                ksk_params,
            ),
            _marker: Default::default(),
        })
    }
}
