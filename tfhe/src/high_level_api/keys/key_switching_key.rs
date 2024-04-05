use crate::high_level_api::integers::{FheIntId, FheUintId};
use crate::integer::BooleanBlock;
use crate::prelude::FheKeyswitch;
pub use crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters;
use crate::{ClientKey, FheBool, FheInt, FheUint, ServerKey};
use std::fmt::{Display, Formatter};

#[derive(Copy, Clone, Debug)]
pub struct IncompatibleParameters;

impl Display for IncompatibleParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for IncompatibleParameters {}

pub struct KeySwitchingKey {
    key: crate::integer::key_switching_key::KeySwitchingKey,
}

impl KeySwitchingKey {
    pub fn new(
        key_pair_from: (&ClientKey, &ServerKey),
        key_pair_to: (&ClientKey, &ServerKey),
    ) -> Result<Self, IncompatibleParameters> {
        let params_from = key_pair_from.0.key.block_parameters();
        let params_to = key_pair_to.0.key.block_parameters();

        if params_to != params_from {
            return Err(IncompatibleParameters);
        }

        let params = ShortintKeySwitchingParameters {
            ks_base_log: key_pair_to.0.key.block_parameters().ks_base_log(),
            ks_level: key_pair_to.0.key.block_parameters().ks_level(),
        };

        Ok(Self::with_parameters(key_pair_from, key_pair_to, params))
    }

    pub fn with_parameters(
        key_pair_from: (&ClientKey, &ServerKey),
        key_pair_to: (&ClientKey, &ServerKey),
        params: ShortintKeySwitchingParameters,
    ) -> Self {
        Self {
            key: crate::integer::key_switching_key::KeySwitchingKey::new(
                (&key_pair_from.0.key.key, &key_pair_from.1.key.key),
                (&key_pair_to.0.key.key, &key_pair_to.1.key.key),
                params,
            ),
        }
    }
}

impl<Id> FheKeyswitch<FheUint<Id>> for KeySwitchingKey
where
    Id: FheUintId,
{
    fn keyswitch(&self, input: &FheUint<Id>) -> FheUint<Id> {
        let radix = input.ciphertext.on_cpu();
        let casted = self.key.cast(&*radix);
        FheUint::new(casted)
    }
}

impl<Id> FheKeyswitch<FheInt<Id>> for KeySwitchingKey
where
    Id: FheIntId,
{
    fn keyswitch(&self, input: &FheInt<Id>) -> FheInt<Id> {
        let radix = input.ciphertext.on_cpu();
        let casted = self.key.cast(&*radix);
        FheInt::new(casted)
    }
}

impl FheKeyswitch<FheBool> for KeySwitchingKey {
    fn keyswitch(&self, input: &FheBool) -> FheBool {
        let boolean_block = input.ciphertext.on_cpu();
        let casted = self.key.key.cast(boolean_block.as_ref());
        FheBool::new(BooleanBlock::new_unchecked(casted))
    }
}
