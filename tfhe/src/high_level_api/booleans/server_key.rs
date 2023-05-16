use super::client_key::GenericBoolClientKey;
use super::parameters::BooleanParameterSet;
use super::types::GenericBool;
use crate::boolean::server_key::{BinaryBooleanGates, CompressedServerKey, ServerKey};

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct GenericBoolServerKey<P>
where
    P: BooleanParameterSet,
{
    pub(in crate::high_level_api::booleans) key: ServerKey,
    _marker: std::marker::PhantomData<P>,
}

impl<P> GenericBoolServerKey<P>
where
    P: BooleanParameterSet,
{
    pub(crate) fn new(key: &GenericBoolClientKey<P>) -> Self {
        Self {
            key: ServerKey::new(&key.key),
            _marker: Default::default(),
        }
    }

    pub(in crate::high_level_api::booleans) fn and(
        &self,
        lhs: &GenericBool<P>,
        rhs: &GenericBool<P>,
    ) -> GenericBool<P> {
        let ciphertext = self.key.and(&lhs.ciphertext, &rhs.ciphertext);
        GenericBool::<P>::new(ciphertext, lhs.id)
    }

    pub(in crate::high_level_api::booleans) fn or(
        &self,
        lhs: &GenericBool<P>,
        rhs: &GenericBool<P>,
    ) -> GenericBool<P> {
        let ciphertext = self.key.or(&lhs.ciphertext, &rhs.ciphertext);
        GenericBool::<P>::new(ciphertext, lhs.id)
    }

    pub(in crate::high_level_api::booleans) fn xor(
        &self,
        lhs: &GenericBool<P>,
        rhs: &GenericBool<P>,
    ) -> GenericBool<P> {
        let ciphertext = self.key.xor(&lhs.ciphertext, &rhs.ciphertext);
        GenericBool::<P>::new(ciphertext, lhs.id)
    }

    pub(in crate::high_level_api::booleans) fn xnor(
        &self,
        lhs: &GenericBool<P>,
        rhs: &GenericBool<P>,
    ) -> GenericBool<P> {
        let ciphertext = self.key.xnor(&lhs.ciphertext, &rhs.ciphertext);
        GenericBool::<P>::new(ciphertext, lhs.id)
    }

    pub(in crate::high_level_api::booleans) fn nand(
        &self,
        lhs: &GenericBool<P>,
        rhs: &GenericBool<P>,
    ) -> GenericBool<P> {
        let ciphertext = self.key.nand(&lhs.ciphertext, &rhs.ciphertext);
        GenericBool::<P>::new(ciphertext, lhs.id)
    }

    pub(in crate::high_level_api::booleans) fn not(&self, lhs: &GenericBool<P>) -> GenericBool<P> {
        let ciphertext = self.key.not(&lhs.ciphertext);
        GenericBool::<P>::new(ciphertext, lhs.id)
    }

    #[allow(dead_code)]
    pub(in crate::high_level_api::booleans) fn mux(
        &self,
        condition: &GenericBool<P>,
        then_result: &GenericBool<P>,
        else_result: &GenericBool<P>,
    ) -> GenericBool<P> {
        let ciphertext = self.key.mux(
            &condition.ciphertext,
            &then_result.ciphertext,
            &else_result.ciphertext,
        );
        GenericBool::<P>::new(ciphertext, condition.id)
    }
}

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct GenericBoolCompressedServerKey<P>
where
    P: BooleanParameterSet,
{
    pub(in crate::high_level_api::booleans) key: CompressedServerKey,
    _marker: std::marker::PhantomData<P>,
}

impl<P> GenericBoolCompressedServerKey<P>
where
    P: BooleanParameterSet,
{
    pub(in crate::high_level_api::booleans) fn new(client_key: &GenericBoolClientKey<P>) -> Self {
        Self {
            key: CompressedServerKey::new(&client_key.key),
            _marker: Default::default(),
        }
    }

    pub(in crate::high_level_api::booleans) fn decompress(self) -> GenericBoolServerKey<P> {
        GenericBoolServerKey {
            key: self.key.into(),
            _marker: std::marker::PhantomData,
        }
    }
}
