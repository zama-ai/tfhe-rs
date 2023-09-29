use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::errors::{UninitializedPublicKey, UnwrapResultExt};
use crate::high_level_api::integers::parameters::IntegerParameter;
use crate::high_level_api::integers::types::base::GenericInteger;
use crate::high_level_api::internal_traits::TypeIdentifier;
use crate::high_level_api::traits::FheTryEncrypt;
use crate::integer::ciphertext::{CiphertextListConformanceParams, CompactCiphertextList};
use crate::shortint::PBSParameters;
use crate::CompactPublicKey;

#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GenericCompactInteger<P: IntegerParameter> {
    pub(in crate::high_level_api::integers) list: CompactCiphertextList,
    pub(in crate::high_level_api::integers) id: P::Id,
}

#[cfg_attr(all(doc, not(doctest)), doc(cfg(feature = "integer")))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct GenericCompactIntegerList<P: IntegerParameter> {
    pub(in crate::high_level_api::integers) list: CompactCiphertextList,
    pub(in crate::high_level_api::integers) id: P::Id,
}

impl<P> GenericCompactInteger<P>
where
    P: IntegerParameter,
{
    pub fn expand(&self) -> GenericInteger<P> {
        let ct = self.list.expand_one();
        GenericInteger::new(ct, self.id)
    }
}

impl<P> GenericCompactIntegerList<P>
where
    P: IntegerParameter,
{
    pub fn len(&self) -> usize {
        self.list.ciphertext_count()
    }

    pub fn expand(&self) -> Vec<GenericInteger<P>> {
        self.list
            .expand()
            .into_iter()
            .map(|ct| GenericInteger::new(ct, self.id))
            .collect::<Vec<_>>()
    }
}

impl<P, T> FheTryEncrypt<T, CompactPublicKey> for GenericCompactInteger<P>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(value: T, key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let ciphertext = key
            .integer_key
            .try_encrypt_compact(&[value], P::num_blocks())
            .ok_or(UninitializedPublicKey(id.type_variant()))
            .unwrap_display();
        Ok(Self {
            list: ciphertext,
            id,
        })
    }
}

impl<'a, P, T> FheTryEncrypt<&'a [T], CompactPublicKey> for GenericCompactIntegerList<P>
where
    T: crate::integer::block_decomposition::DecomposableInto<u64>,
    P: IntegerParameter,
    P::Id: Default + TypeIdentifier,
{
    type Error = crate::high_level_api::errors::Error;

    fn try_encrypt(values: &'a [T], key: &CompactPublicKey) -> Result<Self, Self::Error> {
        let id = P::Id::default();
        let ciphertext = key
            .integer_key
            .try_encrypt_compact(values, P::num_blocks())
            .ok_or(UninitializedPublicKey(id.type_variant()))
            .unwrap_display();
        Ok(Self {
            list: ciphertext,
            id,
        })
    }
}

impl<P: IntegerParameter> ParameterSetConformant for GenericCompactInteger<P> {
    type ParameterSet = PBSParameters;
    fn is_conformant(&self, pbs_parameters: &PBSParameters) -> bool {
        let params = CiphertextListConformanceParams {
            shortint_params: pbs_parameters.to_shortint_conformance_param(),
            num_blocks_per_integer: P::num_blocks(),
            num_integers_constraint: ListSizeConstraint::exact_size(1),
        };
        self.list.is_conformant(&params)
    }
}

impl<P: IntegerParameter> ParameterSetConformant for GenericCompactIntegerList<P> {
    type ParameterSet = (PBSParameters, ListSizeConstraint);
    fn is_conformant(
        &self,
        (pbs_parameters, number_integers_constraint): &(PBSParameters, ListSizeConstraint),
    ) -> bool {
        let params = CiphertextListConformanceParams {
            shortint_params: pbs_parameters.to_shortint_conformance_param(),
            num_blocks_per_integer: P::num_blocks(),
            num_integers_constraint: *number_integers_constraint,
        };
        self.list.is_conformant(&params)
    }
}
