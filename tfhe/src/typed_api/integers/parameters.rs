use crate::integer::CrtClientKey;
use crate::typed_api::internal_traits::{FromParameters, ParameterType};
use serde::{Deserialize, Serialize};

/// Parameters for 'radix' decomposition
///
/// Radix decomposition works by using multiple shortint blocks
/// with the same parameters to represent an integer.
///
/// For example, by taking 4 blocks with parameters
/// for 2bits shortints, with have a 4 * 2 = 8 bit integer.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct RadixParameters {
    pub block_parameters: crate::shortint::Parameters,
    pub num_block: usize,
    pub pbs_order: crate::shortint::PBSOrder,
    pub wopbs_block_parameters: crate::shortint::Parameters,
}

/// Parameters for 'CRT' decomposition
///
/// (Chinese Remainder Theorem)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrtParameters {
    pub block_parameters: crate::shortint::Parameters,
    pub moduli: Vec<u64>,
    pub wopbs_block_parameters: crate::shortint::Parameters,
}

/// Meant to be implemented on the inner server key
/// eg the crate::integer::ServerKey
pub trait EvaluationIntegerKey<ClientKey> {
    fn new(client_key: &ClientKey) -> Self;

    fn new_wopbs_key(
        client_key: &ClientKey,
        server_key: &Self,
        wopbs_block_parameters: crate::shortint::Parameters,
    ) -> crate::integer::wopbs::WopbsKey;
}

impl<P> FromParameters<P> for crate::integer::CrtClientKey
where
    P: Into<CrtParameters>,
{
    fn from_parameters(parameters: P) -> Self {
        let params = parameters.into();
        #[cfg(feature = "internal-keycache")]
        {
            use crate::integer::keycache::KEY_CACHE;
            let key = KEY_CACHE.get_from_params(params.block_parameters).0;
            crate::integer::CrtClientKey::from((key, params.moduli))
        }
        #[cfg(not(feature = "internal-keycache"))]
        {
            crate::integer::CrtClientKey::new(params.block_parameters, params.moduli)
        }
    }
}

/// Trait to mark parameters type for integers
pub trait IntegerParameter: ParameterType {
    fn wopbs_block_parameters(&self) -> crate::shortint::Parameters;

    fn block_parameters(&self) -> crate::shortint::Parameters;
}

/// Marker struct for the RadixRepresentation
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct RadixRepresentation;
/// Marker struct for the CrtRepresentation
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct CrtRepresentation;

/// Trait to mark parameters type for static integers
///
/// Static means the integer types with parameters provided by
/// the crate, so parameters for which we know the number of
/// bits the represent.
pub trait StaticIntegerParameter: IntegerParameter {
    type Representation: Default + Eq;

    const MESSAGE_BITS: usize;
}

pub trait StaticRadixParameter:
    StaticIntegerParameter<Representation = RadixRepresentation>
where
    Self: IntegerParameter<
        InnerClientKey = crate::typed_api::integers::client_key::RadixClientKey,
        InnerServerKey = crate::integer::ServerKey,
    >,
{
}
pub trait StaticCrtParameter: StaticIntegerParameter<Representation = CrtRepresentation>
where
    Self:
        IntegerParameter<InnerClientKey = CrtClientKey, InnerServerKey = crate::integer::ServerKey>,
{
}
