use crate::boolean::parameters::BooleanParameters;
use serde::{Deserialize, Serialize};

use crate::typed_api::booleans::client_key::GenericBoolClientKey;
use crate::typed_api::booleans::parameters::BooleanParameterSet;
pub use crate::typed_api::booleans::parameters::FheBoolParameters;
use crate::typed_api::booleans::public_key::GenericBoolPublicKey;
use crate::typed_api::booleans::server_key::GenericBoolServerKey;
use crate::typed_api::booleans::types::CompressedBool;
use crate::typed_api::errors::Type;

use super::base::GenericBool;

// Has Overridable Operator:
// - and => BitAnd => &
// - not => Not => !
// - or => BitOr => |
// - xor => BitXor => ^
//
// Does Not have overridable operator:
// - mux -> But maybe by using a macro_rules with regular function we can have some sufficiently
//   nice syntax sugar
// - nand
// - nor
// - xnor should be Eq => ==,  But Eq requires to return a bool not a FHE bool So we cant do it
// - ||, && cannot be overloaded, maybe a well-crafted macro-rules that implements `if-else` could
//   bring this syntax sugar

/// The struct to identify the static boolean type
#[derive(Copy, Clone, Default, Serialize, Deserialize)]
pub struct FheBoolId;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StaticBoolParameters(pub(crate) FheBoolParameters);

impl From<StaticBoolParameters> for BooleanParameters {
    fn from(p: StaticBoolParameters) -> Self {
        p.0.into()
    }
}

impl From<FheBoolParameters> for StaticBoolParameters {
    fn from(p: FheBoolParameters) -> Self {
        Self(p)
    }
}

impl BooleanParameterSet for StaticBoolParameters {
    type Id = FheBoolId;
}

pub type FheBool = GenericBool<StaticBoolParameters>;
pub type CompressedFheBool = CompressedBool<StaticBoolParameters>;
pub(in crate::typed_api::booleans) type FheBoolClientKey =
    GenericBoolClientKey<StaticBoolParameters>;
pub(in crate::typed_api::booleans) type FheBoolServerKey =
    GenericBoolServerKey<StaticBoolParameters>;
pub(in crate::typed_api::booleans) type FheBoolPublicKey =
    GenericBoolPublicKey<StaticBoolParameters>;

impl_with_global_key!(
    for FheBoolId {
        key_type: FheBoolServerKey,
        keychain_member: boolean_key.bool_key,
        type_variant: Type::FheBool,
    }
);

impl_ref_key_from_keychain!(
    for FheBoolId {
        key_type: FheBoolClientKey,
        keychain_member: boolean_key.bool_key,
        type_variant: Type::FheBool,
    }
);

impl_ref_key_from_public_keychain!(
    for FheBoolId {
        key_type: FheBoolPublicKey,
        keychain_member: boolean_key.bool_key,
        type_variant: Type::FheBool,
    }
);
