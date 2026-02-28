#![allow(clippy::excessive_precision)]
use crate::conformance::ListSizeConstraint;
use crate::integer::key_switching_key::KeySwitchingKeyView;
use crate::integer::server_key::ServerKey;
use crate::shortint::parameters::{
    CarryModulus, CiphertextConformanceParams, CompactCiphertextListExpansionKind,
    CompactPublicKeyEncryptionParameters, MessageModulus,
};
pub use crate::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize, StandardDev,
};
use crate::shortint::PBSParameters;
pub use crate::shortint::{CiphertextModulus, ClassicPBSParameters};

#[derive(Clone, Copy)]
pub enum IntegerCompactCiphertextListExpansionMode<'key> {
    /// The [`KeySwitchingKeyView`] has all the information to both cast and unpack.
    CastAndUnpackIfNecessary(KeySwitchingKeyView<'key>),
    /// This only allows to unpack.
    UnpackAndSanitizeIfNecessary(&'key ServerKey),
    NoCastingAndNoUnpacking,
}

#[derive(Copy, Clone)]
pub struct RadixCiphertextConformanceParams {
    pub shortint_params: CiphertextConformanceParams,
    pub num_blocks_per_integer: usize,
}

/// Structure to store the expected properties of a ciphertext
/// Can be used on a server to check if client inputs are well formed
/// before running a computation on them
impl RadixCiphertextConformanceParams {
    pub fn from_pbs_parameters<P: Into<PBSParameters>>(
        params: P,
        num_blocks_per_integer: usize,
    ) -> Self {
        let params: PBSParameters = params.into();
        Self {
            shortint_params: params.to_shortint_conformance_param(),
            num_blocks_per_integer,
        }
    }
}

/// Structure to store the expected properties of a ciphertext list
/// Can be used on a server to check if client inputs are well formed
/// before running a computation on them
#[derive(Copy, Clone)]
pub struct CompactCiphertextListConformanceParams {
    pub encryption_lwe_dimension: LweDimension,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus,
    pub expansion_kind: CompactCiphertextListExpansionKind,
    pub num_elements_constraint: ListSizeConstraint,
    pub allow_unpacked: bool,
}

impl CompactCiphertextListConformanceParams {
    pub fn from_parameters_and_size_constraint(
        value: CompactPublicKeyEncryptionParameters,
        num_elements_constraint: ListSizeConstraint,
    ) -> Self {
        Self {
            encryption_lwe_dimension: value.encryption_lwe_dimension,
            message_modulus: value.message_modulus,
            carry_modulus: value.carry_modulus,
            ciphertext_modulus: value.ciphertext_modulus,
            expansion_kind: value.expansion_kind,
            num_elements_constraint,
            allow_unpacked: false,
        }
    }

    /// Allow the list to be composed of unpacked ciphertexts.
    ///
    /// Note that this means that the ciphertexts won't be sanitized.
    pub fn allow_unpacked(self) -> Self {
        Self {
            allow_unpacked: true,
            ..self
        }
    }
}
