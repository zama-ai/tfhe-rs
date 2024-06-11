use super::{CiphertextModulus, PBSOrder};
use crate::core_crypto::commons::parameters::{DynamicDistribution, LweDimension};
use crate::shortint::parameters::{CarryModulus, MessageModulus, ShortintParameterSet};
use crate::shortint::KeySwitchingKeyView;
use crate::Error;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompactCiphertextListExpansionKind {
    RequiresCasting,
    NoCasting(PBSOrder),
}

#[derive(Clone, Copy, Debug)]
pub enum CompactCiphertextListCastingMode<K> {
    CastIfNecessary(K),
    NoCasting,
}

pub type ShortintCompactCiphertextListCastingMode<'key> =
    CompactCiphertextListCastingMode<KeySwitchingKeyView<'key>>;

impl From<PBSOrder> for CompactCiphertextListExpansionKind {
    fn from(value: PBSOrder) -> Self {
        Self::NoCasting(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CompactPublicKeyEncryptionParameters {
    pub encryption_lwe_dimension: LweDimension,
    pub encryption_noise_distribution: DynamicDistribution<u64>,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus,
    pub expansion_kind: CompactCiphertextListExpansionKind,
}

impl CompactPublicKeyEncryptionParameters {
    pub fn try_new(
        encryption_lwe_dimension: LweDimension,
        encryption_noise_distribution: DynamicDistribution<u64>,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        ciphertext_modulus: CiphertextModulus,
        output_ciphertext_kind: CompactCiphertextListExpansionKind,
    ) -> Result<Self, Error> {
        let parameters = Self {
            encryption_lwe_dimension,
            encryption_noise_distribution,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
            expansion_kind: output_ciphertext_kind,
        };

        if !parameters.is_valid() {
            return Err(Error::new(format!(
                "Invalid CompactPublicKeyEncryptionParameters, \
                encryption_lwe_dimension ({:?}) is not a power of 2, which is required.",
                parameters.encryption_lwe_dimension
            )));
        }

        Ok(parameters)
    }

    pub const fn is_valid(&self) -> bool {
        self.encryption_lwe_dimension.0.is_power_of_two()
    }

    /// This should be used while defining static parameters to verify they comply with the
    /// requirements of compact public key encryption.
    pub const fn validate(self) -> Self {
        if self.is_valid() {
            return self;
        }

        panic!(
            "Invalid CompactPublicKeyEncryptionParameters, \
            encryption_lwe_dimension is not a power of 2, which is required.",
        );
    }
}

impl TryFrom<ShortintParameterSet> for CompactPublicKeyEncryptionParameters {
    type Error = Error;

    #[track_caller]
    fn try_from(parameters: ShortintParameterSet) -> Result<Self, Self::Error> {
        if parameters.wopbs_only() {
            return Err(Error::new(String::from(
                "Cannot convert Wopbs only parameters to CompactPublicKeyEncryption parameters.",
            )));
        }

        let encryption_lwe_dimension = parameters.encryption_lwe_dimension();
        let encryption_noise_distribution = parameters.encryption_noise_distribution();
        let message_modulus = parameters.message_modulus();
        let carry_modulus = parameters.carry_modulus();
        let ciphertext_modulus = parameters.ciphertext_modulus();
        let output_ciphertext_kind = CompactCiphertextListExpansionKind::NoCasting(
            parameters.encryption_key_choice().into(),
        );

        Self::try_new(
            encryption_lwe_dimension,
            encryption_noise_distribution,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
            output_ciphertext_kind,
        )
    }
}
