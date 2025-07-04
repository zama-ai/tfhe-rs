use crate::core_crypto::prelude::{LweCiphertextConformanceParams, MsDecompressionType};
use crate::shortint::backward_compatibility::parameters::ClassicPBSParametersVersions;
use crate::shortint::parameters::{
    AtomicPatternKind, CarryModulus, CiphertextConformanceParams, CiphertextModulus,
    DecompositionBaseLog, DecompositionLevelCount, Degree, DynamicDistribution,
    EncryptionKeyChoice, GlweDimension, LweDimension, MaxNoiseLevel, MessageModulus,
    ModulusSwitchType, NoiseLevel, PBSOrder, PolynomialSize,
};

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// A structure defining the set of cryptographic parameters for homomorphic integer circuit
/// evaluation.
///
/// The choice of encryption key for (`shortint
/// ciphertext`)[`crate::shortint::ciphertext::Ciphertext`].
///
/// * The `Big` choice means the big LWE key derived from the GLWE key is used to encrypt the input
///   ciphertext. This offers better performance but the (`public
///   key`)[`crate::shortint::public_key::PublicKey`] can be extremely large and in some cases may
///   not fit in memory. When refreshing a ciphertext and/or evaluating a table lookup the keyswitch
///   is computed first followed by a PBS, the keyswitch goes from the large key to the small key
///   and the PBS goes from the small key to the large key.
/// * The `Small` choice means the small LWE key is used to encrypt the input ciphertext.
///   Performance is not as good as in the `Big` case but (`public
///   key`)[`crate::shortint::public_key::PublicKey`] sizes are much more manageable and should
///   always fit in memory. When refreshing a ciphertext and/or evaluating a table lookup the PBS is
///   computed first followed by a keyswitch, the PBS goes from the small key to the large key and
///   the keyswitch goes from the large key to the small key.
#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq, Versionize)]
#[versionize(ClassicPBSParametersVersions)]
pub struct ClassicPBSParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<u64>,
    pub glwe_noise_distribution: DynamicDistribution<u64>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub max_noise_level: MaxNoiseLevel,
    pub log2_p_fail: f64,
    pub ciphertext_modulus: CiphertextModulus,
    pub encryption_key_choice: EncryptionKeyChoice,
    pub modulus_switch_noise_reduction_params: ModulusSwitchType,
}

impl ClassicPBSParameters {
    /// Constructs a new set of parameters for integer circuit evaluation.
    ///
    /// # Warning
    ///
    /// Failing to fix the parameters properly would yield incorrect and insecure computation.
    /// Unless you are a cryptographer who really knows the impact of each of those parameters, you
    /// __must__ stick with the provided parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        lwe_noise_distribution: DynamicDistribution<u64>,
        glwe_noise_distribution: DynamicDistribution<u64>,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        max_noise_level: MaxNoiseLevel,
        log2_p_fail: f64,
        ciphertext_modulus: CiphertextModulus,
        encryption_key_choice: EncryptionKeyChoice,
        modulus_switch_noise_reduction_params: ModulusSwitchType,
    ) -> Self {
        Self {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            message_modulus,
            carry_modulus,
            max_noise_level,
            log2_p_fail,
            ciphertext_modulus,
            encryption_key_choice,
            modulus_switch_noise_reduction_params,
        }
    }

    pub fn to_shortint_conformance_param(&self) -> CiphertextConformanceParams {
        let (atomic_pattern, expected_dim) = match self.encryption_key_choice {
            EncryptionKeyChoice::Big => (
                AtomicPatternKind::Standard(PBSOrder::KeyswitchBootstrap),
                self.glwe_dimension
                    .to_equivalent_lwe_dimension(self.polynomial_size),
            ),
            EncryptionKeyChoice::Small => (
                AtomicPatternKind::Standard(PBSOrder::BootstrapKeyswitch),
                self.lwe_dimension,
            ),
        };

        let message_modulus = self.message_modulus;
        let ciphertext_modulus = self.ciphertext_modulus;
        let carry_modulus = self.carry_modulus;

        let degree = Degree::new(message_modulus.0 - 1);

        let noise_level = NoiseLevel::NOMINAL;

        CiphertextConformanceParams {
            ct_params: LweCiphertextConformanceParams {
                lwe_dim: expected_dim,
                ct_modulus: ciphertext_modulus,
                ms_decompression_method: MsDecompressionType::ClassicPbs,
            },
            message_modulus,
            carry_modulus,
            atomic_pattern,
            degree,
            noise_level,
        }
    }
}
