#![allow(clippy::excessive_precision)]
//! Module with the definition of cryptographic parameters.
//!
//! This module provides the structure containing the cryptographic parameters required for the
//! homomorphic evaluation of integer circuits as well as a list of secure cryptographic parameter
//! sets.

pub use crate::core_crypto::commons::dispersion::{DispersionParameter, StandardDev};
pub use crate::core_crypto::commons::parameters::{
    CiphertextModulus as CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    GlweDimension, LweBskGroupingFactor, LweDimension, PolynomialSize,
};
use serde::{Deserialize, Serialize};

pub mod key_switching;
pub mod multi_bit;
pub mod parameters_compact_pk;
pub mod parameters_wopbs;
pub mod parameters_wopbs_message_carry;
pub(crate) mod parameters_wopbs_prime_moduli;

pub use crate::core_crypto::commons::parameters::EncryptionKeyChoice;
pub use key_switching::ShortintKeySwitchingParameters;
pub use multi_bit::*;
pub use parameters_compact_pk::*;
pub use parameters_wopbs::WopbsParameters;

/// The number of bits on which the message will be encoded.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct MessageModulus(pub usize);

/// The number of bits on which the carry will be encoded.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct CarryModulus(pub usize);

/// Determines in what ring computations are made
pub type CiphertextModulus = CoreCiphertextModulus<u64>;

/// A structure defining the set of cryptographic parameters for homomorphic integer circuit
/// evaluation.
///
/// The choice of encryption key for (`shortint ciphertext`)[`super::ciphertext::Ciphertext`].
///
/// * The `Big` choice means the big LWE key derived from the GLWE key is used to encrypt the input
///   ciphertext. This offers better performance but the (`public
///   key`)[`super::public_key::PublicKey`] can be extremely large and in some cases may not fit in
///   memory. When refreshing a ciphertext and/or evaluating a table lookup the PBS is computed
///   first followed by a keyswitch.
/// * The `Small` choice means the small LWE key is used to encrypt the input ciphertext.
///   Performance is not as good as in the `Big` case but (`public
///   key`)[`super::public_key::PublicKey`] sizes are much more manageable and shoud always fit in
///   memory. When refreshing a ciphertext and/or evaluating a table lookup the keyswitch is
///   computed first followed by a PBS.
#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq)]
pub struct ClassicPBSParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_modular_std_dev: StandardDev,
    pub glwe_modular_std_dev: StandardDev,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus,
    pub encryption_key_choice: EncryptionKeyChoice,
}

impl ClassicPBSParameters {
    /// Constructs a new set of parameters for integer circuit evaluation.
    ///
    /// # Warning
    ///
    /// Failing to fix the parameters properly would yield incorrect and unsecure computation.
    /// Unless you are a cryptographer who really knows the impact of each of those parameters, you
    /// __must__ stick with the provided parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        lwe_modular_std_dev: StandardDev,
        glwe_modular_std_dev: StandardDev,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        ciphertext_modulus: CiphertextModulus,
        encryption_key_choice: EncryptionKeyChoice,
    ) -> ClassicPBSParameters {
        ClassicPBSParameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_level,
            ks_base_log,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
            encryption_key_choice,
        }
    }
}

#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq)]
pub enum PBSParameters {
    PBS(ClassicPBSParameters),
    MultiBitPBS(MultiBitPBSParameters),
}

impl From<ClassicPBSParameters> for PBSParameters {
    fn from(value: ClassicPBSParameters) -> Self {
        Self::PBS(value)
    }
}

impl From<MultiBitPBSParameters> for PBSParameters {
    fn from(value: MultiBitPBSParameters) -> Self {
        Self::MultiBitPBS(value)
    }
}

impl PBSParameters {
    pub const fn lwe_dimension(&self) -> LweDimension {
        match self {
            PBSParameters::PBS(params) => params.lwe_dimension,
            PBSParameters::MultiBitPBS(params) => params.lwe_dimension,
        }
    }
    pub const fn glwe_dimension(&self) -> GlweDimension {
        match self {
            PBSParameters::PBS(params) => params.glwe_dimension,
            PBSParameters::MultiBitPBS(params) => params.glwe_dimension,
        }
    }
    pub const fn polynomial_size(&self) -> PolynomialSize {
        match self {
            PBSParameters::PBS(params) => params.polynomial_size,
            PBSParameters::MultiBitPBS(params) => params.polynomial_size,
        }
    }
    pub const fn lwe_modular_std_dev(&self) -> StandardDev {
        match self {
            PBSParameters::PBS(params) => params.lwe_modular_std_dev,
            PBSParameters::MultiBitPBS(params) => params.lwe_modular_std_dev,
        }
    }
    pub const fn glwe_modular_std_dev(&self) -> StandardDev {
        match self {
            PBSParameters::PBS(params) => params.glwe_modular_std_dev,
            PBSParameters::MultiBitPBS(params) => params.glwe_modular_std_dev,
        }
    }
    pub const fn pbs_base_log(&self) -> DecompositionBaseLog {
        match self {
            PBSParameters::PBS(params) => params.pbs_base_log,
            PBSParameters::MultiBitPBS(params) => params.pbs_base_log,
        }
    }
    pub const fn pbs_level(&self) -> DecompositionLevelCount {
        match self {
            PBSParameters::PBS(params) => params.pbs_level,
            PBSParameters::MultiBitPBS(params) => params.pbs_level,
        }
    }
    pub const fn ks_base_log(&self) -> DecompositionBaseLog {
        match self {
            PBSParameters::PBS(params) => params.ks_base_log,
            PBSParameters::MultiBitPBS(params) => params.ks_base_log,
        }
    }
    pub const fn ks_level(&self) -> DecompositionLevelCount {
        match self {
            PBSParameters::PBS(params) => params.ks_level,
            PBSParameters::MultiBitPBS(params) => params.ks_level,
        }
    }
    pub const fn message_modulus(&self) -> MessageModulus {
        match self {
            PBSParameters::PBS(params) => params.message_modulus,
            PBSParameters::MultiBitPBS(params) => params.message_modulus,
        }
    }
    pub const fn carry_modulus(&self) -> CarryModulus {
        match self {
            PBSParameters::PBS(params) => params.carry_modulus,
            PBSParameters::MultiBitPBS(params) => params.carry_modulus,
        }
    }
    pub const fn ciphertext_modulus(&self) -> CiphertextModulus {
        match self {
            PBSParameters::PBS(params) => params.ciphertext_modulus,
            PBSParameters::MultiBitPBS(params) => params.ciphertext_modulus,
        }
    }
    pub const fn encryption_key_choice(&self) -> EncryptionKeyChoice {
        match self {
            PBSParameters::PBS(params) => params.encryption_key_choice,
            PBSParameters::MultiBitPBS(params) => params.encryption_key_choice,
        }
    }
    pub const fn grouping_factor(&self) -> LweBskGroupingFactor {
        match self {
            PBSParameters::PBS(_) => {
                panic!("PBSParameters::PBS does not have an LweBskGroupingFactor")
            }
            PBSParameters::MultiBitPBS(params) => params.grouping_factor,
        }
    }

    pub const fn is_pbs(&self) -> bool {
        matches!(self, Self::PBS(_))
    }

    pub const fn is_multi_bit_pbs(&self) -> bool {
        matches!(self, Self::MultiBitPBS(_))
    }
}

#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq)]
enum ShortintParameterSetInner {
    PBSOnly(PBSParameters),
    WopbsOnly(WopbsParameters),
    PBSAndWopbs(PBSParameters, WopbsParameters),
}

impl ShortintParameterSetInner {
    pub const fn is_pbs_only(&self) -> bool {
        matches!(self, Self::PBSOnly(_))
    }

    pub const fn is_wopbs_only(&self) -> bool {
        matches!(self, Self::WopbsOnly(_))
    }

    pub const fn is_pbs_and_wopbs(&self) -> bool {
        matches!(self, Self::PBSAndWopbs(_, _))
    }
}

#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq)]
pub struct ShortintParameterSet {
    inner: ShortintParameterSetInner,
}

impl ShortintParameterSet {
    pub const fn new_pbs_param_set(params: PBSParameters) -> Self {
        Self {
            inner: ShortintParameterSetInner::PBSOnly(params),
        }
    }

    pub const fn new_wopbs_param_set(params: WopbsParameters) -> Self {
        Self {
            inner: ShortintParameterSetInner::WopbsOnly(params),
        }
    }

    pub fn try_new_pbs_and_wopbs_param_set<P>(
        (pbs_params, wopbs_params): (P, WopbsParameters),
    ) -> Result<Self, &'static str>
    where
        P: Into<PBSParameters>,
    {
        let pbs_params: PBSParameters = pbs_params.into();

        if pbs_params.carry_modulus() != wopbs_params.carry_modulus
            || pbs_params.message_modulus() != wopbs_params.message_modulus
            || pbs_params.ciphertext_modulus() != wopbs_params.ciphertext_modulus
            || pbs_params.encryption_key_choice() != wopbs_params.encryption_key_choice
        {
            return Err(
                "Incompatible ClassicPBSParameters and WopbsParameters, this may be due to mismatched \
                carry moduli, message moduli, ciphertext moduli or encryption key choices",
            );
        }
        Ok(Self {
            inner: ShortintParameterSetInner::PBSAndWopbs(pbs_params, wopbs_params),
        })
    }

    pub const fn pbs_parameters(&self) -> Option<PBSParameters> {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => Some(params),
            ShortintParameterSetInner::WopbsOnly(_) => None,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => Some(params),
        }
    }

    pub const fn wopbs_parameters(&self) -> Option<WopbsParameters> {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(_) => None,
            ShortintParameterSetInner::WopbsOnly(params) => Some(params),
            ShortintParameterSetInner::PBSAndWopbs(_, params) => Some(params),
        }
    }

    pub const fn lwe_dimension(&self) -> LweDimension {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.lwe_dimension(),
            ShortintParameterSetInner::WopbsOnly(params) => params.lwe_dimension,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.lwe_dimension(),
        }
    }

    pub const fn glwe_dimension(&self) -> GlweDimension {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.glwe_dimension(),
            ShortintParameterSetInner::WopbsOnly(params) => params.glwe_dimension,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.glwe_dimension(),
        }
    }

    pub const fn polynomial_size(&self) -> PolynomialSize {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.polynomial_size(),
            ShortintParameterSetInner::WopbsOnly(params) => params.polynomial_size,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.polynomial_size(),
        }
    }

    pub const fn lwe_modular_std_dev(&self) -> StandardDev {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.lwe_modular_std_dev(),
            ShortintParameterSetInner::WopbsOnly(params) => params.lwe_modular_std_dev,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.lwe_modular_std_dev(),
        }
    }

    pub const fn glwe_modular_std_dev(&self) -> StandardDev {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.glwe_modular_std_dev(),
            ShortintParameterSetInner::WopbsOnly(params) => params.glwe_modular_std_dev,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.glwe_modular_std_dev(),
        }
    }

    pub const fn pbs_base_log(&self) -> DecompositionBaseLog {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.pbs_base_log(),
            ShortintParameterSetInner::WopbsOnly(params) => params.pbs_base_log,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.pbs_base_log(),
        }
    }

    pub const fn pbs_level(&self) -> DecompositionLevelCount {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.pbs_level(),
            ShortintParameterSetInner::WopbsOnly(params) => params.pbs_level,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.pbs_level(),
        }
    }

    pub const fn ks_base_log(&self) -> DecompositionBaseLog {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.ks_base_log(),
            ShortintParameterSetInner::WopbsOnly(params) => params.ks_base_log,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.ks_base_log(),
        }
    }

    pub const fn ks_level(&self) -> DecompositionLevelCount {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.ks_level(),
            ShortintParameterSetInner::WopbsOnly(params) => params.ks_level,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.ks_level(),
        }
    }

    pub const fn message_modulus(&self) -> MessageModulus {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.message_modulus(),
            ShortintParameterSetInner::WopbsOnly(params) => params.message_modulus,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.message_modulus(),
        }
    }

    pub const fn carry_modulus(&self) -> CarryModulus {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.carry_modulus(),
            ShortintParameterSetInner::WopbsOnly(params) => params.carry_modulus,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.carry_modulus(),
        }
    }

    pub const fn ciphertext_modulus(&self) -> CiphertextModulus {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.ciphertext_modulus(),
            ShortintParameterSetInner::WopbsOnly(params) => params.ciphertext_modulus,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.ciphertext_modulus(),
        }
    }

    pub const fn encryption_key_choice(&self) -> EncryptionKeyChoice {
        match self.inner {
            ShortintParameterSetInner::PBSOnly(params) => params.encryption_key_choice(),
            ShortintParameterSetInner::WopbsOnly(params) => params.encryption_key_choice,
            ShortintParameterSetInner::PBSAndWopbs(params, _) => params.encryption_key_choice(),
        }
    }

    pub const fn pbs_only(&self) -> bool {
        self.inner.is_pbs_only()
    }

    pub const fn wopbs_only(&self) -> bool {
        self.inner.is_wopbs_only()
    }

    pub const fn pbs_and_wopbs(&self) -> bool {
        self.inner.is_pbs_and_wopbs()
    }
}

impl<P> From<P> for ShortintParameterSet
where
    P: Into<PBSParameters>,
{
    fn from(value: P) -> Self {
        Self::new_pbs_param_set(value.into())
    }
}

impl From<WopbsParameters> for ShortintParameterSet {
    fn from(value: WopbsParameters) -> Self {
        Self::new_wopbs_param_set(value)
    }
}

impl<P> TryFrom<(P, WopbsParameters)> for ShortintParameterSet
where
    P: Into<PBSParameters>,
{
    type Error = &'static str;

    fn try_from(value: (P, WopbsParameters)) -> Result<Self, Self::Error> {
        ShortintParameterSet::try_new_pbs_and_wopbs_param_set(value)
    }
}

/// Vector containing all [`ClassicPBSParameters`] parameter sets
pub const ALL_PARAMETER_VEC: [ClassicPBSParameters; 28] = WITH_CARRY_PARAMETERS_VEC;

/// Vector containing all parameter sets where the carry space is strictly greater than one
pub const WITH_CARRY_PARAMETERS_VEC: [ClassicPBSParameters; 28] = [
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_1_CARRY_2_KS_PBS,
    PARAM_MESSAGE_1_CARRY_3_KS_PBS,
    PARAM_MESSAGE_1_CARRY_4_KS_PBS,
    PARAM_MESSAGE_1_CARRY_5_KS_PBS,
    PARAM_MESSAGE_1_CARRY_6_KS_PBS,
    PARAM_MESSAGE_1_CARRY_7_KS_PBS,
    PARAM_MESSAGE_2_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    PARAM_MESSAGE_2_CARRY_4_KS_PBS,
    PARAM_MESSAGE_2_CARRY_5_KS_PBS,
    PARAM_MESSAGE_2_CARRY_6_KS_PBS,
    PARAM_MESSAGE_3_CARRY_1_KS_PBS,
    PARAM_MESSAGE_3_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_3_CARRY_4_KS_PBS,
    PARAM_MESSAGE_3_CARRY_5_KS_PBS,
    PARAM_MESSAGE_4_CARRY_1_KS_PBS,
    PARAM_MESSAGE_4_CARRY_2_KS_PBS,
    PARAM_MESSAGE_4_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MESSAGE_5_CARRY_1_KS_PBS,
    PARAM_MESSAGE_5_CARRY_2_KS_PBS,
    PARAM_MESSAGE_5_CARRY_3_KS_PBS,
    PARAM_MESSAGE_6_CARRY_1_KS_PBS,
    PARAM_MESSAGE_6_CARRY_2_KS_PBS,
    PARAM_MESSAGE_7_CARRY_1_KS_PBS,
];

/// Vector containing all parameter sets where the carry space is strictly greater than one
pub const BIVARIATE_PBS_COMPLIANT_PARAMETER_SET_VEC: [ClassicPBSParameters; 16] = [
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_1_CARRY_2_KS_PBS,
    PARAM_MESSAGE_1_CARRY_3_KS_PBS,
    PARAM_MESSAGE_1_CARRY_4_KS_PBS,
    PARAM_MESSAGE_1_CARRY_5_KS_PBS,
    PARAM_MESSAGE_1_CARRY_6_KS_PBS,
    PARAM_MESSAGE_1_CARRY_7_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    PARAM_MESSAGE_2_CARRY_4_KS_PBS,
    PARAM_MESSAGE_2_CARRY_5_KS_PBS,
    PARAM_MESSAGE_2_CARRY_6_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_3_CARRY_4_KS_PBS,
    PARAM_MESSAGE_3_CARRY_5_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
];

/// Nomenclature: PARAM_MESSAGE_X_CARRY_Y: the message (respectively carry) modulus is
/// encoded over X (reps. Y) bits, i.e., message_modulus = 2^{X} (resp. carry_modulus = 2^{Y}).
/// All parameter sets guarantee 128-bits of security and an error probability smaller than
/// 2^{-40} for a PBS.
pub const PARAM_MESSAGE_1_CARRY_0_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(678),
    glwe_dimension: GlweDimension(5),
    polynomial_size: PolynomialSize(256),
    lwe_modular_std_dev: StandardDev(0.000022810107419132102),
    glwe_modular_std_dev: StandardDev(0.00000000037411618952047216),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_1_CARRY_1_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(684),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.00002043784477291318),
    glwe_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    pbs_base_log: DecompositionBaseLog(18),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_2_CARRY_0_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(656),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.000034119201269311964),
    glwe_modular_std_dev: StandardDev(0.00000004053919869756513),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_1_CARRY_2_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_2_CARRY_1_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_3_CARRY_0_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_1_CARRY_3_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(745),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000006692125069956277),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_3_CARRY_1_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_4_CARRY_0_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_1_CARRY_4_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(807),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000021515145918907506),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_2_CARRY_3_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(856),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000008775214009854235),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_3_CARRY_2_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(812),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000019633637461248447),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_4_CARRY_1_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(808),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000021124945159091033),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_5_CARRY_0_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(807),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(0.0000021515145918907506),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_1_CARRY_5_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(864),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.000000757998020150446),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(32),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_2_CARRY_4_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(864),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.000000757998020150446),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_3_CARRY_3_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(864),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.000000757998020150446),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_4_CARRY_2_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(864),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.000000757998020150446),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_5_CARRY_1_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(875),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.0000006197725091905067),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_6_CARRY_0_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(915),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.00000029804653749339636),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_1_CARRY_6_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(930),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000022649232786295453),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(64),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_2_CARRY_5_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(934),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000021050318566634375),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(32),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_3_CARRY_4_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(930),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000022649232786295453),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_4_CARRY_3_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(930),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000022649232786295453),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_5_CARRY_2_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(930),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000022649232786295453),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_6_CARRY_1_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(930),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000022649232786295453),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_7_CARRY_0_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(930),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_modular_std_dev: StandardDev(0.00000022649232786295453),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_1_CARRY_7_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1004),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.00000005845871624688967),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(128),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_2_CARRY_6_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(987),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.00000007979529246348835),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(64),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_3_CARRY_5_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(985),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.00000008277032914509569),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(32),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_4_CARRY_4_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(996),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.00000006767666038309478),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_5_CARRY_3_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1020),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.000000043618425315728666),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_6_CARRY_2_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1018),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.000000045244666805696514),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_7_CARRY_1_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1017),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.0000000460803851108693),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
pub const PARAM_MESSAGE_8_CARRY_0_KS_PBS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1017),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.0000000460803851108693),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(256),
    carry_modulus: CarryModulus(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_MESSAGE_1_CARRY_1_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(783),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.0000033382067621812462),
    glwe_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    pbs_base_log: DecompositionBaseLog(18),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_MESSAGE_2_CARRY_2_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(870),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.0000006791658447437413),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_MESSAGE_3_CARRY_3_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1025),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_modular_std_dev: StandardDev(0.00000003980397588319241),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_MESSAGE_4_CARRY_4_PBS_KS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1214),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_modular_std_dev: StandardDev(0.0000000012520482863081104),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(4),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

/// Return a parameter set from a message and carry moduli.
///
/// # Example
///
/// ```rust
/// use tfhe::shortint::parameters::{
///     get_parameters_from_message_and_carry, PARAM_MESSAGE_3_CARRY_1_KS_PBS,
/// };
/// let message_space = 7;
/// let carry_space = 2;
/// let param = get_parameters_from_message_and_carry(message_space, carry_space);
/// assert_eq!(param, PARAM_MESSAGE_3_CARRY_1_KS_PBS);
/// ```
pub fn get_parameters_from_message_and_carry(
    msg_space: usize,
    carry_space: usize,
) -> ClassicPBSParameters {
    let mut out = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let mut flag: bool = false;
    let mut rescaled_message_space = f64::ceil(f64::log2(msg_space as f64)) as usize;
    rescaled_message_space = 1 << rescaled_message_space;
    let mut rescaled_carry_space = f64::ceil(f64::log2(carry_space as f64)) as usize;
    rescaled_carry_space = 1 << rescaled_carry_space;

    for param in ALL_PARAMETER_VEC {
        if param.message_modulus.0 == rescaled_message_space
            && param.carry_modulus.0 == rescaled_carry_space
        {
            out = param;
            flag = true;
            break;
        }
    }
    if !flag {
        println!(
            "### WARNING: NO PARAMETERS FOUND for msg_space = {rescaled_message_space} and \
            carry_space = {rescaled_carry_space} ### "
        );
    }
    out
}

// Aliases, to be deprecated in subsequent versions once we e.g. have the "parameter builder"
pub const PARAM_MESSAGE_1_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_2_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_3: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_3_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_4: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_4_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_5: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_5_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_6: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_6_KS_PBS;
pub const PARAM_MESSAGE_1_CARRY_7: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_7_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_3: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_3_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_4: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_4_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_5: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_5_KS_PBS;
pub const PARAM_MESSAGE_2_CARRY_6: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_6_KS_PBS;
pub const PARAM_MESSAGE_3_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_3_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_3_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_2_KS_PBS;
pub const PARAM_MESSAGE_3_CARRY_3: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_3_KS_PBS;
pub const PARAM_MESSAGE_3_CARRY_4: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_4_KS_PBS;
pub const PARAM_MESSAGE_3_CARRY_5: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_5_KS_PBS;
pub const PARAM_MESSAGE_4_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_4_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_4_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_4_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_4_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_4_CARRY_2_KS_PBS;
pub const PARAM_MESSAGE_4_CARRY_3: ClassicPBSParameters = PARAM_MESSAGE_4_CARRY_3_KS_PBS;
pub const PARAM_MESSAGE_4_CARRY_4: ClassicPBSParameters = PARAM_MESSAGE_4_CARRY_4_KS_PBS;
pub const PARAM_MESSAGE_5_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_5_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_5_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_5_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_5_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_5_CARRY_2_KS_PBS;
pub const PARAM_MESSAGE_5_CARRY_3: ClassicPBSParameters = PARAM_MESSAGE_5_CARRY_3_KS_PBS;
pub const PARAM_MESSAGE_6_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_6_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_6_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_6_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_6_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_6_CARRY_2_KS_PBS;
pub const PARAM_MESSAGE_7_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_7_CARRY_0_KS_PBS;
pub const PARAM_MESSAGE_7_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_7_CARRY_1_KS_PBS;
pub const PARAM_MESSAGE_8_CARRY_0: ClassicPBSParameters = PARAM_MESSAGE_8_CARRY_0_KS_PBS;
pub const PARAM_SMALL_MESSAGE_1_CARRY_1: ClassicPBSParameters = PARAM_MESSAGE_1_CARRY_1_PBS_KS;
pub const PARAM_SMALL_MESSAGE_2_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_2_PBS_KS;
pub const PARAM_SMALL_MESSAGE_3_CARRY_3: ClassicPBSParameters = PARAM_MESSAGE_3_CARRY_3_PBS_KS;
pub const PARAM_SMALL_MESSAGE_4_CARRY_4: ClassicPBSParameters = PARAM_MESSAGE_4_CARRY_4_PBS_KS;
