use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::commons::parameters::*;

#[derive(VersionsDispatch)]
pub enum PlaintextCountVersions {
    V0(PlaintextCount),
}

#[derive(VersionsDispatch)]
pub enum CleartextCountVersions {
    V0(CleartextCount),
}

#[derive(VersionsDispatch)]
pub enum CiphertextCountVersions {
    V0(CiphertextCount),
}

#[derive(VersionsDispatch)]
pub enum LweCiphertextCountVersions {
    V0(LweCiphertextCount),
}

#[derive(VersionsDispatch)]
#[cfg(feature = "gpu")]
pub enum LweCiphertextIndexVersions {
    V0(LweCiphertextIndex),
}

#[derive(VersionsDispatch)]
pub enum GlweCiphertextCountVersions {
    V0(GlweCiphertextCount),
}

#[derive(VersionsDispatch)]
pub enum GswCiphertextCountVersions {
    V0(GswCiphertextCount),
}

#[derive(VersionsDispatch)]
pub enum GgswCiphertextCountVersions {
    V0(GgswCiphertextCount),
}

#[derive(VersionsDispatch)]
pub enum LweSizeVersions {
    V0(LweSize),
}

#[derive(VersionsDispatch)]
pub enum LweDimensionVersions {
    V0(LweDimension),
}

#[derive(VersionsDispatch)]
pub enum LwePublicKeyZeroEncryptionCountVersions {
    V0(LwePublicKeyZeroEncryptionCount),
}

#[derive(VersionsDispatch)]
pub enum LweMaskCountVersions {
    V0(LweMaskCount),
}

#[derive(VersionsDispatch)]
pub enum LweBodyCountVersions {
    V0(LweBodyCount),
}

#[derive(VersionsDispatch)]
pub enum GlweSizeVersions {
    V0(GlweSize),
}

#[derive(VersionsDispatch)]
pub enum GlweDimensionVersions {
    V0(GlweDimension),
}

#[derive(VersionsDispatch)]
pub enum PolynomialSizeVersions {
    V0(PolynomialSize),
}

#[derive(VersionsDispatch)]
pub enum FourierPolynomialSizeVersions {
    V0(FourierPolynomialSize),
}

#[derive(VersionsDispatch)]
pub enum PolynomialSizeLogVersions {
    V0(PolynomialSizeLog),
}

#[derive(VersionsDispatch)]
pub enum PolynomialCountVersions {
    V0(PolynomialCount),
}

#[derive(VersionsDispatch)]
pub enum MonomialDegreeVersions {
    V0(MonomialDegree),
}

#[derive(VersionsDispatch)]
pub enum DecompositionBaseLogVersions {
    V0(DecompositionBaseLog),
}

#[derive(VersionsDispatch)]
pub enum DecompositionLevelCountVersions {
    V0(DecompositionLevelCount),
}

#[derive(VersionsDispatch)]
pub enum LutCountLogVersions {
    V0(LutCountLog),
}

#[derive(VersionsDispatch)]
pub enum ModulusSwitchOffsetVersions {
    V0(ModulusSwitchOffset),
}

#[derive(VersionsDispatch)]
pub enum DeltaLogVersions {
    V0(DeltaLog),
}

#[derive(VersionsDispatch)]
pub enum ExtractedBitsCountVersions {
    V0(ExtractedBitsCount),
}

#[derive(VersionsDispatch)]
pub enum FunctionalPackingKeyswitchKeyCountVersions {
    V0(FunctionalPackingKeyswitchKeyCount),
}

#[derive(VersionsDispatch)]
pub enum CiphertextModulusLogVersions {
    V0(CiphertextModulusLog),
}

#[derive(VersionsDispatch)]
pub enum MessageModulusLogVersions {
    V0(MessageModulusLog),
}

#[derive(VersionsDispatch)]
pub enum ThreadCountVersions {
    V0(ThreadCount),
}

#[derive(VersionsDispatch)]
pub enum LweBskGroupingFactorVersions {
    V0(LweBskGroupingFactor),
}

#[derive(VersionsDispatch)]
pub enum GgswPerLweMultiBitBskElementVersions {
    V0(GgswPerLweMultiBitBskElement),
}

#[derive(VersionsDispatch)]
pub enum EncryptionKeyChoiceVersions {
    V0(EncryptionKeyChoice),
}

#[derive(VersionsDispatch)]
pub enum PBSOrderVersions {
    V0(PBSOrder),
}
