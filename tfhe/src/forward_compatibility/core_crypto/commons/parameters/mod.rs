use crate::core_crypto::commons::parameters::PlaintextCount;
use next_tfhe::core_crypto::commons::parameters::PlaintextCount as NextPlaintextCount;

impl crate::forward_compatibility::ConvertFrom<PlaintextCount> for NextPlaintextCount {
    #[inline]
    fn convert_from(value: PlaintextCount) -> Self {
        let PlaintextCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::CleartextCount;
use next_tfhe::core_crypto::commons::parameters::CleartextCount as NextCleartextCount;

impl crate::forward_compatibility::ConvertFrom<CleartextCount> for NextCleartextCount {
    #[inline]
    fn convert_from(value: CleartextCount) -> Self {
        let CleartextCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::CiphertextCount;
use next_tfhe::core_crypto::commons::parameters::CiphertextCount as NextCiphertextCount;

impl crate::forward_compatibility::ConvertFrom<CiphertextCount> for NextCiphertextCount {
    #[inline]
    fn convert_from(value: CiphertextCount) -> Self {
        let CiphertextCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::LweCiphertextCount;
use next_tfhe::core_crypto::commons::parameters::LweCiphertextCount as NextLweCiphertextCount;

impl crate::forward_compatibility::ConvertFrom<LweCiphertextCount> for NextLweCiphertextCount {
    #[inline]
    fn convert_from(value: LweCiphertextCount) -> Self {
        let LweCiphertextCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::GlweCiphertextCount;
use next_tfhe::core_crypto::commons::parameters::GlweCiphertextCount as NextGlweCiphertextCount;

impl crate::forward_compatibility::ConvertFrom<GlweCiphertextCount> for NextGlweCiphertextCount {
    #[inline]
    fn convert_from(value: GlweCiphertextCount) -> Self {
        let GlweCiphertextCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::GswCiphertextCount;
use next_tfhe::core_crypto::commons::parameters::GswCiphertextCount as NextGswCiphertextCount;

impl crate::forward_compatibility::ConvertFrom<GswCiphertextCount> for NextGswCiphertextCount {
    #[inline]
    fn convert_from(value: GswCiphertextCount) -> Self {
        let GswCiphertextCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::GgswCiphertextCount;
use next_tfhe::core_crypto::commons::parameters::GgswCiphertextCount as NextGgswCiphertextCount;

impl crate::forward_compatibility::ConvertFrom<GgswCiphertextCount> for NextGgswCiphertextCount {
    #[inline]
    fn convert_from(value: GgswCiphertextCount) -> Self {
        let GgswCiphertextCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::LweSize;
use next_tfhe::core_crypto::commons::parameters::LweSize as NextLweSize;

impl crate::forward_compatibility::ConvertFrom<LweSize> for NextLweSize {
    #[inline]
    fn convert_from(value: LweSize) -> Self {
        let LweSize(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::LweDimension;
use next_tfhe::core_crypto::commons::parameters::LweDimension as NextLweDimension;

impl crate::forward_compatibility::ConvertFrom<LweDimension> for NextLweDimension {
    #[inline]
    fn convert_from(value: LweDimension) -> Self {
        let LweDimension(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::LwePublicKeyZeroEncryptionCount;
use next_tfhe::core_crypto::commons::parameters::LwePublicKeyZeroEncryptionCount as NextLwePublicKeyZeroEncryptionCount;

impl crate::forward_compatibility::ConvertFrom<LwePublicKeyZeroEncryptionCount>
    for NextLwePublicKeyZeroEncryptionCount
{
    #[inline]
    fn convert_from(value: LwePublicKeyZeroEncryptionCount) -> Self {
        let LwePublicKeyZeroEncryptionCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::LweMaskCount;
use next_tfhe::core_crypto::commons::parameters::LweMaskCount as NextLweMaskCount;

impl crate::forward_compatibility::ConvertFrom<LweMaskCount> for NextLweMaskCount {
    #[inline]
    fn convert_from(value: LweMaskCount) -> Self {
        let LweMaskCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::LweBodyCount;
use next_tfhe::core_crypto::commons::parameters::LweBodyCount as NextLweBodyCount;

impl crate::forward_compatibility::ConvertFrom<LweBodyCount> for NextLweBodyCount {
    #[inline]
    fn convert_from(value: LweBodyCount) -> Self {
        let LweBodyCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::GlweSize;
use next_tfhe::core_crypto::commons::parameters::GlweSize as NextGlweSize;

impl crate::forward_compatibility::ConvertFrom<GlweSize> for NextGlweSize {
    #[inline]
    fn convert_from(value: GlweSize) -> Self {
        let GlweSize(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::GlweDimension;
use next_tfhe::core_crypto::commons::parameters::GlweDimension as NextGlweDimension;

impl crate::forward_compatibility::ConvertFrom<GlweDimension> for NextGlweDimension {
    #[inline]
    fn convert_from(value: GlweDimension) -> Self {
        let GlweDimension(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::PolynomialSize;
use next_tfhe::core_crypto::commons::parameters::PolynomialSize as NextPolynomialSize;

impl crate::forward_compatibility::ConvertFrom<PolynomialSize> for NextPolynomialSize {
    #[inline]
    fn convert_from(value: PolynomialSize) -> Self {
        let PolynomialSize(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::FourierPolynomialSize;
use next_tfhe::core_crypto::commons::parameters::FourierPolynomialSize as NextFourierPolynomialSize;

impl crate::forward_compatibility::ConvertFrom<FourierPolynomialSize>
    for NextFourierPolynomialSize
{
    #[inline]
    fn convert_from(value: FourierPolynomialSize) -> Self {
        let FourierPolynomialSize(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::PolynomialSizeLog;
use next_tfhe::core_crypto::commons::parameters::PolynomialSizeLog as NextPolynomialSizeLog;

impl crate::forward_compatibility::ConvertFrom<PolynomialSizeLog> for NextPolynomialSizeLog {
    #[inline]
    fn convert_from(value: PolynomialSizeLog) -> Self {
        let PolynomialSizeLog(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::PolynomialCount;
use next_tfhe::core_crypto::commons::parameters::PolynomialCount as NextPolynomialCount;

impl crate::forward_compatibility::ConvertFrom<PolynomialCount> for NextPolynomialCount {
    #[inline]
    fn convert_from(value: PolynomialCount) -> Self {
        let PolynomialCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::MonomialDegree;
use next_tfhe::core_crypto::commons::parameters::MonomialDegree as NextMonomialDegree;

impl crate::forward_compatibility::ConvertFrom<MonomialDegree> for NextMonomialDegree {
    #[inline]
    fn convert_from(value: MonomialDegree) -> Self {
        let MonomialDegree(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::DecompositionBaseLog;
use next_tfhe::core_crypto::commons::parameters::DecompositionBaseLog as NextDecompositionBaseLog;

impl crate::forward_compatibility::ConvertFrom<DecompositionBaseLog> for NextDecompositionBaseLog {
    #[inline]
    fn convert_from(value: DecompositionBaseLog) -> Self {
        let DecompositionBaseLog(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::DecompositionLevelCount;
use next_tfhe::core_crypto::commons::parameters::DecompositionLevelCount as NextDecompositionLevelCount;

impl crate::forward_compatibility::ConvertFrom<DecompositionLevelCount>
    for NextDecompositionLevelCount
{
    #[inline]
    fn convert_from(value: DecompositionLevelCount) -> Self {
        let DecompositionLevelCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::LutCountLog;
use next_tfhe::core_crypto::commons::parameters::LutCountLog as NextLutCountLog;

impl crate::forward_compatibility::ConvertFrom<LutCountLog> for NextLutCountLog {
    #[inline]
    fn convert_from(value: LutCountLog) -> Self {
        let LutCountLog(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::ModulusSwitchOffset;
use next_tfhe::core_crypto::commons::parameters::ModulusSwitchOffset as NextModulusSwitchOffset;

impl crate::forward_compatibility::ConvertFrom<ModulusSwitchOffset> for NextModulusSwitchOffset {
    #[inline]
    fn convert_from(value: ModulusSwitchOffset) -> Self {
        let ModulusSwitchOffset(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::DeltaLog;
use next_tfhe::core_crypto::commons::parameters::DeltaLog as NextDeltaLog;

impl crate::forward_compatibility::ConvertFrom<DeltaLog> for NextDeltaLog {
    #[inline]
    fn convert_from(value: DeltaLog) -> Self {
        let DeltaLog(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::ExtractedBitsCount;
use next_tfhe::core_crypto::commons::parameters::ExtractedBitsCount as NextExtractedBitsCount;

impl crate::forward_compatibility::ConvertFrom<ExtractedBitsCount> for NextExtractedBitsCount {
    #[inline]
    fn convert_from(value: ExtractedBitsCount) -> Self {
        let ExtractedBitsCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::FunctionalPackingKeyswitchKeyCount;
use next_tfhe::core_crypto::commons::parameters::FunctionalPackingKeyswitchKeyCount as NextFunctionalPackingKeyswitchKeyCount;

impl crate::forward_compatibility::ConvertFrom<FunctionalPackingKeyswitchKeyCount>
    for NextFunctionalPackingKeyswitchKeyCount
{
    #[inline]
    fn convert_from(value: FunctionalPackingKeyswitchKeyCount) -> Self {
        let FunctionalPackingKeyswitchKeyCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use next_tfhe::core_crypto::commons::parameters::CiphertextModulusLog as NextCiphertextModulusLog;

impl crate::forward_compatibility::ConvertFrom<CiphertextModulusLog> for NextCiphertextModulusLog {
    #[inline]
    fn convert_from(value: CiphertextModulusLog) -> Self {
        let CiphertextModulusLog(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::ThreadCount;
use next_tfhe::core_crypto::commons::parameters::ThreadCount as NextThreadCount;

impl crate::forward_compatibility::ConvertFrom<ThreadCount> for NextThreadCount {
    #[inline]
    fn convert_from(value: ThreadCount) -> Self {
        let ThreadCount(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::LweBskGroupingFactor;
use next_tfhe::core_crypto::commons::parameters::LweBskGroupingFactor as NextLweBskGroupingFactor;

impl crate::forward_compatibility::ConvertFrom<LweBskGroupingFactor> for NextLweBskGroupingFactor {
    #[inline]
    fn convert_from(value: LweBskGroupingFactor) -> Self {
        let LweBskGroupingFactor(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::GgswPerLweMultiBitBskElement;
use next_tfhe::core_crypto::commons::parameters::GgswPerLweMultiBitBskElement as NextGgswPerLweMultiBitBskElement;

impl crate::forward_compatibility::ConvertFrom<GgswPerLweMultiBitBskElement>
    for NextGgswPerLweMultiBitBskElement
{
    #[inline]
    fn convert_from(value: GgswPerLweMultiBitBskElement) -> Self {
        let GgswPerLweMultiBitBskElement(field_0) = value;
        Self(field_0)
    }
}

use crate::core_crypto::commons::parameters::EncryptionKeyChoice;
use next_tfhe::core_crypto::commons::parameters::EncryptionKeyChoice as NextEncryptionKeyChoice;

impl crate::forward_compatibility::ConvertFrom<EncryptionKeyChoice> for NextEncryptionKeyChoice {
    #[inline]
    fn convert_from(value: EncryptionKeyChoice) -> Self {
        match value {
            EncryptionKeyChoice::Big => Self::Big,
            EncryptionKeyChoice::Small => Self::Small,
        }
    }
}

use crate::core_crypto::commons::parameters::PBSOrder;
use next_tfhe::core_crypto::commons::parameters::PBSOrder as NextPBSOrder;

impl crate::forward_compatibility::ConvertFrom<PBSOrder> for NextPBSOrder {
    #[inline]
    fn convert_from(value: PBSOrder) -> Self {
        match value {
            PBSOrder::KeyswitchBootstrap => Self::KeyswitchBootstrap,
            PBSOrder::BootstrapKeyswitch => Self::BootstrapKeyswitch,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_plaintext_count() {
        use crate::core_crypto::commons::parameters::PlaintextCount;
        use next_tfhe::core_crypto::commons::parameters::PlaintextCount as NextPlaintextCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = PlaintextCount(rng.gen());
        let _next_tfhe_struct: NextPlaintextCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_cleartext_count() {
        use crate::core_crypto::commons::parameters::CleartextCount;
        use next_tfhe::core_crypto::commons::parameters::CleartextCount as NextCleartextCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = CleartextCount(rng.gen());
        let _next_tfhe_struct: NextCleartextCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_ciphertext_count() {
        use crate::core_crypto::commons::parameters::CiphertextCount;
        use next_tfhe::core_crypto::commons::parameters::CiphertextCount as NextCiphertextCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = CiphertextCount(rng.gen());
        let _next_tfhe_struct: NextCiphertextCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_lwe_ciphertext_count() {
        use crate::core_crypto::commons::parameters::LweCiphertextCount;
        use next_tfhe::core_crypto::commons::parameters::LweCiphertextCount as NextLweCiphertextCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = LweCiphertextCount(rng.gen());
        let _next_tfhe_struct: NextLweCiphertextCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_glwe_ciphertext_count() {
        use crate::core_crypto::commons::parameters::GlweCiphertextCount;
        use next_tfhe::core_crypto::commons::parameters::GlweCiphertextCount as NextGlweCiphertextCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = GlweCiphertextCount(rng.gen());
        let _next_tfhe_struct: NextGlweCiphertextCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_gsw_ciphertext_count() {
        use crate::core_crypto::commons::parameters::GswCiphertextCount;
        use next_tfhe::core_crypto::commons::parameters::GswCiphertextCount as NextGswCiphertextCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = GswCiphertextCount(rng.gen());
        let _next_tfhe_struct: NextGswCiphertextCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_ggsw_ciphertext_count() {
        use crate::core_crypto::commons::parameters::GgswCiphertextCount;
        use next_tfhe::core_crypto::commons::parameters::GgswCiphertextCount as NextGgswCiphertextCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = GgswCiphertextCount(rng.gen());
        let _next_tfhe_struct: NextGgswCiphertextCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_lwe_size() {
        use crate::core_crypto::commons::parameters::LweSize;
        use next_tfhe::core_crypto::commons::parameters::LweSize as NextLweSize;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = LweSize(rng.gen());
        let _next_tfhe_struct: NextLweSize = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_lwe_dimension() {
        use crate::core_crypto::commons::parameters::LweDimension;
        use next_tfhe::core_crypto::commons::parameters::LweDimension as NextLweDimension;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = LweDimension(rng.gen());
        let _next_tfhe_struct: NextLweDimension = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_lwe_public_key_zero_encryption_count() {
        use crate::core_crypto::commons::parameters::LwePublicKeyZeroEncryptionCount;
        use next_tfhe::core_crypto::commons::parameters::LwePublicKeyZeroEncryptionCount as NextLwePublicKeyZeroEncryptionCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = LwePublicKeyZeroEncryptionCount(rng.gen());
        let _next_tfhe_struct: NextLwePublicKeyZeroEncryptionCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_lwe_mask_count() {
        use crate::core_crypto::commons::parameters::LweMaskCount;
        use next_tfhe::core_crypto::commons::parameters::LweMaskCount as NextLweMaskCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = LweMaskCount(rng.gen());
        let _next_tfhe_struct: NextLweMaskCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_lwe_body_count() {
        use crate::core_crypto::commons::parameters::LweBodyCount;
        use next_tfhe::core_crypto::commons::parameters::LweBodyCount as NextLweBodyCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = LweBodyCount(rng.gen());
        let _next_tfhe_struct: NextLweBodyCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_glwe_size() {
        use crate::core_crypto::commons::parameters::GlweSize;
        use next_tfhe::core_crypto::commons::parameters::GlweSize as NextGlweSize;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = GlweSize(rng.gen());
        let _next_tfhe_struct: NextGlweSize = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_glwe_dimension() {
        use crate::core_crypto::commons::parameters::GlweDimension;
        use next_tfhe::core_crypto::commons::parameters::GlweDimension as NextGlweDimension;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = GlweDimension(rng.gen());
        let _next_tfhe_struct: NextGlweDimension = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_polynomial_size() {
        use crate::core_crypto::commons::parameters::PolynomialSize;
        use next_tfhe::core_crypto::commons::parameters::PolynomialSize as NextPolynomialSize;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = PolynomialSize(rng.gen());
        let _next_tfhe_struct: NextPolynomialSize = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_fourier_polynomial_size() {
        use crate::core_crypto::commons::parameters::FourierPolynomialSize;
        use next_tfhe::core_crypto::commons::parameters::FourierPolynomialSize as NextFourierPolynomialSize;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = FourierPolynomialSize(rng.gen());
        let _next_tfhe_struct: NextFourierPolynomialSize = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_polynomial_size_log() {
        use crate::core_crypto::commons::parameters::PolynomialSizeLog;
        use next_tfhe::core_crypto::commons::parameters::PolynomialSizeLog as NextPolynomialSizeLog;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = PolynomialSizeLog(rng.gen());
        let _next_tfhe_struct: NextPolynomialSizeLog = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_polynomial_count() {
        use crate::core_crypto::commons::parameters::PolynomialCount;
        use next_tfhe::core_crypto::commons::parameters::PolynomialCount as NextPolynomialCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = PolynomialCount(rng.gen());
        let _next_tfhe_struct: NextPolynomialCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_monomial_degree() {
        use crate::core_crypto::commons::parameters::MonomialDegree;
        use next_tfhe::core_crypto::commons::parameters::MonomialDegree as NextMonomialDegree;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = MonomialDegree(rng.gen());
        let _next_tfhe_struct: NextMonomialDegree = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_decomposition_base_log() {
        use crate::core_crypto::commons::parameters::DecompositionBaseLog;
        use next_tfhe::core_crypto::commons::parameters::DecompositionBaseLog as NextDecompositionBaseLog;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = DecompositionBaseLog(rng.gen());
        let _next_tfhe_struct: NextDecompositionBaseLog = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_decomposition_level_count() {
        use crate::core_crypto::commons::parameters::DecompositionLevelCount;
        use next_tfhe::core_crypto::commons::parameters::DecompositionLevelCount as NextDecompositionLevelCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = DecompositionLevelCount(rng.gen());
        let _next_tfhe_struct: NextDecompositionLevelCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_lut_count_log() {
        use crate::core_crypto::commons::parameters::LutCountLog;
        use next_tfhe::core_crypto::commons::parameters::LutCountLog as NextLutCountLog;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = LutCountLog(rng.gen());
        let _next_tfhe_struct: NextLutCountLog = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_modulus_switch_offset() {
        use crate::core_crypto::commons::parameters::ModulusSwitchOffset;
        use next_tfhe::core_crypto::commons::parameters::ModulusSwitchOffset as NextModulusSwitchOffset;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = ModulusSwitchOffset(rng.gen());
        let _next_tfhe_struct: NextModulusSwitchOffset = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_delta_log() {
        use crate::core_crypto::commons::parameters::DeltaLog;
        use next_tfhe::core_crypto::commons::parameters::DeltaLog as NextDeltaLog;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = DeltaLog(rng.gen());
        let _next_tfhe_struct: NextDeltaLog = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_extracted_bits_count() {
        use crate::core_crypto::commons::parameters::ExtractedBitsCount;
        use next_tfhe::core_crypto::commons::parameters::ExtractedBitsCount as NextExtractedBitsCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = ExtractedBitsCount(rng.gen());
        let _next_tfhe_struct: NextExtractedBitsCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_functional_packing_keyswitch_key_count() {
        use crate::core_crypto::commons::parameters::FunctionalPackingKeyswitchKeyCount;
        use next_tfhe::core_crypto::commons::parameters::FunctionalPackingKeyswitchKeyCount as NextFunctionalPackingKeyswitchKeyCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = FunctionalPackingKeyswitchKeyCount(rng.gen());
        let _next_tfhe_struct: NextFunctionalPackingKeyswitchKeyCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_ciphertext_modulus_log() {
        use crate::core_crypto::commons::parameters::CiphertextModulusLog;
        use next_tfhe::core_crypto::commons::parameters::CiphertextModulusLog as NextCiphertextModulusLog;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = CiphertextModulusLog(rng.gen());
        let _next_tfhe_struct: NextCiphertextModulusLog = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_thread_count() {
        use crate::core_crypto::commons::parameters::ThreadCount;
        use next_tfhe::core_crypto::commons::parameters::ThreadCount as NextThreadCount;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = ThreadCount(rng.gen());
        let _next_tfhe_struct: NextThreadCount = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_lwe_bsk_grouping_factor() {
        use crate::core_crypto::commons::parameters::LweBskGroupingFactor;
        use next_tfhe::core_crypto::commons::parameters::LweBskGroupingFactor as NextLweBskGroupingFactor;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = LweBskGroupingFactor(rng.gen());
        let _next_tfhe_struct: NextLweBskGroupingFactor = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_ggsw_per_lwe_multi_bit_bsk_element() {
        use crate::core_crypto::commons::parameters::GgswPerLweMultiBitBskElement;
        use next_tfhe::core_crypto::commons::parameters::GgswPerLweMultiBitBskElement as NextGgswPerLweMultiBitBskElement;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = GgswPerLweMultiBitBskElement(rng.gen());
        let _next_tfhe_struct: NextGgswPerLweMultiBitBskElement = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_encryption_key_choice() {
        use crate::core_crypto::commons::parameters::EncryptionKeyChoice;
        use next_tfhe::core_crypto::commons::parameters::EncryptionKeyChoice as NextEncryptionKeyChoice;

        let enum_val_big = EncryptionKeyChoice::Big;
        let enum_val_small = EncryptionKeyChoice::Small;

        let next_enum_val_big: NextEncryptionKeyChoice = enum_val_big.convert_into();
        let next_enum_val_small: NextEncryptionKeyChoice = enum_val_small.convert_into();

        assert_eq!(next_enum_val_big, NextEncryptionKeyChoice::Big);
        assert_eq!(next_enum_val_small, NextEncryptionKeyChoice::Small);
    }

    #[test]
    fn test_conversion_pbs_order() {
        use crate::core_crypto::commons::parameters::PBSOrder;
        use next_tfhe::core_crypto::commons::parameters::PBSOrder as NextPBSOrder;

        let enum_val_pbs_ks = PBSOrder::BootstrapKeyswitch;
        let enum_val_ks_pbs = PBSOrder::KeyswitchBootstrap;

        let next_enum_val_pbs_ks: NextPBSOrder = enum_val_pbs_ks.convert_into();
        let next_enum_val_ls_pbs: NextPBSOrder = enum_val_ks_pbs.convert_into();

        assert_eq!(next_enum_val_pbs_ks, NextPBSOrder::BootstrapKeyswitch);
        assert_eq!(next_enum_val_ls_pbs, NextPBSOrder::KeyswitchBootstrap);
    }
}
