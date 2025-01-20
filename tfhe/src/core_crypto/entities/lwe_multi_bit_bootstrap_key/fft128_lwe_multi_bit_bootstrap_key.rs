use crate::core_crypto::backward_compatibility::entities::lwe_multi_bit_bootstrap_key::Fourier128MultiBitLweBootstrapKeyVersions;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
};
use crate::core_crypto::commons::traits::Container;

use tfhe_versionable::Versionize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(Fourier128MultiBitLweBootstrapKeyVersions)]
pub struct Fourier128MultiBitLweBootstrapKey<C: Container<Element = f64>> {
    data_re0: C,
    data_re1: C,
    data_im0: C,
    data_im1: C,
    polynomial_size: PolynomialSize,
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}
