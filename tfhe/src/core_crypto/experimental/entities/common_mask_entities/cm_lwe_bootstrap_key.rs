//! Module containing the definition of the CmLweBootstrapKey.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::entities::*;
use crate::core_crypto::experimental::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CmLweBootstrapKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    // An CmLweBootstrapKey is literally a CmGgswCiphertextList, so we wrap a
    // CmGgswCiphertextList and use Deref to have access to all the primitives of the
    // CmGgswCiphertextList easily
    ggsw_list: CmGgswCiphertextList<C>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> std::ops::Deref
    for CmLweBootstrapKey<C>
{
    type Target = CmGgswCiphertextList<C>;

    fn deref(&self) -> &CmGgswCiphertextList<C> {
        &self.ggsw_list
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> std::ops::DerefMut
    for CmLweBootstrapKey<C>
{
    fn deref_mut(&mut self) -> &mut CmGgswCiphertextList<C> {
        &mut self.ggsw_list
    }
}

pub fn cm_lwe_bootstrap_key_size(
    input_lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    cm_ggsw_ciphertext_list_size(
        GgswCiphertextCount(input_lwe_dimension.0),
        glwe_dimension,
        cm_dimension,
        polynomial_size,
        decomp_level_count,
    )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmLweBootstrapKey<C> {
    pub fn from_container(
        container: C,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        Self {
            ggsw_list: CmGgswCiphertextList::from_container(
                container,
                glwe_dimension,
                cm_dimension,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                ciphertext_modulus,
            ),
        }
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.cm_ggsw_ciphertext_count().0)
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.glwe_dimension()
            .to_equivalent_lwe_dimension(self.polynomial_size())
    }

    pub fn into_container(self) -> C {
        self.ggsw_list.into_container()
    }

    pub fn as_view(&self) -> CmLweBootstrapKey<&'_ [Scalar]> {
        CmLweBootstrapKey::from_container(
            self.as_ref(),
            self.glwe_dimension(),
            self.cm_dimension(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmLweBootstrapKey<C> {
    pub fn as_mut_view(&mut self) -> CmLweBootstrapKey<&'_ mut [Scalar]> {
        let glwe_dimension = self.glwe_dimension();
        let cm_dimension = self.cm_dimension();
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        let decomp_level_count = self.decomposition_level_count();
        let ciphertext_modulus = self.ciphertext_modulus();
        CmLweBootstrapKey::from_container(
            self.as_mut(),
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        )
    }
}

pub type CmLweBootstrapKeyOwned<Scalar> = CmLweBootstrapKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> CmLweBootstrapKeyOwned<Scalar> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fill_with: Scalar,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self {
            ggsw_list: CmGgswCiphertextList::new(
                fill_with,
                glwe_dimension,
                cm_dimension,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                GgswCiphertextCount(input_lwe_dimension.0),
                ciphertext_modulus,
            ),
        }
    }
}
