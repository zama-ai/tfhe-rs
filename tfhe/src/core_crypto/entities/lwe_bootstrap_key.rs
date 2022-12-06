use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

// An LweBootstrapKey is literally a GgswCiphertextList, so we wrap a GgswCiphetextList and use
// Deref to have access to all the primitives of the GgswCiphertextList easily
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LweBootstrapKey<C: Container> {
    ggsw_list: GgswCiphertextList<C>,
}

impl<C: Container> std::ops::Deref for LweBootstrapKey<C> {
    type Target = GgswCiphertextList<C>;

    fn deref(&self) -> &GgswCiphertextList<C> {
        &self.ggsw_list
    }
}

impl<C: ContainerMut> std::ops::DerefMut for LweBootstrapKey<C> {
    fn deref_mut(&mut self) -> &mut GgswCiphertextList<C> {
        &mut self.ggsw_list
    }
}

impl<Scalar, C: Container<Element = Scalar>> LweBootstrapKey<C> {
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
    ) -> LweBootstrapKey<C> {
        LweBootstrapKey {
            ggsw_list: GgswCiphertextList::from_container(
                container,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
            ),
        }
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.ggsw_ciphertext_count().0)
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.glwe_size().to_glwe_dimension().0 * self.polynomial_size().0)
    }

    pub fn into_container(self) -> C {
        self.ggsw_list.into_container()
    }

    pub fn as_view(&self) -> LweBootstrapKey<&'_ [Scalar]> {
        LweBootstrapKey::from_container(
            self.as_ref(),
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.decomposition_level_count(),
        )
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LweBootstrapKey<C> {
    pub fn as_mut_view(&mut self) -> LweBootstrapKey<&'_ mut [Scalar]> {
        let glwe_size = self.glwe_size();
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        let decomp_level_count = self.decomposition_level_count();
        LweBootstrapKey::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        )
    }
}

pub type LweBootstrapKeyOwned<Scalar> = LweBootstrapKey<Vec<Scalar>>;

impl<Scalar: Copy> LweBootstrapKeyOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
    ) -> LweBootstrapKeyOwned<Scalar> {
        LweBootstrapKeyOwned {
            ggsw_list: GgswCiphertextList::new(
                fill_with,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                GgswCiphertextCount(input_lwe_dimension.0),
            ),
        }
    }
}
