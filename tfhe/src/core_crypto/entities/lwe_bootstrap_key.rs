use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::parameters::*;

// An LweBootstrapKey is literally a GgswCiphertextList, so we wrap a GgswCiphetextList and use
// Deref to have access to all the primitives of the GgswCiphertextList easily
pub struct LweBootstrapKeyBase<C: Container> {
    ggsw_list: GgswCiphertextListBase<C>,
}

impl<C: Container> std::ops::Deref for LweBootstrapKeyBase<C> {
    type Target = GgswCiphertextListBase<C>;

    fn deref(&self) -> &GgswCiphertextListBase<C> {
        self.as_ggsw_ciphertext_list()
    }
}

impl<C: ContainerMut> std::ops::DerefMut for LweBootstrapKeyBase<C> {
    fn deref_mut(&mut self) -> &mut GgswCiphertextListBase<C> {
        self.as_mut_ggsw_ciphertext_list()
    }
}

impl<C: Container> LweBootstrapKeyBase<C> {
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
    ) -> LweBootstrapKeyBase<C> {
        LweBootstrapKeyBase {
            ggsw_list: GgswCiphertextListBase::from_container(
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

    pub fn as_ggsw_ciphertext_list(&self) -> &GgswCiphertextListBase<C> {
        &self.ggsw_list
    }

    pub fn into_container(self) -> C {
        self.ggsw_list.into_container()
    }
}

impl<C: ContainerMut> LweBootstrapKeyBase<C> {
    pub fn as_mut_ggsw_ciphertext_list(&mut self) -> &mut GgswCiphertextListBase<C> {
        &mut self.ggsw_list
    }
}

pub type LweBootstrapKey<Scalar> = LweBootstrapKeyBase<Vec<Scalar>>;

impl<Scalar: Copy> LweBootstrapKey<Scalar> {
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
    ) -> LweBootstrapKey<Scalar> {
        LweBootstrapKey {
            ggsw_list: GgswCiphertextListBase::new(
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

// TODO REFACTOR
// Remove
impl From<LweBootstrapKey<u64>> for crate::core_crypto::prelude::LweBootstrapKey64 {
    fn from(bsk: LweBootstrapKey<u64>) -> Self {
        use crate::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
        use crate::core_crypto::prelude::*;

        let glwe_size = bsk.glwe_size();
        let poly_size = bsk.polynomial_size();
        let decomp_level = bsk.decomposition_level_count();
        let decomp_base_log = bsk.decomposition_base_log();

        LweBootstrapKey64(StandardBootstrapKey::from_container(
            bsk.into_container(),
            glwe_size,
            poly_size,
            decomp_level,
            decomp_base_log,
        ))
    }
}
