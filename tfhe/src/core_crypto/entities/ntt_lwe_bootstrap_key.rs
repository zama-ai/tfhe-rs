use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, GgswCiphertextCount,
    GlweSize, LweDimension, PolynomialSize,
};
use crate::core_crypto::commons::traits::{Container, ContainerMut, Split};
pub use crate::core_crypto::entities::ggsw_ciphertext_list::ggsw_ciphertext_list_size;
use crate::core_crypto::entities::ntt_ggsw_ciphertext::NttGgswCiphertext;
use crate::core_crypto::entities::ntt_ggsw_ciphertext_list::NttGgswCiphertextList;
use crate::core_crypto::entities::polynomial_list::{PolynomialListMutView, PolynomialListView};
use aligned_vec::ABox;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NttLweBootstrapKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    ggsw_list: NttGgswCiphertextList<C>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NttLweBootstrapKey<C> {
    pub fn from_container(
        data: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        let ggsw_list = NttGgswCiphertextList::from_container(
            data,
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
            ciphertext_modulus,
        );
        Self { ggsw_list }
    }

    /// Return an iterator over the GGSW ciphertexts composing the key.
    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = NttGgswCiphertext<C>>
    where
        C: Split,
    {
        self.ggsw_list.into_ggsw_iter()
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.ggsw_list.ggsw_ciphertext_count().0)
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.ggsw_list.polynomial_size()
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.ggsw_list.glwe_size()
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.ggsw_list.decomposition_base_log()
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.ggsw_list.decomposition_level_count()
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.glwe_size()
            .to_glwe_dimension()
            .to_equivalent_lwe_dimension(self.polynomial_size())
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.ggsw_list.ciphertext_modulus()
    }

    pub fn data(self) -> C {
        self.ggsw_list.data()
    }

    pub fn as_view(&self) -> NttLweBootstrapKeyView<'_, Scalar> {
        let ggsw_list_view = self.ggsw_list.as_view();
        NttLweBootstrapKeyView {
            ggsw_list: ggsw_list_view,
        }
    }

    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        self.ggsw_list.as_polynomial_list()
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NttLweBootstrapKey<C> {
    pub fn as_mut_view(&mut self) -> NttLweBootstrapKeyMutView<'_, Scalar> {
        let ggsw_list_mut_view = self.ggsw_list.as_mut_view();
        NttLweBootstrapKeyMutView {
            ggsw_list: ggsw_list_mut_view,
        }
    }

    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        self.ggsw_list.as_mut_polynomial_list()
    }
}

pub type NttLweBootstrapKeyOwned<Scalar> = NttLweBootstrapKey<ABox<[Scalar]>>;
pub type NttLweBootstrapKeyView<'data, Scalar> = NttLweBootstrapKey<&'data [Scalar]>;
pub type NttLweBootstrapKeyMutView<'data, Scalar> = NttLweBootstrapKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> NttLweBootstrapKey<ABox<[Scalar]>> {
    pub fn new(
        fill_with: Scalar,
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        let ggsw_list = NttGgswCiphertextList::new(
            fill_with,
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
            GgswCiphertextCount(input_lwe_dimension.0),
            ciphertext_modulus,
        );

        Self { ggsw_list }
    }
}
