use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, GgswCiphertextCount,
    GlweSize, PolynomialSize,
};
use crate::core_crypto::commons::traits::{Container, ContainerMut, Split};
use crate::core_crypto::entities::ggsw_ciphertext::ggsw_ciphertext_size;
pub use crate::core_crypto::entities::ggsw_ciphertext_list::ggsw_ciphertext_list_size;
use crate::core_crypto::entities::ntt_ggsw_ciphertext::NttGgswCiphertext;
use crate::core_crypto::entities::polynomial_list::{
    PolynomialList, PolynomialListMutView, PolynomialListView,
};
use aligned_vec::{avec, ABox};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NttGgswCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    decomposition_level_count: DecompositionLevelCount,
    decomposition_base_log: DecompositionBaseLog,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NttGgswCiphertextList<C> {
    pub fn from_container(
        data: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert!(
            data.container_len()
                % ggsw_ciphertext_size(glwe_size, polynomial_size, decomposition_level_count)
                == 0,
            "The provided container length is not valid. \
            It needs to be dividable by the size of a GGSW ciphertext: {}. \
            Got container length: {}.",
            ggsw_ciphertext_size(glwe_size, polynomial_size, decomposition_level_count),
            data.container_len(),
        );

        Self {
            data,
            polynomial_size,
            glwe_size,
            decomposition_level_count,
            decomposition_base_log,
            ciphertext_modulus,
        }
    }

    pub fn data(self) -> C {
        self.data
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn ggsw_ciphertext_count(&self) -> GgswCiphertextCount {
        GgswCiphertextCount(
            self.data.container_len()
                / ggsw_ciphertext_size(
                    self.glwe_size,
                    self.polynomial_size,
                    self.decomposition_level_count,
                ),
        )
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.ciphertext_modulus
    }

    pub fn as_view(&self) -> NttGgswCiphertextListView<'_, Scalar> {
        NttGgswCiphertextListView {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialList::from_container(self.data.as_ref(), self.polynomial_size())
    }

    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = NttGgswCiphertext<C>>
    where
        C: Split,
    {
        let ggsw_ciphertext_count = self.ggsw_ciphertext_count();
        self.data
            .split_into(ggsw_ciphertext_count.0)
            .map(move |slice| {
                NttGgswCiphertext::from_container(
                    slice,
                    self.glwe_size,
                    self.polynomial_size,
                    self.decomposition_base_log,
                    self.decomposition_level_count,
                )
            })
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NttGgswCiphertextList<C> {
    pub fn as_mut_view(&mut self) -> NttGgswCiphertextListMutView<'_, Scalar> {
        NttGgswCiphertextListMutView {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        PolynomialList::from_container(self.data.as_mut(), self.polynomial_size)
    }
}

pub type NttGgswCiphertextListOwned<Scalar> = NttGgswCiphertextList<ABox<[Scalar]>>;
pub type NttGgswCiphertextListView<'data, Scalar> = NttGgswCiphertextList<&'data [Scalar]>;
pub type NttGgswCiphertextListMutView<'data, Scalar> = NttGgswCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> NttGgswCiphertextListOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        ciphertext_count: GgswCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        let container_size = ggsw_ciphertext_list_size(
            ciphertext_count,
            glwe_size,
            polynomial_size,
            decomposition_level_count,
        );
        Self::from_container(
            avec![fill_with; container_size].into_boxed_slice(),
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
            ciphertext_modulus,
        )
    }
}
