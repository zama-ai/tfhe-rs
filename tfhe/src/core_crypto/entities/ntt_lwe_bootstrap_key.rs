use crate::core_crypto::backward_compatibility::entities::ntt_lwe_bootstrap_key::NttLweBootstrapKeyVersions;
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
use tfhe_versionable::Versionize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(NttLweBootstrapKeyVersions)]
pub struct NttLweBootstrapKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    ggsw_list: NttGgswCiphertextList<C>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NttLweBootstrapKey<C> {
    /// Create an [`NttLweBootstrapKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to have useful
    /// data in the [`NttLweBootstrapKey`] you will first need to convert it from a standard
    /// [`LweBootstrapKey`](`crate::core_crypto::entities::LweBootstrapKey`) by calling
    /// [`convert_standard_lwe_bootstrap_key_to_ntt64`](crate::core_crypto::algorithms::convert_standard_lwe_bootstrap_key_to_ntt64).
    ///
    /// This docstring exhibits [`NttLweBootstrapKey`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for NttLweBootstrapKey creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let input_lwe_dimension = LweDimension(600);
    /// let ciphertext_modulus = CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap();
    ///
    /// // Create a new NttLweBootstrapKey
    /// let bsk = NttLweBootstrapKey::new(
    ///     0u64,
    ///     input_lwe_dimension,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(bsk.glwe_size(), glwe_size);
    /// assert_eq!(bsk.polynomial_size(), polynomial_size);
    /// assert_eq!(bsk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(bsk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(bsk.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(bsk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(
    ///     bsk.output_lwe_dimension(),
    ///     glwe_size
    ///         .to_glwe_dimension()
    ///         .to_equivalent_lwe_dimension(polynomial_size)
    /// );
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container = bsk.into_container();
    ///
    /// // Recreate a key using from_container
    /// let bsk = NttLweBootstrapKey::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(bsk.glwe_size(), glwe_size);
    /// assert_eq!(bsk.polynomial_size(), polynomial_size);
    /// assert_eq!(bsk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(bsk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(bsk.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(bsk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(
    ///     bsk.output_lwe_dimension(),
    ///     glwe_size
    ///         .to_glwe_dimension()
    ///         .to_equivalent_lwe_dimension(polynomial_size)
    /// );
    /// ```
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

    /// Return an iterator over the contiguous [`NttGgswCiphertext`]. This consumes the entity,
    /// consider calling [`NttLweBootstrapKey::as_view`] or
    /// [`NttLweBootstrapKey::as_mut_view`] first to have an iterator over borrowed contents
    /// instead of consuming the original entity.
    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = NttGgswCiphertext<C>>
    where
        C: Split,
    {
        self.ggsw_list.into_ggsw_iter()
    }

    /// Return the [`LweDimension`] of the input
    /// [`LweSecretKey`](`crate::core_crypto::entities::LweSecretKey`).
    ///
    /// See [`NttLweBootstrapKey::from_container`] for usage.
    pub fn input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.ggsw_list.ggsw_ciphertext_count().0)
    }

    /// Return the [`PolynomialSize`] of the [`NttLweBootstrapKey`].
    ///
    /// See [`NttLweBootstrapKey::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.ggsw_list.polynomial_size()
    }

    /// Return the [`GlweSize`] of the [`NttLweBootstrapKey`].
    ///
    /// See [`NttLweBootstrapKey::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.ggsw_list.glwe_size()
    }

    /// Return the [`DecompositionBaseLog`] of the [`NttLweBootstrapKey`].
    ///
    /// See [`NttLweBootstrapKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.ggsw_list.decomposition_base_log()
    }

    /// Return the [`DecompositionLevelCount`] of the [`NttLweBootstrapKey`].
    ///
    /// See [`NttLweBootstrapKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.ggsw_list.decomposition_level_count()
    }

    /// Return the [`LweDimension`] of the equivalent output
    /// [`LweSecretKey`](`crate::core_crypto::entities::LweSecretKey`).
    ///
    /// See [`NttLweBootstrapKey::from_container`] for usage.
    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.glwe_size()
            .to_glwe_dimension()
            .to_equivalent_lwe_dimension(self.polynomial_size())
    }

    /// Return the [`CiphertextModulus`] of the [`NttLweBootstrapKey`].
    ///
    /// See [`NttLweBootstrapKey::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.ggsw_list.ciphertext_modulus()
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`NttLweBootstrapKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.ggsw_list.into_container()
    }

    /// Return a view of the [`NttLweBootstrapKey`]. This is useful if an algorithm takes a view
    /// by value.
    pub fn as_view(&self) -> NttLweBootstrapKeyView<'_, Scalar> {
        let ggsw_list_view = self.ggsw_list.as_view();
        NttLweBootstrapKeyView {
            ggsw_list: ggsw_list_view,
        }
    }

    /// Interpret the [`NttLweBootstrapKey`] as a
    /// [`PolynomialList`](`crate::core_crypto::entities::PolynomialList`).
    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        self.ggsw_list.as_polynomial_list()
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NttLweBootstrapKey<C> {
    /// Mutable variant of [`NttLweBootstrapKey::as_view`].
    pub fn as_mut_view(&mut self) -> NttLweBootstrapKeyMutView<'_, Scalar> {
        let ggsw_list_mut_view = self.ggsw_list.as_mut_view();
        NttLweBootstrapKeyMutView {
            ggsw_list: ggsw_list_mut_view,
        }
    }

    /// Mutable variant of [`NttLweBootstrapKey::as_polynomial_list`].
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        self.ggsw_list.as_mut_polynomial_list()
    }
}

pub type NttLweBootstrapKeyOwned<Scalar> = NttLweBootstrapKey<ABox<[Scalar]>>;
pub type NttLweBootstrapKeyView<'data, Scalar> = NttLweBootstrapKey<&'data [Scalar]>;
pub type NttLweBootstrapKeyMutView<'data, Scalar> = NttLweBootstrapKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> NttLweBootstrapKey<ABox<[Scalar]>> {
    /// Allocate memory and create a new owned [`NttLweBootstrapKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to have useful data in the [`NttLweBootstrapKey`] you will first need to
    /// convert it from a standard
    /// [`LweBootstrapKey`](`crate::core_crypto::entities::LweBootstrapKey`) by calling
    /// [`convert_standard_lwe_bootstrap_key_to_ntt64`](crate::core_crypto::algorithms::convert_standard_lwe_bootstrap_key_to_ntt64).
    ///
    ///
    /// See [`NttLweBootstrapKey::from_container`] for usage.
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
