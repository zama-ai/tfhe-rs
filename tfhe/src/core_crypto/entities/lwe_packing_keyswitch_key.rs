//! Module containing the definition of the [`LwePackingKeyswitchKey`].

use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::backward_compatibility::entities::lwe_packing_keyswitch_key::LwePackingKeyswitchKeyVersions;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::glwe_ciphertext::glwe_ciphertext_size;
use crate::core_crypto::entities::glwe_ciphertext_list::{
    GlweCiphertextListCreationMetadata, GlweCiphertextListMutView, GlweCiphertextListView,
};

/// A keyswitching key allowing to keyswitch [`an LWE ciphertext`](super::LweCiphertext) to
/// [`a GLWE ciphertext`](super::GlweCiphertext) allowing to pack several LWE ciphertexts into a
/// GLWE ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(LwePackingKeyswitchKeyVersions)]
pub struct LwePackingKeyswitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for LwePackingKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for LwePackingKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in an encryption of an input [`super::LweSecretKey`] element for a
/// [`LwePackingKeyswitchKey`] given a [`DecompositionLevelCount`] and output [`GlweSize`] and
/// [`PolynomialSize`].
pub fn lwe_packing_keyswitch_key_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * glwe_ciphertext_size(output_glwe_size, output_polynomial_size)
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LwePackingKeyswitchKey<C> {
    /// Create an [`LwePackingKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`LwePackingKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_packing_keyswitch_key`] using this key as
    /// output.
    ///
    /// This docstring exhibits [`LwePackingKeyswitchKey`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LwePackingKeyswitchKey creation
    /// let input_lwe_dimension = LweDimension(600);
    /// let output_glwe_dimension = GlweDimension(1);
    /// let output_polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LwePackingKeyswitchKey
    /// let lwe_pksk = LwePackingKeyswitchKey::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
    ///     output_glwe_dimension,
    ///     output_polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_pksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_pksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_pksk.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(lwe_pksk.output_key_glwe_dimension(), output_glwe_dimension);
    /// assert_eq!(
    ///     lwe_pksk.output_key_polynomial_size(),
    ///     output_polynomial_size
    /// );
    /// assert_eq!(
    ///     lwe_pksk.output_glwe_size(),
    ///     output_glwe_dimension.to_glwe_size()
    /// );
    /// assert_eq!(lwe_pksk.output_polynomial_size(), output_polynomial_size);
    /// assert_eq!(lwe_pksk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_pksk.into_container();
    ///
    /// // Recreate a secret key using from_container
    /// let lwe_pksk = LwePackingKeyswitchKey::from_container(
    ///     underlying_container,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     output_glwe_dimension.to_glwe_size(),
    ///     output_polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_pksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_pksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_pksk.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(lwe_pksk.output_key_glwe_dimension(), output_glwe_dimension);
    /// assert_eq!(
    ///     lwe_pksk.output_key_polynomial_size(),
    ///     output_polynomial_size
    /// );
    /// assert_eq!(
    ///     lwe_pksk.output_glwe_size(),
    ///     output_glwe_dimension.to_glwe_size()
    /// );
    /// assert_eq!(lwe_pksk.output_polynomial_size(), output_polynomial_size);
    /// assert_eq!(lwe_pksk.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LwePackingKeyswitchKey"
        );
        assert!(
            container.container_len()
                % lwe_packing_keyswitch_key_input_key_element_encrypted_size(
                    decomp_level_count,
                    output_glwe_size,
                    output_polynomial_size
                )
                == 0,
            "The provided container length is not valid. \
        It needs to be dividable by: {}. Got container length: {} and decomp_level_count: \
        {decomp_level_count:?}, output_glwe_size: {output_glwe_size:?}, output_polynomial_size: \
        {output_polynomial_size:?}.",
            lwe_packing_keyswitch_key_input_key_element_encrypted_size(
                decomp_level_count,
                output_glwe_size,
                output_polynomial_size
            ),
            container.container_len()
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`DecompositionBaseLog`] of the [`LwePackingKeyswitchKey`].
    ///
    /// See [`LwePackingKeyswitchKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`LwePackingKeyswitchKey`].
    ///
    /// See [`LwePackingKeyswitchKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the input [`LweDimension`] of the [`LwePackingKeyswitchKey`].
    ///
    /// See [`LwePackingKeyswitchKey::from_container`] for usage.
    pub fn input_key_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len() / self.input_key_element_encrypted_size())
    }

    /// Return the output [`GlweDimension`] of the [`LwePackingKeyswitchKey`].
    ///
    /// See [`LwePackingKeyswitchKey::from_container`] for usage.
    pub fn output_key_glwe_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    /// Return the output [`PolynomialSize`] of the [`LwePackingKeyswitchKey`].
    ///
    /// See [`LwePackingKeyswitchKey::from_container`] for usage.
    pub fn output_key_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Return the output [`GlweSize`] of the [`LwePackingKeyswitchKey`].
    ///
    /// See [`LwePackingKeyswitchKey::from_container`] for usage.
    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    /// Return the output [`PolynomialSize`] of the [`LwePackingKeyswitchKey`].
    ///
    /// See [`LwePackingKeyswitchKey::from_container`] for usage.
    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Return the number of elements in an encryption of an input [`super::LweSecretKey`] element
    /// of the current [`LwePackingKeyswitchKey`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        lwe_packing_keyswitch_key_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_glwe_size,
            self.output_polynomial_size,
        )
    }

    /// Return a view of the [`LwePackingKeyswitchKey`]. This is useful if an algorithm takes a view
    /// by value.
    pub fn as_view(&self) -> LwePackingKeyswitchKeyView<'_, Scalar> {
        LwePackingKeyswitchKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.output_glwe_size,
            self.output_polynomial_size,
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LwePackingKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_glwe_ciphertext_list(&self) -> GlweCiphertextListView<'_, Scalar> {
        GlweCiphertextListView::from_container(
            self.as_ref(),
            self.output_glwe_size(),
            self.output_polynomial_size(),
            self.ciphertext_modulus(),
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LwePackingKeyswitchKey<C> {
    /// Mutable variant of [`LwePackingKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> LwePackingKeyswitchKeyMutView<'_, Scalar> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_glwe_size = self.output_glwe_size;
        let output_polynomial_size = self.output_polynomial_size;
        let ciphertext_modulus = self.ciphertext_modulus;
        LwePackingKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_glwe_ciphertext_list(&mut self) -> GlweCiphertextListMutView<'_, Scalar> {
        let output_glwe_size = self.output_glwe_size();
        let output_polynomial_size = self.output_polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();
        GlweCiphertextListMutView::from_container(
            self.as_mut(),
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// An [`LwePackingKeyswitchKey`] owning the memory for its own storage.
pub type LwePackingKeyswitchKeyOwned<Scalar> = LwePackingKeyswitchKey<Vec<Scalar>>;
/// An [`LwePackingKeyswitchKey`] immutably borrowing memory for its own storage.
pub type LwePackingKeyswitchKeyView<'data, Scalar> = LwePackingKeyswitchKey<&'data [Scalar]>;
/// An [`LwePackingKeyswitchKey`] mutably borrowing memory for its own storage.
pub type LwePackingKeyswitchKeyMutView<'data, Scalar> = LwePackingKeyswitchKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> LwePackingKeyswitchKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`LwePackingKeyswitchKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`LwePackingKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_packing_keyswitch_key`] using this key as
    /// output.
    ///
    /// See [`LwePackingKeyswitchKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_key_glwe_dimension: GlweDimension,
        output_key_polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                input_key_lwe_dimension.0
                    * lwe_packing_keyswitch_key_input_key_element_encrypted_size(
                        decomp_level_count,
                        output_key_glwe_dimension.to_glwe_size(),
                        output_key_polynomial_size
                    )
            ],
            decomp_base_log,
            decomp_level_count,
            output_key_glwe_dimension.to_glwe_size(),
            output_key_polynomial_size,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for LwePackingKeyswitchKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = GlweCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this>
        = GlweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfView<'this>
        = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        GlweCiphertextListCreationMetadata {
            glwe_size: self.output_glwe_size(),
            polynomial_size: self.output_polynomial_size(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    /// Unimplemented for [`LwePackingKeyswitchKey`]. At the moment it does not make sense to
    /// return "sub" keyswitch keys.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for LwePackingKeyswitchKey. \
        At the moment it does not make sense to return 'sub' keyswitch keys."
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for LwePackingKeyswitchKey<C>
{
    type EntityMutView<'this>
        = GlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfMutView<'this>
        = DummyCreateFrom
    where
        Self: 'this;
}

pub struct PackingKeyswitchConformanceParams {
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub input_lwe_dimension: LweDimension,
    pub output_glwe_size: GlweSize,
    pub output_polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<u64>,
}

impl<C: Container<Element = u64>> ParameterSetConformant for LwePackingKeyswitchKey<C> {
    type ParameterSet = PackingKeyswitchConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            data,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        } = self;

        data.container_len()
            == lwe_packing_keyswitch_key_input_key_element_encrypted_size(
                *decomp_level_count,
                *output_glwe_size,
                *output_polynomial_size,
            ) * parameter_set.input_lwe_dimension.0
            && *decomp_base_log == parameter_set.decomp_base_log
            && *decomp_level_count == parameter_set.decomp_level_count
            && *output_glwe_size == parameter_set.output_glwe_size
            && *output_polynomial_size == parameter_set.output_polynomial_size
            && *ciphertext_modulus == parameter_set.ciphertext_modulus
    }
}
