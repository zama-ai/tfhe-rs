//! Module containing the definition of the [`CmLweCompressionKeyPart`].

use self::cm_lwe_ciphertext_list::{
    CmLweCiphertextListCreationMetadata, CmLweCiphertextListMutView, CmLweCiphertextListView,
};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CmLweCompressionKeyPart<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_lwe_dimension: LweDimension,
    output_cm_dimension: CmDimension,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmLweCompressionKeyPart<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmLweCompressionKeyPart<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub fn cm_lwe_compression_key_part_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_lwe_dimension: LweDimension,
    output_cm_dimension: CmDimension,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * (output_lwe_dimension.0 + output_cm_dimension.0)
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmLweCompressionKeyPart<C> {
    /// Create an [`CmLweCompressionKeyPart`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`CmLweCompressionKeyPart`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_keyswitch_key`] using this key as output.
    ///
    /// This docstring exhibits [`CmLweCompressionKeyPart`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CmLweCompressionKeyPart creation
    /// let input_lwe_dimension = LweDimension(600);
    /// let output_lwe_dimension = LweDimension(1024);
    /// let output_cm_dimension = CmDimension(2);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new CmLweCompressionKeyPart
    /// let lwe_ksk = CmLweCompressionKeyPart::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
    ///     output_lwe_dimension,
    ///     output_cm_dimension,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_ksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_ksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_ksk.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(lwe_ksk.output_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(lwe_ksk.output_cm_dimension(), output_cm_dimension);
    /// assert_eq!(lwe_ksk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_ksk.into_container();
    ///
    /// // Recreate a secret key using from_container
    /// let lwe_ksk = CmLweCompressionKeyPart::from_container(
    ///     underlying_container,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     output_lwe_dimension,
    ///     output_cm_dimension,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_ksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_ksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_ksk.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(lwe_ksk.output_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(lwe_ksk.output_cm_dimension(), output_cm_dimension);
    /// assert_eq!(lwe_ksk.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_lwe_dimension: LweDimension,
        output_cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an CmLweCompressionKeyPart"
        );
        assert_eq!(
            container.container_len() % (decomp_level_count.0 * (output_lwe_dimension.0 + output_cm_dimension.0)),
            0,
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * (output_lwe_dimension + output_cm_dimension): {}. \
        Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        output_lwe_dimension + output_cm_dimension: {}.",
            decomp_level_count.0 * (output_lwe_dimension.0 + output_cm_dimension.0),
            container.container_len(),
            output_lwe_dimension.0 + output_cm_dimension.0,
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        }
    }

    /// Return the [`DecompositionBaseLog`] of the [`CmLweCompressionKeyPart`].
    ///
    /// See [`CmLweCompressionKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`CmLweCompressionKeyPart`].
    ///
    /// See [`CmLweCompressionKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the input [`LweDimension`] of the [`CmLweCompressionKeyPart`].
    ///
    /// See [`CmLweCompressionKey::from_container`] for usage.
    pub fn input_key_lwe_dimension(&self) -> LweDimension {
        LweDimension(
            self.data.container_len()
                / (self.output_lwe_dimension.0 + self.output_cm_dimension.0)
                / self.decomp_level_count.0,
        )
    }

    /// Return the output [`LweDimension`] of the [`CmLweCompressionKeyPart`].
    ///
    /// See [`CmLweCompressionKey::from_container`] for usage.
    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.output_lwe_dimension
    }

    /// Return the output [`LweDimension`] of the [`CmLweCompressionKeyPart`].
    ///
    /// See [`CmLweCompressionKey::from_container`] for usage.
    pub fn output_cm_dimension(&self) -> CmDimension {
        self.output_cm_dimension
    }

    /// Return the number of elements in an encryption of an input [`LweSecretKey`] element of the
    /// current [`CmLweCompressionKeyPart`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        cm_lwe_compression_key_part_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_lwe_dimension,
            self.output_cm_dimension,
        )
    }

    /// Return a view of the [`CmLweCompressionKeyPart`]. This is useful if an algorithm takes a
    /// view by value.
    pub fn as_view(&self) -> CmLweCompressionKeyPartView<'_, Scalar> {
        CmLweCompressionKeyPart::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.output_lwe_dimension,
            self.output_cm_dimension,
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`CmLweCompressionKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_lwe_ciphertext_list(&self) -> CmLweCiphertextListView<'_, Scalar> {
        CmLweCiphertextListView::from_container(
            self.as_ref(),
            self.output_lwe_dimension(),
            self.output_cm_dimension,
            self.ciphertext_modulus(),
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmLweCompressionKeyPart<C> {
    /// Mutable variant of [`CmLweCompressionKey::as_view`].
    pub fn as_mut_view(&mut self) -> CmLweCompressionKeyPartMutView<'_, Scalar> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_lwe_dimension = self.output_lwe_dimension;
        let output_cm_dimension = self.output_cm_dimension;

        let ciphertext_modulus = self.ciphertext_modulus;
        CmLweCompressionKeyPart::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_csr_lwe_ciphertext_list(&mut self) -> CmLweCiphertextListMutView<'_, Scalar> {
        let output_lwe_dimension = self.output_lwe_dimension();
        let output_cm_dimension = self.output_cm_dimension;
        let ciphertext_modulus = self.ciphertext_modulus();
        CmLweCiphertextListMutView::from_container(
            self.as_mut(),
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        )
    }
}

/// An [`CmLweCompressionKeyPart`] owning the memory for its own storage.
pub type CmLweCompressionKeyPartOwned<Scalar> = CmLweCompressionKeyPart<Vec<Scalar>>;
/// An [`CmLweCompressionKeyPart`] immutably borrowing memory for its own storage.
pub type CmLweCompressionKeyPartView<'data, Scalar> = CmLweCompressionKeyPart<&'data [Scalar]>;
/// An [`CmLweCompressionKeyPart`] mutably borrowing memory for its own storage.
pub type CmLweCompressionKeyPartMutView<'data, Scalar> =
    CmLweCompressionKeyPart<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmLweCompressionKeyPartOwned<Scalar> {
    /// Allocate memory and create a new owned [`CmLweCompressionKeyPart`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`CmLweCompressionKeyPart`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_keyswitch_key`] using this key as output.
    ///
    /// See [`CmLweCompressionKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_lwe_dimension: LweDimension,
        output_key_cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                input_key_lwe_dimension.0
                    * cm_lwe_compression_key_part_input_key_element_encrypted_size(
                        decomp_level_count,
                        output_lwe_dimension,
                        output_key_cm_dimension,
                    )
            ],
            decomp_base_log,
            decomp_level_count,
            output_lwe_dimension,
            output_key_cm_dimension,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct CmLweCompressionKeyPartCreationMetadata<Scalar: UnsignedInteger> {
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub output_lwe_dimension: LweDimension,
    pub output_cm_dimension: CmDimension,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for CmLweCompressionKeyPart<C>
{
    type Metadata = CmLweCompressionKeyPartCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmLweCompressionKeyPartCreationMetadata {
            decomp_base_log,
            decomp_level_count,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            output_lwe_dimension,
            output_cm_dimension,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for CmLweCompressionKeyPart<C>
{
    type Element = C::Element;

    type EntityViewMetadata = CmLweCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this>
        = CmLweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = CmLweCompressionKeyPartCreationMetadata<Self::Element>;

    type SelfView<'this>
        = CmLweCompressionKeyPartView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        CmLweCiphertextListCreationMetadata {
            lwe_dimension: self.output_lwe_dimension(),
            cm_dimension: self.output_cm_dimension,
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        CmLweCompressionKeyPartCreationMetadata {
            decomp_base_log: self.decomposition_base_log(),
            decomp_level_count: self.decomposition_level_count(),
            output_lwe_dimension: self.output_lwe_dimension(),
            output_cm_dimension: self.output_cm_dimension,
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for CmLweCompressionKeyPart<C>
{
    type EntityMutView<'this>
        = CmLweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = CmLweCompressionKeyPartMutView<'this, Self::Element>
    where
        Self: 'this;
}
