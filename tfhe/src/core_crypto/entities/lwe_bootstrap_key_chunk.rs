//! Module containing the definition of the LweBootstrapKeyChunk.

use tfhe_versionable::Versionize;

use crate::core_crypto::backward_compatibility::entities::lwe_bootstrap_key_chunk::LweBootstrapKeyChunkVersions;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::named::Named;

/// An [`LWE bootstrap key chunk`](`LweBootstrapKeyChunk`).
///
/// It is a chunked version of [`LWE bootstrap key`](`LweBootstrapKey`).
///
/// This is a wrapper type of [`GgswCiphertextList`], [`std::ops::Deref`] and [`std::ops::DerefMut`]
/// are implemented to dereference to the underlying [`GgswCiphertextList`] for ease of use. See
/// [`GgswCiphertextList`] for additional methods.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(LweBootstrapKeyChunkVersions)]
pub struct LweBootstrapKeyChunk<C: Container>
where
    C::Element: UnsignedInteger,
{
    // An LweBootstrapKeyChunk is literally a GgswCiphertextList, so we wrap a GgswCiphertextList
    // and use Deref to have access to all the primitives of the GgswCiphertextList easily
    ggsw_list: GgswCiphertextList<C>,
}

impl<C: Container> Named for LweBootstrapKeyChunk<C>
where
    C::Element: UnsignedInteger,
{
    const NAME: &'static str = "core_crypto::LweBootstrapKeyChunk";
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> std::ops::Deref
    for LweBootstrapKeyChunk<C>
{
    type Target = GgswCiphertextList<C>;

    fn deref(&self) -> &GgswCiphertextList<C> {
        &self.ggsw_list
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> std::ops::DerefMut
    for LweBootstrapKeyChunk<C>
{
    fn deref_mut(&mut self) -> &mut GgswCiphertextList<C> {
        &mut self.ggsw_list
    }
}

pub fn lwe_bootstrap_key_chunk_size(
    chunk_size: ChunkSize,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    ggsw_ciphertext_list_size(
        GgswCiphertextCount(chunk_size.0),
        glwe_size,
        polynomial_size,
        decomp_level_count,
    )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweBootstrapKeyChunk<C> {
    /// Create an [`LweBootstrapKeyChunk`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an LWE
    /// bootstrap key chunk you need to use
    /// [`crate::core_crypto::algorithms::generate_chunked_lwe_bootstrap_key`] or its parallel
    /// equivalent [`crate::core_crypto::algorithms::par_generate_chunked_lwe_bootstrap_key`]
    /// using this key as output.
    ///
    /// This docstring exhibits [`LweBootstrapKeyChunk`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweBootstrapKeyChunk creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let chunk_size = ChunkSize(8);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LweBootstrapKeyChunk
    /// let bsk_chunk = LweBootstrapKeyChunk::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     chunk_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// // These methods are "inherited" from GgswCiphertextList and are accessed through the Deref
    /// // trait
    /// assert_eq!(bsk_chunk.glwe_size(), glwe_size);
    /// assert_eq!(bsk_chunk.polynomial_size(), polynomial_size);
    /// assert_eq!(bsk_chunk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(bsk_chunk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(bsk_chunk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // These methods are specific to the LweBootstrapKeyChunk
    /// assert_eq!(bsk_chunk.chunk_size(), chunk_size);
    /// assert_eq!(
    ///     bsk_chunk.output_lwe_dimension(),
    ///     glwe_size
    ///         .to_glwe_dimension()
    ///         .to_equivalent_lwe_dimension(polynomial_size)
    /// );
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = bsk_chunk.into_container();
    ///
    /// // Recreate a key using from_container
    /// let bsk_chunk = LweBootstrapKeyChunk::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(bsk_chunk.glwe_size(), glwe_size);
    /// assert_eq!(bsk_chunk.polynomial_size(), polynomial_size);
    /// assert_eq!(bsk_chunk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(bsk_chunk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(bsk_chunk.chunk_size(), chunk_size);
    /// assert_eq!(bsk_chunk.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     bsk_chunk.output_lwe_dimension(),
    ///     glwe_size
    ///         .to_glwe_dimension()
    ///         .to_equivalent_lwe_dimension(polynomial_size)
    /// );
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        Self {
            ggsw_list: GgswCiphertextList::from_container(
                container,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                ciphertext_modulus,
            ),
        }
    }

    /// Return the [`ChunkSize`] of the input [`LweBootstrapKeyChunk`].
    ///
    /// See [`LweBootstrapKeyChunk::from_container`] for usage.
    pub fn chunk_size(&self) -> ChunkSize {
        ChunkSize(self.ggsw_ciphertext_count().0)
    }

    /// Return the [`LweDimension`] of the equivalent output [`LweSecretKey`].
    ///
    /// See [`LweBootstrapKeyChunk::from_container`] for usage.
    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.glwe_size()
            .to_glwe_dimension()
            .to_equivalent_lwe_dimension(self.polynomial_size())
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweBootstrapKeyChunk::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.ggsw_list.into_container()
    }

    /// Return a view of the [`LweBootstrapKeyChunk`]. This is useful if an algorithm takes a view
    /// by value.
    pub fn as_view(&self) -> LweBootstrapKeyChunk<&'_ [Scalar]> {
        LweBootstrapKeyChunk::from_container(
            self.as_ref(),
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweBootstrapKeyChunk<C> {
    /// Mutable variant of [`LweBootstrapKeyChunk::as_view`].
    pub fn as_mut_view(&mut self) -> LweBootstrapKeyChunk<&'_ mut [Scalar]> {
        let glwe_size = self.glwe_size();
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        let decomp_level_count = self.decomposition_level_count();
        let ciphertext_modulus = self.ciphertext_modulus();
        LweBootstrapKeyChunk::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        )
    }
}

/// An [`LweBootstrapKeyChunk`] owning the memory for its own storage.
pub type LweBootstrapKeyChunkOwned<Scalar> = LweBootstrapKeyChunk<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> LweBootstrapKeyChunkOwned<Scalar> {
    /// Allocate memory and create a new owned [`LweBootstrapKeyChunk`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an LWE bootstrap key chunk you need to use
    /// [`crate::core_crypto::algorithms::generate_chunked_lwe_bootstrap_key`] or its parallel
    /// equivalent [`crate::core_crypto::algorithms::par_generate_chunked_lwe_bootstrap_key`] using
    /// this key as output.
    ///
    /// See [`LweBootstrapKeyChunk::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        chunk_size: ChunkSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self {
            ggsw_list: GgswCiphertextList::new(
                fill_with,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                GgswCiphertextCount(chunk_size.0),
                ciphertext_modulus,
            ),
        }
    }
}
