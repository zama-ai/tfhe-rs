//! Module containing the definition of the GlweCiphertext.

use crate::conformance::ParameterSetConformant;
use tfhe_versionable::Versionize;

use crate::core_crypto::backward_compatibility::entities::glwe_ciphertext::GlweCiphertextVersions;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::misc::check_encrypted_content_respects_mod;

/// A convenience structure to easily manipulate the body of a [`GlweCiphertext`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlweBody<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> GlweBody<C> {
    /// Create a [`GlweBody`] from an existing container.
    ///
    /// # Note
    ///
    /// This docstring exhibits [`GlweBody`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GlweBody creation
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// let glwe_body = GlweBody::from_container(vec![0u64; polynomial_size.0], ciphertext_modulus);
    ///
    /// assert_eq!(glwe_body.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe_body.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(container: C, ciphertext_modulus: CiphertextModulus<C::Element>) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a GlweBody"
        );
        Self {
            data: container,
            ciphertext_modulus,
        }
    }

    /// Return the [`PolynomialSize`] of the [`GlweBody`].
    ///
    /// See [`GlweBody::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        PolynomialSize(self.data.container_len())
    }

    /// Return the [`CiphertextModulus`] of the [`GlweBody`].
    ///
    /// See [`GlweBody::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Interpret the [`GlweBody`] as a [`Polynomial`].
    pub fn as_polynomial(&self) -> PolynomialView<'_, C::Element> {
        PolynomialView::from_container(self.as_ref())
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> GlweBody<C> {
    /// Mutable variant of [`GlweBody::as_polynomial`].
    pub fn as_mut_polynomial(&mut self) -> PolynomialMutView<'_, C::Element> {
        PolynomialMutView::from_container(self.as_mut())
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for GlweBody<C> {
    type Metadata = GlweCiphertextCreationMetadata<C::Element>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let GlweCiphertextCreationMetadata {
            polynomial_size: _,
            ciphertext_modulus,
        } = meta;
        Self::from_container(from, ciphertext_modulus)
    }
}

/// A convenience structure to easily manipulate the mask of a [`GlweCiphertext`].
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct GlweMask<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> GlweMask<C> {
    /// Create a [`GlweMask`] from an existing container.
    ///
    /// # Note
    ///
    /// This docstring exhibits [`GlweMask`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GlweMask creation
    /// let glwe_dimension = GlweDimension(1);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// let glwe_mask = GlweMask::from_container(
    ///     vec![
    ///         0u64;
    ///         glwe_dimension
    ///             .to_equivalent_lwe_dimension(polynomial_size)
    ///             .0
    ///     ],
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(glwe_mask.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe_mask.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe_mask.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size. \
        Got container length: {} and polynomial_size: {polynomial_size:?}.",
            container.container_len()
        );
        Self {
            data: container,
            polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`GlweDimension`] of the [`GlweMask`].
    ///
    /// See [`GlweMask::from_container`] for usage.
    pub fn glwe_dimension(&self) -> GlweDimension {
        GlweDimension(self.data.container_len() / self.polynomial_size.0)
    }

    /// Return the [`PolynomialSize`] of the [`GlweMask`].
    ///
    /// See [`GlweMask::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`CiphertextModulus`] of the [`GlweMask`].
    ///
    /// See [`GlweMask::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Interpret the [`GlweMask`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, C::Element> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> GlweMask<C> {
    /// Mutable variant of [`GlweMask::as_polynomial_list`].
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, C::Element> {
        let polynomial_size = self.polynomial_size;
        PolynomialListMutView::from_container(self.as_mut(), polynomial_size)
    }
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for GlweMask<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for GlweMask<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for GlweBody<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for GlweBody<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in a [`GlweCiphertext`] given a [`GlweSize`] and
/// [`PolynomialSize`].
pub fn glwe_ciphertext_size(glwe_size: GlweSize, polynomial_size: PolynomialSize) -> usize {
    glwe_size.0 * polynomial_size.0
}

/// Return the number of elements in a [`GlweMask`] given a [`GlweDimension`] and
/// [`PolynomialSize`].
pub fn glwe_ciphertext_mask_size(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
) -> usize {
    glwe_dimension
        .to_equivalent_lwe_dimension(polynomial_size)
        .0
}

/// Return the number of mask samples used during encryption of a [`GlweCiphertext`] given a
/// [`GlweDimension`] and [`PolynomialSize`].
pub fn glwe_ciphertext_encryption_mask_sample_count(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
) -> EncryptionMaskSampleCount {
    EncryptionMaskSampleCount(glwe_ciphertext_mask_size(glwe_dimension, polynomial_size))
}

/// Return the number of noise samples required to encrypt a [`GlweCiphertext`] given a
/// [`PolynomialSize`].
pub fn glwe_ciphertext_encryption_noise_sample_count(
    polynomial_size: PolynomialSize,
) -> EncryptionNoiseSampleCount {
    EncryptionNoiseSampleCount(polynomial_size.0)
}

/// A [`GLWE ciphertext`](`GlweCiphertext`).
///
/// **Remark:** GLWE ciphertexts generalize LWE ciphertexts by definition, however in this library,
/// GLWE ciphertext entities do not generalize LWE ciphertexts, i.e., polynomial size cannot be 1.
///
/// # Formal Definition
///
/// ## GLWE Ciphertext
///
/// A GLWE ciphertext is an encryption of a polynomial plaintext.
/// It is secure under the hardness assumption called General Learning With Errors (GLWE). It is a
/// generalization of both [`LWE ciphertexts`](`crate::core_crypto::entities::LweCiphertext`) and
/// RLWE ciphertexts. GLWE requires a cyclotomic ring. We use the notation $\mathcal{R}\_q$ for the
/// following cyclotomic ring: $\mathbb{Z}\_q\[X\]/\left\langle X^N + 1\right\rangle$ where
/// $N\in\mathbb{N}$ is a power of two.
///
/// We call $q$ the ciphertext modulus and $N$ the ring dimension.
///
/// We indicate a GLWE ciphertext of a plaintext $\mathsf{PT} \in\mathcal{R}\_q^{k+1}$ as the
/// following couple: $$\mathsf{CT} = \left( \vec{A}, B\right) = \left( A\_0, \ldots, A\_{k-1},
/// B\right) \in \mathsf{GLWE}\_{\vec{S}} \left( \mathsf{PT} \right) \subseteq
/// \mathcal{R}\_q^{k+1}$$
///
/// ## Generalisation of LWE and RLWE
///
/// When we set $k=1$ a GLWE ciphertext becomes an RLWE ciphertext.
/// When we set $N=1$ a GLWE ciphertext becomes an LWE ciphertext with $n=k$.
///
/// ## GLWE Encryption
/// ###### inputs:
/// - $\mathsf{PT}\in\mathcal{R}\_q$: a plaintext
/// - $\vec{S} \in\mathcal{R}\_q^k$: a secret key
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and mean $\mu$
///
/// ###### outputs:
/// - $\mathsf{CT} = \left( \vec{A} , B \right) \in \mathsf{GLWE}\_{\vec{S}}( \mathsf{PT} )\subseteq
///   \mathcal{R}\_q^{k+1}$: an GLWE ciphertext
///
/// ###### algorithm:
/// 1. uniformly sample each coefficient of the polynomial vector $\vec{A}\in\mathcal{R}^k\_q$
/// 2. sample each integer error coefficient of an error polynomial $E\in\mathcal{R}\_q$ from
///    $\mathcal{D\_{\sigma^2,\mu}}$ 3. compute $B = \left\langle \vec{A} , \vec{S} \right\rangle +
///    \mathsf{PT} + E \in\mathcal{R}\_q$ 4. output $\left( \vec{A} , B \right)$
///
/// ## GLWE Decryption
/// ###### inputs:
/// - $\mathsf{CT} = \left( \vec{A} , B \right) \in \mathsf{GLWE}\_{\vec{S}}( \mathsf{PT} )\subseteq
///   \mathcal{R}\_q^{k+1}$: an GLWE ciphertext
/// - $\vec{S} \in\mathcal{R}\_q^k$: a secret key
///
/// ###### outputs:
/// - $\mathsf{PT}\in\mathcal{R}\_q$: a plaintext
///
/// ###### algorithm:
///
/// 1. compute $\mathsf{PT} = B - \left\langle \vec{A} , \vec{S} \right\rangle \in\mathcal{R}\_q$
/// 2. output $\mathsf{PT}$
///
/// **Remark:** Observe that the decryption is followed by a decoding phase that will contain a
/// rounding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(GlweCiphertextVersions)]
pub struct GlweCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for GlweCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for GlweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> GlweCiphertext<C> {
    /// Create a [`GlweCiphertext`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext`] using this
    /// ciphertext as output.
    ///
    /// This docstring exhibits [`GlweCiphertext`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GlweCiphertext creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new GlweCiphertext
    /// let mut glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
    ///
    /// assert_eq!(glwe.glwe_size(), glwe_size);
    /// assert_eq!(glwe.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_body().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_body().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_body().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_mut_body().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     glwe.get_mask().glwe_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(
    ///     glwe.get_mut_mask().glwe_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(glwe.get_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mask().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_mut_mask().ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = glwe.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let mut glwe =
    ///     GlweCiphertext::from_container(underlying_container, polynomial_size, ciphertext_modulus);
    ///
    /// assert_eq!(glwe.glwe_size(), glwe_size);
    /// assert_eq!(glwe.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_body().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_body().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_body().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_mut_body().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     glwe.get_mask().glwe_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(
    ///     glwe.get_mut_mask().glwe_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(glwe.get_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mut_mask().polynomial_size(), polynomial_size);
    /// assert_eq!(glwe.get_mask().ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(glwe.get_mut_mask().ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a GlweCiphertext"
        );
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size. \
        Got container length: {} and polynomial_size: {polynomial_size:?}.",
            container.container_len()
        );
        Self {
            data: container,
            polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`GlweSize`] of the [`GlweCiphertext`].
    ///
    /// See [`GlweCiphertext::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        GlweSize(self.as_ref().container_len() / self.polynomial_size.0)
    }

    /// Return the [`PolynomialSize`] of the [`GlweCiphertext`].
    ///
    /// See [`GlweCiphertext::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`CiphertextModulus`] of the [`GlweCiphertext`].
    ///
    /// See [`GlweCiphertext::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Return immutable views to the [`GlweMask`] and [`GlweBody`] of a [`GlweCiphertext`].
    pub fn get_mask_and_body(&self) -> (GlweMask<&[Scalar]>, GlweBody<&[Scalar]>) {
        let (mask, body) = self.data.as_ref().split_at(glwe_ciphertext_mask_size(
            self.glwe_size().to_glwe_dimension(),
            self.polynomial_size,
        ));

        (
            GlweMask::from_container(mask, self.polynomial_size, self.ciphertext_modulus),
            GlweBody::from_container(body, self.ciphertext_modulus),
        )
    }

    /// Return an immutable view to the [`GlweBody`] of a [`GlweCiphertext`].
    ///
    /// See [`GlweCiphertext::from_container`] for usage.
    pub fn get_body(&self) -> GlweBody<&[Scalar]> {
        let body = &self.data.as_ref()[glwe_ciphertext_mask_size(
            self.glwe_size().to_glwe_dimension(),
            self.polynomial_size,
        )..];

        GlweBody::from_container(body, self.ciphertext_modulus)
    }

    /// Return an immutable view to the [`GlweMask`] of a [`GlweCiphertext`].
    ///
    /// See [`GlweCiphertext::from_container`] for usage.
    pub fn get_mask(&self) -> GlweMask<&[Scalar]> {
        GlweMask::from_container(
            &self.as_ref()[0..glwe_ciphertext_mask_size(
                self.glwe_size().to_glwe_dimension(),
                self.polynomial_size,
            )],
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    /// Interpret the [`GlweCiphertext`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialList<&'_ [Scalar]> {
        PolynomialList::from_container(self.as_ref(), self.polynomial_size)
    }

    /// Return a view of the [`GlweCiphertext`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> GlweCiphertext<&'_ [Scalar]> {
        GlweCiphertext {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`GlweCiphertext::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> GlweCiphertext<C> {
    /// Mutable variant of [`GlweCiphertext::get_mask_and_body`].
    pub fn get_mut_mask_and_body(&mut self) -> (GlweMask<&mut [Scalar]>, GlweBody<&mut [Scalar]>) {
        let glwe_dimension = self.glwe_size().to_glwe_dimension();
        let polynomial_size = self.polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();

        let (mask, body) = self
            .data
            .as_mut()
            .split_at_mut(glwe_ciphertext_mask_size(glwe_dimension, polynomial_size));

        (
            GlweMask::from_container(mask, polynomial_size, ciphertext_modulus),
            GlweBody::from_container(body, ciphertext_modulus),
        )
    }

    /// Mutable variant of [`GlweCiphertext::get_body`].
    ///
    /// See [`GlweCiphertext::from_container`] for usage.
    pub fn get_mut_body(&mut self) -> GlweBody<&mut [Scalar]> {
        let glwe_dimension = self.glwe_size().to_glwe_dimension();
        let polynomial_size = self.polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();

        let body =
            &mut self.data.as_mut()[glwe_ciphertext_mask_size(glwe_dimension, polynomial_size)..];

        GlweBody::from_container(body, ciphertext_modulus)
    }

    /// Mutable variant of [`GlweCiphertext::get_mask`].
    ///
    /// See [`GlweCiphertext::from_container`] for usage.
    pub fn get_mut_mask(&mut self) -> GlweMask<&mut [Scalar]> {
        let polynomial_size = self.polynomial_size();
        let glwe_dimension = self.glwe_size().to_glwe_dimension();
        let ciphertext_modulus = self.ciphertext_modulus();

        GlweMask::from_container(
            &mut self.as_mut()[0..glwe_ciphertext_mask_size(glwe_dimension, polynomial_size)],
            polynomial_size,
            ciphertext_modulus,
        )
    }

    /// Mutable variant of [`GlweCiphertext::as_polynomial_list`].
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialList<&'_ mut [Scalar]> {
        let polynomial_size = self.polynomial_size;
        PolynomialList::from_container(self.as_mut(), polynomial_size)
    }

    /// Mutable variant of [`GlweCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> GlweCiphertext<&'_ mut [Scalar]> {
        GlweCiphertext {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

/// A [`GlweCiphertext`] owning the memory for its own storage.
pub type GlweCiphertextOwned<Scalar> = GlweCiphertext<Vec<Scalar>>;
/// A [`GlweCiphertext`] immutably borrowing memory for its own storage.
pub type GlweCiphertextView<'data, Scalar> = GlweCiphertext<&'data [Scalar]>;
/// A [`GlweCiphertext`] mutably borrowing memory for its own storage.
pub type GlweCiphertextMutView<'data, Scalar> = GlweCiphertext<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> GlweCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`GlweCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext`] using this ciphertext as
    /// output.
    ///
    ///
    /// See [`GlweCiphertext::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; glwe_ciphertext_size(glwe_size, polynomial_size)],
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`GlweCiphertext`] entities.
#[derive(Clone, Copy)]
pub struct GlweCiphertextCreationMetadata<Scalar: UnsignedInteger> {
    pub polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for GlweCiphertext<C> {
    type Metadata = GlweCiphertextCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let GlweCiphertextCreationMetadata {
            polynomial_size,
            ciphertext_modulus,
        } = meta;
        Self::from_container(from, polynomial_size, ciphertext_modulus)
    }
}

/// Structure to store the expected properties of a ciphertext
/// Can be used on a server to check if client inputs are well formed
/// before running a computation on them
#[derive(Copy, Clone)]
pub struct GlweCiphertextConformanceParameters<T: UnsignedInteger> {
    pub glwe_dim: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub ct_modulus: CiphertextModulus<T>,
}

impl<C: Container> ParameterSetConformant for GlweCiphertext<C>
where
    C::Element: UnsignedInteger,
{
    type ParameterSet = GlweCiphertextConformanceParameters<C::Element>;

    fn is_conformant(
        &self,
        glwe_ct_parameters: &GlweCiphertextConformanceParameters<C::Element>,
    ) -> bool {
        let Self {
            data,
            polynomial_size,
            ciphertext_modulus,
        } = self;

        polynomial_size.0.is_power_of_two()
            && check_encrypted_content_respects_mod(self, glwe_ct_parameters.ct_modulus)
            && data.container_len()
                == glwe_ciphertext_size(
                    glwe_ct_parameters.glwe_dim.to_glwe_size(),
                    glwe_ct_parameters.polynomial_size,
                )
            && *polynomial_size == glwe_ct_parameters.polynomial_size
            && *ciphertext_modulus == glwe_ct_parameters.ct_modulus
    }
}
