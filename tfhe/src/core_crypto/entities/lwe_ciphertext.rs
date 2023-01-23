//! Module containing the definition of the [`LweCiphertext`].

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;

/// A convenience structure to easily manipulate the body of an [`LweCiphertext`].
#[derive(Clone, Debug)]
pub struct LweBody<T: UnsignedInteger> {
    pub data: T,
    pub ciphertext_modulus: CiphertextModulus<T>,
}

#[derive(Debug)]
pub struct LweBodyRef<'a, T: UnsignedInteger> {
    pub data: &'a T,
    pub ciphertext_modulus: CiphertextModulus<T>,
}

#[derive(Debug)]
pub struct LweBodyRefMut<'a, T: UnsignedInteger> {
    pub data: &'a mut T,
    pub ciphertext_modulus: CiphertextModulus<T>,
}

#[derive(Clone, Debug)]
pub struct LweMask<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

/// A convenience structure to easily manipulate the mask of an [`LweCiphertext`].
impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweMask<C> {
    /// Create an [`LweMask`] from an existing container.
    ///
    /// # Note
    ///
    /// This docstring exhibits [`LweMask`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweMask creation
    /// let lwe_dimension = LweDimension(600);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// let lwe_mask = LweMask::from_container(vec![0u64; lwe_dimension.0], ciphertext_modulus);
    ///
    /// assert_eq!(lwe_mask.lwe_dimension(), lwe_dimension);
    /// assert_eq!(lwe_mask.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(container: C, ciphertext_modulus: CiphertextModulus<C::Element>) -> Self {
        LweMask {
            data: container,
            ciphertext_modulus,
        }
    }

    /// Return the [`LweDimension`] of the [`LweMask`].
    ///
    /// See [`LweMask::from_container`] for usage.
    pub fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len())
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for LweMask<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for LweMask<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger> LweBody<Scalar> {
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.ciphertext_modulus
    }
}

impl<T: UnsignedInteger> LweBodyRef<'_, T> {
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<T> {
        self.ciphertext_modulus
    }
}

impl<T: UnsignedInteger> LweBodyRefMut<'_, T> {
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<T> {
        self.ciphertext_modulus
    }
}

impl<'data, T: UnsignedInteger> CreateFrom<&'data [T]> for LweBodyRef<'data, T> {
    type Metadata = LweCiphertextCreationMetadata<T>;

    #[inline]
    fn create_from(from: &[T], meta: Self::Metadata) -> LweBodyRef<T> {
        let LweCiphertextCreationMetadata(ciphertext_modulus) = meta;
        LweBodyRef {
            data: &from[0],
            ciphertext_modulus,
        }
    }
}

impl<'data, T: UnsignedInteger> CreateFrom<&'data mut [T]> for LweBodyRefMut<'data, T> {
    type Metadata = LweCiphertextCreationMetadata<T>;

    #[inline]
    fn create_from(from: &mut [T], meta: Self::Metadata) -> LweBodyRefMut<T> {
        let LweCiphertextCreationMetadata(ciphertext_modulus) = meta;
        LweBodyRefMut {
            data: &mut from[0],
            ciphertext_modulus,
        }
    }
}

/// An [`LWE ciphertext`](`LweCiphertext`).
///
/// # Formal Definition
///
/// ## LWE Ciphertext
///
/// An LWE ciphertext is an encryption of a plaintext.
/// It is secure under the hardness assumption called Learning With Errors (LWE).
/// It is a specialization of
/// [`GLWE ciphertext`](`crate::core_crypto::entities::GlweCiphertext`).
///
/// We indicate an LWE ciphertext of a plaintext $\mathsf{pt} \in\mathbb{Z}\_q$ as the following
/// couple: $$\mathsf{ct} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt}
/// )\subseteq \mathbb{Z}\_q^{(n+1)}$$ We call $q$ the ciphertext modulus and $n$ the LWE dimension.
///
/// ## LWE dimension
/// It corresponds to the number of element in the LWE secret key.
/// In an LWE ciphertext, it is the length of the vector $\vec{a}$.
/// At [`encryption`](`crate::core_crypto::algorithms::encrypt_lwe_ciphertext`) time, it is
/// the number of uniformly random integers generated.
///
/// ## LWE Encryption
/// ###### inputs:
/// - $\mathsf{pt}\in\mathbb{Z}\_q$: a plaintext
/// - $\vec{s}\in\mathbb{Z}\_q^n$: a secret key
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and a mean $\mu$
///
/// ###### outputs:
/// - $\mathsf{ct} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt} )\subseteq
///   \mathbb{Z}\_q^{(n+1)}$: an LWE ciphertext
///
/// ###### algorithm:
/// 1. uniformly sample a vector $\vec{a}\in\mathbb{Z}\_q^n$
/// 2. sample an integer error term $e \hookleftarrow \mathcal{D\_{\sigma^2,\mu}}$
/// 3. compute $b = \left\langle \vec{a} , \vec{s} \right\rangle + \mathsf{pt} + e \in\mathbb{Z}\_q$
/// 4. output $\left( \vec{a} , b\right)$
///
/// ## LWE Decryption
/// ###### inputs:
/// - $\mathsf{ct} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt} )\subseteq
///   \mathbb{Z}\_q^{(n+1)}$: an LWE ciphertext
/// - $\vec{s}\in\mathbb{Z}\_q^n$: a secret key
///
/// ###### outputs:
/// - $\mathsf{pt}\in\mathbb{Z}\_q$: a plaintext
///
/// ###### algorithm:
/// 1. compute $\mathsf{pt} = b - \left\langle \vec{a} , \vec{s} \right\rangle \in\mathbb{Z}\_q$
/// 3. output $\mathsf{pt}$
///
/// **Remark:** Observe that the decryption is followed by a decoding phase that will contain a
/// rounding.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LweCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for LweCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for LweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweCiphertext<C> {
    /// Create an [`LweCiphertext`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext`] using this
    /// ciphertext as output.
    ///
    /// This docstring exhibits [`LweCiphertext`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweCiphertext creation
    /// let lwe_size = LweSize(601);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LweCiphertext
    /// let mut lwe = LweCiphertext::new(0u64, lwe_size, ciphertext_modulus);
    ///
    /// assert_eq!(lwe.lwe_size(), lwe_size);
    /// assert_eq!(lwe.get_mask().lwe_dimension(), lwe_size.to_lwe_dimension());
    /// assert_eq!(
    ///     lwe.get_mut_mask().lwe_dimension(),
    ///     lwe_size.to_lwe_dimension()
    /// );
    /// assert_eq!(lwe.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let mut lwe = LweCiphertext::from_container(underlying_container, ciphertext_modulus);
    ///
    /// assert_eq!(lwe.lwe_size(), lwe_size);
    /// assert_eq!(lwe.get_mask().lwe_dimension(), lwe_size.to_lwe_dimension());
    /// assert_eq!(
    ///     lwe.get_mut_mask().lwe_dimension(),
    ///     lwe_size.to_lwe_dimension()
    /// );
    /// assert_eq!(lwe.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> LweCiphertext<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweCiphertext"
        );
        LweCiphertext {
            data: container,
            ciphertext_modulus,
        }
    }

    /// Return the [`LweSize`] of the [`LweCiphertext`].
    ///
    /// See [`LweCiphertext::from_container`] for usage.
    pub fn lwe_size(&self) -> LweSize {
        LweSize(self.data.container_len())
    }

    /// Return immutable views to the [`LweMask`] and [`LweBody`] of an [`LweCiphertext`].
    pub fn get_mask_and_body(&self) -> (LweMask<&[Scalar]>, LweBodyRef<'_, Scalar>) {
        let (body, mask) = self.data.as_ref().split_last().unwrap();
        let ciphertext_modulus = self.ciphertext_modulus();

        (
            LweMask::from_container(mask, ciphertext_modulus),
            LweBodyRef {
                data: body,
                ciphertext_modulus,
            },
        )
    }

    /// Return an immutable view to the [`LweBody`] of an [`LweCiphertext`].
    pub fn get_body(&self) -> LweBodyRef<'_, Scalar> {
        let body = self.data.as_ref().last().unwrap();
        let ciphertext_modulus = self.ciphertext_modulus();

        LweBodyRef {
            data: body,
            ciphertext_modulus,
        }
    }

    /// Return an immutable view to the [`LweMask`] of an [`LweCiphertext`].
    ///
    /// See [`LweCiphertext::from_container`] for usage.
    pub fn get_mask(&self) -> LweMask<&[Scalar]> {
        LweMask::from_container(
            &self.as_ref()[0..self.lwe_size().to_lwe_dimension().0],
            self.ciphertext_modulus(),
        )
    }

    /// Return a view of the [`LweCiphertext`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> LweCiphertextView<'_, Scalar> {
        LweCiphertextView::from_container(self.as_ref(), self.ciphertext_modulus())
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweCiphertext::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweCiphertext<C> {
    /// Mutable variant of [`LweCiphertext::get_mask_and_body`].
    pub fn get_mut_mask_and_body(&mut self) -> (LweMask<&mut [Scalar]>, LweBodyRefMut<'_, Scalar>) {
        let ciphertext_modulus = self.ciphertext_modulus();
        let (body, mask) = self.data.as_mut().split_last_mut().unwrap();

        (
            LweMask::from_container(mask, ciphertext_modulus),
            LweBodyRefMut {
                data: body,
                ciphertext_modulus,
            },
        )
    }

    /// Mutable variant of [`LweCiphertext::get_body`].
    pub fn get_mut_body(&mut self) -> LweBodyRefMut<'_, Scalar> {
        let ciphertext_modulus = self.ciphertext_modulus();
        let body = self.data.as_mut().last_mut().unwrap();

        LweBodyRefMut {
            data: body,
            ciphertext_modulus,
        }
    }

    /// Mutable variant of [`LweCiphertext::get_mask`].
    ///
    /// See [`LweCiphertext::from_container`] for usage.
    pub fn get_mut_mask(&mut self) -> LweMask<&mut [Scalar]> {
        let lwe_dimension = self.lwe_size().to_lwe_dimension();
        let ciphertext_modulus = self.ciphertext_modulus();

        LweMask::from_container(&mut self.as_mut()[0..lwe_dimension.0], ciphertext_modulus)
    }

    /// Mutable variant of [`LweCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> LweCiphertextMutView<'_, Scalar> {
        let ciphertext_modulus = self.ciphertext_modulus();
        LweCiphertextMutView::from_container(self.as_mut(), ciphertext_modulus)
    }
}

/// An [`LweCiphertext`] owning the memory for its own storage.
pub type LweCiphertextOwned<Scalar> = LweCiphertext<Vec<Scalar>>;
/// An [`LweCiphertext`] immutably borrowing memory for its own storage.
pub type LweCiphertextView<'data, Scalar> = LweCiphertext<&'data [Scalar]>;
/// An [`LweCiphertext`] mutably borrowing memory for its own storage.
pub type LweCiphertextMutView<'data, Scalar> = LweCiphertext<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> LweCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`LweCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext`] using this ciphertext as
    /// output.
    ///
    /// See [`LweCiphertext::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        lwe_size: LweSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> LweCiphertextOwned<Scalar> {
        LweCiphertextOwned::from_container(vec![fill_with; lwe_size.0], ciphertext_modulus)
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`LweCiphertext`] entities.
#[derive(Clone, Copy)]
pub struct LweCiphertextCreationMetadata<Scalar: UnsignedInteger>(pub CiphertextModulus<Scalar>);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for LweCiphertext<C> {
    type Metadata = LweCiphertextCreationMetadata<C::Element>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> LweCiphertext<C> {
        let LweCiphertextCreationMetadata(modulus) = meta;
        LweCiphertext::from_container(from, modulus)
    }
}
