use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;

/// A convenience structure to easily manipulate the body of an [`LweCiphertext`].
#[derive(Clone, Debug)]
pub struct LweBody<T>(pub T);
#[derive(Clone, Debug)]
pub struct LweMask<C: Container> {
    data: C,
}

/// A convenience structure to easily manipulate the mask of an [`LweCiphertext`].
impl<C: Container> LweMask<C> {
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
    ///
    /// let lwe_mask = LweMask::from_container(vec![0u64; lwe_dimension.0]);
    ///
    /// assert_eq!(lwe_mask.lwe_dimension(), lwe_dimension);
    /// ```
    pub fn from_container(container: C) -> Self {
        LweMask { data: container }
    }

    /// Return the [`LweDimension`] of the [`LweMask`].
    ///
    /// See [`LweMask::from_container`] for usage.
    pub fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len())
    }
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LweMask<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LweMask<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<'data, T> CreateFrom<&'data [T]> for LweBody<&'data T> {
    type Metadata = ();

    #[inline]
    fn create_from(from: &[T], _meta: Self::Metadata) -> LweBody<&'_ T> {
        LweBody(&from[0])
    }
}

impl<'data, T> CreateFrom<&'data mut [T]> for LweBody<&'data mut T> {
    type Metadata = ();

    #[inline]
    fn create_from(from: &mut [T], _meta: Self::Metadata) -> LweBody<&'_ mut T> {
        LweBody(&mut from[0])
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LweCiphertext<C: Container> {
    data: C,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LweCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> LweCiphertext<C> {
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
    ///
    /// // Create a new LweCiphertext
    /// let mut lwe = LweCiphertext::new(0u64, lwe_size);
    ///
    /// assert_eq!(lwe.lwe_size(), lwe_size);
    /// assert_eq!(lwe.get_mask().lwe_dimension(), lwe_size.to_lwe_dimension());
    /// assert_eq!(
    ///     lwe.get_mut_mask().lwe_dimension(),
    ///     lwe_size.to_lwe_dimension()
    /// );
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let mut lwe = LweCiphertext::from_container(underlying_container);
    ///
    /// assert_eq!(lwe.lwe_size(), lwe_size);
    /// assert_eq!(lwe.get_mask().lwe_dimension(), lwe_size.to_lwe_dimension());
    /// assert_eq!(
    ///     lwe.get_mut_mask().lwe_dimension(),
    ///     lwe_size.to_lwe_dimension()
    /// );
    /// ```
    pub fn from_container(container: C) -> LweCiphertext<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweCiphertext"
        );
        LweCiphertext { data: container }
    }

    /// Return the [`LweSize`] of the [`LweCiphertext`].
    ///
    /// See [`LweCiphertext::from_container`] for usage.
    pub fn lwe_size(&self) -> LweSize {
        LweSize(self.data.container_len())
    }

    /// Return immutable views to the [`LweMask`] and [`LweBody`] of an [`LweCiphertext`].
    pub fn get_mask_and_body(&self) -> (LweMask<&[Scalar]>, LweBody<&Scalar>) {
        let (body, mask) = self.data.as_ref().split_last().unwrap();

        (LweMask::from_container(mask), LweBody(body))
    }

    /// Return an immutable view to the [`LweBody`] of an [`LweCiphertext`].
    pub fn get_body(&self) -> LweBody<&Scalar> {
        let body = self.data.as_ref().last().unwrap();

        LweBody(body)
    }

    /// Return an immutable view to the [`LweMask`] of an [`LweCiphertext`].
    ///
    /// See [`LweCiphertext::from_container`] for usage.
    pub fn get_mask(&self) -> LweMask<&[Scalar]> {
        LweMask::from_container(&self.as_ref()[0..self.lwe_size().to_lwe_dimension().0])
    }

    /// Return a view of the [`LweCiphertext`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> LweCiphertextView<'_, Scalar> {
        LweCiphertextView::from_container(self.as_ref())
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweCiphertext::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LweCiphertext<C> {
    /// Mutable variant of [`LweCiphertext::get_mask_and_body`].
    pub fn get_mut_mask_and_body(&mut self) -> (LweMask<&mut [Scalar]>, LweBody<&mut Scalar>) {
        let (body, mask) = self.data.as_mut().split_last_mut().unwrap();

        (LweMask::from_container(mask), LweBody(body))
    }

    /// Mutable variant of [`LweCiphertext::get_body`].
    pub fn get_mut_body(&mut self) -> LweBody<&mut Scalar> {
        let body = self.data.as_mut().last_mut().unwrap();

        LweBody(body)
    }

    /// Mutable variant of [`LweCiphertext::get_mask`].
    ///
    /// See [`LweCiphertext::from_container`] for usage.
    pub fn get_mut_mask(&mut self) -> LweMask<&mut [Scalar]> {
        let lwe_dimension = self.lwe_size().to_lwe_dimension();
        LweMask::from_container(&mut self.as_mut()[0..lwe_dimension.0])
    }

    /// Mutable variant of [`LweCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> LweCiphertextMutView<'_, Scalar> {
        LweCiphertextMutView::from_container(self.as_mut())
    }
}

/// An [`LweCiphertext`] owning the memory for its own storage.
pub type LweCiphertextOwned<Scalar> = LweCiphertext<Vec<Scalar>>;
/// An [`LweCiphertext`] immutably borrowing memory for its own storage.
pub type LweCiphertextView<'data, Scalar> = LweCiphertext<&'data [Scalar]>;
/// An [`LweCiphertext`] mutably borrowing memory for its own storage.
pub type LweCiphertextMutView<'data, Scalar> = LweCiphertext<&'data mut [Scalar]>;

impl<Scalar: Copy> LweCiphertextOwned<Scalar> {
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
    pub fn new(fill_with: Scalar, lwe_size: LweSize) -> LweCiphertextOwned<Scalar> {
        LweCiphertextOwned::from_container(vec![fill_with; lwe_size.0])
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`LweCiphertext`] entities.
#[derive(Clone, Copy)]
pub struct LweCiphertextCreationMetadata();

impl<C: Container> CreateFrom<C> for LweCiphertext<C> {
    type Metadata = LweCiphertextCreationMetadata;

    #[inline]
    fn create_from(from: C, _: Self::Metadata) -> LweCiphertext<C> {
        LweCiphertext::from_container(from)
    }
}
