//! Module containing the definition of the [`LweCompactPublicKey`].

use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::backward_compatibility::entities::lwe_compact_public_key::LweCompactPublicKeyVersions;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`compact public LWE encryption key`](`LweCompactPublicKey`).
///
/// Implementation of the public key construction described in <https://eprint.iacr.org/2023/603> by
/// M. Joye.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(LweCompactPublicKeyVersions)]
pub struct LweCompactPublicKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    glwe_ciphertext: GlweCiphertext<C>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for LweCompactPublicKey<C> {
    fn as_ref(&self) -> &[T] {
        self.glwe_ciphertext.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for LweCompactPublicKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.glwe_ciphertext.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweCompactPublicKey<C> {
    /// Create an [`LweCompactPublicKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`LweCompactPublicKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_compact_public_key`] using this key as
    /// output.
    ///
    /// This docstring exhibits [`LweCompactPublicKey`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweCompactPublicKey creation
    /// let lwe_dimension = LweDimension(1024);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LweCompactPublicKey
    /// let lwe_compact_public_key = LweCompactPublicKey::new(0u64, lwe_dimension, ciphertext_modulus);
    ///
    /// assert_eq!(lwe_compact_public_key.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     lwe_compact_public_key.ciphertext_modulus(),
    ///     ciphertext_modulus
    /// );
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_compact_public_key.into_container();
    ///
    /// // Recreate a public key using from_container
    /// let lwe_compact_public_key =
    ///     LweCompactPublicKey::from_container(underlying_container, ciphertext_modulus);
    ///
    /// assert_eq!(lwe_compact_public_key.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     lwe_compact_public_key.ciphertext_modulus(),
    ///     ciphertext_modulus
    /// );
    /// ```
    pub fn from_container(container: C, ciphertext_modulus: CiphertextModulus<Scalar>) -> Self {
        assert!(
            container.container_len().is_power_of_two(),
            "LweCompactPublicKey container len must be a power of 2, got len = {}",
            container.container_len()
        );
        let equivalent_polynomial_size = PolynomialSize(container.container_len() / 2);
        Self {
            glwe_ciphertext: GlweCiphertext::from_container(
                container,
                equivalent_polynomial_size,
                ciphertext_modulus,
            ),
        }
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweCompactPublicKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.glwe_ciphertext.into_container()
    }

    /// Return the [`LweDimension`] of the [`LweCompactPublicKey`].
    ///
    /// See [`LweCompactPublicKey::from_container`] for usage.
    pub fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.glwe_ciphertext.polynomial_size().0)
    }

    /// Return the [`CiphertextModulus`] of the [`LweCompactPublicKey`].
    ///
    /// See [`LweCompactPublicKey::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.glwe_ciphertext.ciphertext_modulus()
    }

    /// Return an immutable view to the [`GlweMask`] of the underlying [`GlweCiphertext`] of the
    /// [`LweCompactPublicKey`].
    pub fn get_mask(&self) -> GlweMask<&[Scalar]> {
        self.glwe_ciphertext.get_mask()
    }

    /// Return an immutable view to the [`GlweBody`] of the underlying [`GlweCiphertext`] of the
    /// [`LweCompactPublicKey`].
    pub fn get_body(&self) -> GlweBody<&[Scalar]> {
        self.glwe_ciphertext.get_body()
    }

    /// Return immutable views to the [`GlweMask`] and [`GlweBody`] of the underlying
    /// [`GlweCiphertext`]  of the [`LweCompactPublicKey`].
    pub fn get_mask_and_body(&self) -> (GlweMask<&[Scalar]>, GlweBody<&[Scalar]>) {
        self.glwe_ciphertext.get_mask_and_body()
    }

    pub fn as_glwe_ciphertext(&self) -> GlweCiphertextView<'_, Scalar> {
        self.glwe_ciphertext.as_view()
    }

    pub fn size_elements(&self) -> usize {
        self.glwe_ciphertext.as_ref().len()
    }

    pub fn size_bytes(&self) -> usize {
        std::mem::size_of_val(self.glwe_ciphertext.as_ref())
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweCompactPublicKey<C> {
    /// Return a mutable view to the [`GlweMask`] of the underlying [`GlweCiphertext`] of the
    /// [`LweCompactPublicKey`].
    pub fn get_mut_mask(&mut self) -> GlweMask<&mut [Scalar]> {
        self.glwe_ciphertext.get_mut_mask()
    }

    /// Return a mutable view to the [`GlweBody`] of the underlying [`GlweCiphertext`] of the
    /// [`LweCompactPublicKey`].
    pub fn get_mut_body(&mut self) -> GlweBody<&mut [Scalar]> {
        self.glwe_ciphertext.get_mut_body()
    }

    /// Return mutable views to the [`GlweMask`] and [`GlweBody`] of the underlying
    /// [`GlweCiphertext`]  of the [`LweCompactPublicKey`].
    pub fn get_mut_mask_and_body(&mut self) -> (GlweMask<&mut [Scalar]>, GlweBody<&mut [Scalar]>) {
        self.glwe_ciphertext.get_mut_mask_and_body()
    }

    pub fn as_mut_glwe_ciphertext(&mut self) -> GlweCiphertextMutView<'_, Scalar> {
        self.glwe_ciphertext.as_mut_view()
    }
}

pub type LweCompactPublicKeyOwned<Scalar> = LweCompactPublicKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> LweCompactPublicKeyOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        lwe_dimension: LweDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert!(
            lwe_dimension.0.is_power_of_two(),
            "LweCompactPublicKey only supports power of 2 LweDimension. Got lwe_dimension = {}.",
            lwe_dimension.0
        );
        Self::from_container(vec![fill_with; 2 * lwe_dimension.0], ciphertext_modulus)
    }
}

#[derive(Clone, Copy)]
pub struct LweCompactPublicKeyEncryptionParameters<Scalar: UnsignedInteger> {
    pub encryption_lwe_dimension: LweDimension,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<C: Container> ParameterSetConformant for LweCompactPublicKey<C>
where
    C::Element: UnsignedInteger,
{
    type ParameterSet = LweCompactPublicKeyEncryptionParameters<C::Element>;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { glwe_ciphertext } = self;

        if !parameter_set.encryption_lwe_dimension.0.is_power_of_two() {
            return false;
        }

        let glwe_ciphertext_conformance_parameters = GlweCiphertextConformanceParameters {
            glwe_dim: GlweDimension(1),
            polynomial_size: PolynomialSize(parameter_set.encryption_lwe_dimension.0),
            ct_modulus: parameter_set.ciphertext_modulus,
        };

        glwe_ciphertext.is_conformant(&glwe_ciphertext_conformance_parameters)
    }
}
