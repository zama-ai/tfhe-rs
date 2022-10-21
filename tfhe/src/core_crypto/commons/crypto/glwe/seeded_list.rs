use crate::core_crypto::prelude::{
    CiphertextCount, GlweDimension, GlweSize, PolynomialSize,
};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

use super::{GlweBody, GlweList};
use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, CompressionSeed, RandomGenerable, RandomGenerator, Uniform,
};
use crate::core_crypto::commons::math::tensor::{
    ck_dim_div, tensor_traits, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};
use crate::core_crypto::commons::numeric::Numeric;

/// A list of ciphertexts encoded with the GLWE scheme.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweSeededList<Cont> {
    pub tensor: Tensor<Cont>,
    pub glwe_dimension: GlweDimension,
    pub poly_size: PolynomialSize,
    pub compression_seed: CompressionSeed,
}

tensor_traits!(GlweSeededList);

impl<Scalar> GlweSeededList<Vec<Scalar>>
where
    Scalar: Numeric,
{
    /// Allocates storage for an owned [`GlweSeededList`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, GlweDimension, GlweSize, PolynomialSize,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(20);
    /// let ciphertext_count = CiphertextCount(30);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list = GlweSeededList::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     ciphertext_count,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(list.polynomial_size(), polynomial_size);
    /// assert_eq!(list.glwe_dimension(), GlweDimension(20));
    /// assert_eq!(list.glwe_size(), GlweSize(21));
    /// assert_eq!(list.ciphertext_count(), ciphertext_count);
    /// assert_eq!(list.compression_seed(), compression_seed);
    /// ```
    pub fn allocate(
        poly_size: PolynomialSize,
        glwe_dimension: GlweDimension,
        ciphertext_number: CiphertextCount,
        compression_seed: CompressionSeed,
    ) -> Self {
        GlweSeededList {
            tensor: Tensor::from_container(vec![Scalar::ZERO; poly_size.0 * ciphertext_number.0]),
            glwe_dimension,
            poly_size,
            compression_seed,
        }
    }
}

impl<Cont> GlweSeededList<Cont> {
    /// Creates a list from a container of values.
    ///
    /// # Example
    ///
    /// TODO
    pub fn from_container(
        cont: Cont,
        glwe_dimension: GlweDimension,
        poly_size: PolynomialSize,
        compression_seed: CompressionSeed,
    ) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() => poly_size.0);
        GlweSeededList {
            tensor,
            glwe_dimension,
            poly_size,
            compression_seed,
        }
    }

    /// Returns the number of ciphertexts in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, GlweDimension, GlweSize, PolynomialSize,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(20);
    /// let ciphertext_count = CiphertextCount(30);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list = GlweSeededList::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     ciphertext_count,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(list.ciphertext_count(), ciphertext_count);
    /// ```
    pub fn ciphertext_count(&self) -> CiphertextCount
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.poly_size.0);
        CiphertextCount(self.as_tensor().len() / self.polynomial_size().0)
    }

    /// Returns the size of the glwe ciphertexts contained in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, GlweDimension, GlweSize, PolynomialSize,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(20);
    /// let ciphertext_count = CiphertextCount(30);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list = GlweSeededList::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     ciphertext_count,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(list.glwe_size(), GlweSize(21));
    /// ```
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_dimension.to_glwe_size()
    }

    /// Returns the number of coefficients of the polynomials used for the list ciphertexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, GlweDimension, GlweSize, PolynomialSize,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(20);
    /// let ciphertext_count = CiphertextCount(30);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list = GlweSeededList::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     ciphertext_count,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(list.polynomial_size(), polynomial_size);
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns the number of masks of the ciphertexts in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, GlweDimension, GlweSize, PolynomialSize,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(20);
    /// let ciphertext_count = CiphertextCount(30);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list = GlweSeededList::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     ciphertext_count,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(list.glwe_dimension(), GlweDimension(20));
    /// ```
    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, GlweDimension, GlweSize, PolynomialSize,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(20);
    /// let ciphertext_count = CiphertextCount(30);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list = GlweSeededList::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     ciphertext_count,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(list.compression_seed(), compression_seed);
    /// ```
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed
    }

    /// Returns an iterator over ciphertexts bodies from the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::commons::math::tensor::{
    ///     AsRefSlice, AsRefTensor, Tensor,
    /// };
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, GlweDimension, GlweSize, PolynomialSize,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(20);
    /// let ciphertext_count = CiphertextCount(30);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list = GlweSeededList::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     ciphertext_count,
    ///     compression_seed,
    /// );
    ///
    /// for body in list.body_iter() {
    ///     let tensor_container = vec![0u8; polynomial_size.0];
    ///
    ///     assert_eq!(body.as_tensor().as_slice(), &tensor_container[..]);
    /// }
    /// ```
    pub fn body_iter(&self) -> impl Iterator<Item = GlweBody<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        self.as_tensor()
            .as_slice()
            .chunks(self.poly_size.0)
            .map(|body| GlweBody {
                tensor: Tensor::from_container(body),
            })
    }

    /// Returns an iterator over mutable ciphertexts bodies from the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::commons::math::tensor::{
    ///     AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
    /// };
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, GlweDimension, GlweSize, PolynomialSize,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(20);
    /// let ciphertext_count = CiphertextCount(30);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let mut list = GlweSeededList::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     ciphertext_count,
    ///     compression_seed,
    /// );
    ///
    /// for mut body in list.body_iter_mut() {
    ///     let mut tensor_container = vec![0u8; polynomial_size.0];
    ///
    ///     assert_eq!(body.as_tensor().as_slice(), &tensor_container[..]);
    ///
    ///     body.as_mut_tensor().as_mut_slice()[0] = 1;
    ///
    ///     tensor_container[0] = 1;
    ///
    ///     assert_eq!(body.as_tensor().as_slice(), &tensor_container[..]);
    /// }
    /// ```
    pub fn body_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = GlweBody<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        let poly_size = self.poly_size.0;

        self.as_mut_tensor()
            .as_mut_slice()
            .chunks_mut(poly_size)
            .map(|body| GlweBody {
                tensor: Tensor::from_container(body),
            })
    }

    /// Returns the ciphertext list as a full fledged GlweList
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::PlaintextList;
    /// use tfhe::core_crypto::commons::crypto::glwe::{
    ///     GlweCiphertext, GlweList, GlweSeededList,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::random::CompressionSeed;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, GlweDimension, LogStandardDev, PolynomialSize,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(2);
    /// let glwe_dimension = GlweDimension(256);
    /// let ciphertext_count = CiphertextCount(2);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let mut seeded_ciphertexts = GlweSeededList::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     ciphertext_count,
    ///     compression_seed,
    /// );
    ///
    /// let mut ciphertexts = GlweList::allocate(
    ///     0 as u32,
    ///     seeded_ciphertexts.polynomial_size(),
    ///     seeded_ciphertexts.glwe_size().to_glwe_dimension(),
    ///     seeded_ciphertexts.ciphertext_count(),
    /// );
    ///
    /// seeded_ciphertexts.expand_into::<_, _, SoftwareRandomGenerator>(&mut ciphertexts);
    ///
    /// assert_eq!(ciphertexts.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertexts.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertexts.ciphertext_count(), ciphertext_count);
    /// ```
    pub fn expand_into<OutCont, Scalar, Gen>(self, output: &mut GlweList<OutCont>)
    where
        Self: AsRefTensor<Element = Scalar>,
        GlweList<OutCont>: AsMutTensor<Element = Scalar>,
        Scalar: Numeric + RandomGenerable<Uniform>,
        Gen: ByteRandomGenerator,
    {
        let mut generator = RandomGenerator::<Gen>::new(self.compression_seed().seed);

        for (mut glwe_out, body_in) in output.ciphertext_iter_mut().zip(self.body_iter()) {
            let (mut body, mut mask) = glwe_out.get_mut_body_and_mask();
            generator.fill_tensor_with_random_uniform(mask.as_mut_tensor());
            body.as_mut_tensor().fill_with_copy(body_in.as_tensor());
        }
    }
}
