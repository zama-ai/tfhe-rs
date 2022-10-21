use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, CompressionSeed, RandomGenerable, RandomGenerator, Uniform,
};
use crate::core_crypto::commons::math::tensor::{
    tensor_traits, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, IntoTensor, Tensor,
};

use super::{GlweBody, GlweCiphertext};

/// An GLWE seeded ciphertext.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweSeededCiphertext<Cont> {
    tensor: Tensor<Cont>,
    glwe_dimension: GlweDimension,
    compression_seed: CompressionSeed,
}

tensor_traits!(GlweSeededCiphertext);

impl<Scalar> GlweSeededCiphertext<Vec<Scalar>> {
    /// Allocates a new GLWE seeded ciphertext, whose body coefficients are all 0. The underlying
    /// container has a size of `poly_size`. This seeded version of the GLWE ciphertext stores the
    /// coefficients of the body.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweSeededCiphertext;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(99);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let glwe_seeded_ciphertext = GlweSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(glwe_seeded_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe_seeded_ciphertext.mask_size(), glwe_dimension);
    /// assert_eq!(glwe_seeded_ciphertext.compression_seed(), compression_seed);
    /// assert_eq!(glwe_seeded_ciphertext.size(), glwe_dimension.to_glwe_size());
    /// ```
    pub fn allocate(
        poly_size: PolynomialSize,
        dimension: GlweDimension,
        compression_seed: CompressionSeed,
    ) -> Self
    where
        Self: AsMutTensor,
        Scalar: Numeric,
    {
        Self {
            tensor: Tensor::from_container(vec![Scalar::ZERO; poly_size.0]),
            glwe_dimension: dimension,
            compression_seed,
        }
    }
}

impl<Cont> GlweSeededCiphertext<Cont> {
    /// Creates a new GLWE seeded ciphertext from an existing container.
    ///
    /// # Note
    ///
    /// This method does not perform any transformation of the container data. Those are assumed to
    /// represent a valid glwe body.
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::{GlweBody, GlweSeededCiphertext};
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::commons::math::tensor::{AsRefSlice, AsRefTensor, Tensor};
    /// use tfhe::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(99);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    /// let tensor_container = vec![0u8; polynomial_size.0];
    ///
    /// let glwe_seeded_ciphertext = GlweSeededCiphertext::<Vec<u8>>::from_container(
    ///     tensor_container,
    ///     glwe_dimension,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(glwe_seeded_ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe_seeded_ciphertext.mask_size(), glwe_dimension);
    /// assert_eq!(glwe_seeded_ciphertext.compression_seed(), compression_seed);
    /// assert_eq!(glwe_seeded_ciphertext.size(), glwe_dimension.to_glwe_size());
    /// ```
    pub fn from_container(
        cont: Cont,
        dimension: GlweDimension,
        compression_seed: CompressionSeed,
    ) -> Self {
        Self {
            tensor: Tensor::from_container(cont),
            glwe_dimension: dimension,
            compression_seed,
        }
    }

    /// Returns the size of the ciphertext, i.e. the number of masks + 1.
    ///
    /// # Example
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweSeededCiphertext;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(99);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let glwe_seeded_ciphertext = GlweSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(glwe_seeded_ciphertext.size(), glwe_dimension.to_glwe_size());
    /// ```
    pub fn size(&self) -> GlweSize {
        self.glwe_dimension.to_glwe_size()
    }

    /// Returns the number of masks of the ciphertext, i.e. its size - 1.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweSeededCiphertext;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(99);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let glwe_seeded_ciphertext = GlweSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(glwe_seeded_ciphertext.mask_size(), glwe_dimension);
    /// ```
    pub fn mask_size(&self) -> GlweDimension {
        self.glwe_dimension
    }

    /// Returns the number of coefficients of the polynomials of the ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweSeededCiphertext;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(99);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let glwe_seeded_ciphertext = GlweSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(glwe_seeded_ciphertext.polynomial_size(), polynomial_size);
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize
    where
        Self: AsRefTensor,
    {
        PolynomialSize(self.as_tensor().len())
    }

    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweSeededCiphertext;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(99);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let glwe_seeded_ciphertext = GlweSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(glwe_seeded_ciphertext.compression_seed(), compression_seed);
    /// ```
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed
    }

    /// Returns a borrowed [`GlweBody`] from the current ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::{GlweBody, GlweSeededCiphertext};
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::commons::math::tensor::{AsRefSlice, AsRefTensor, Tensor};
    /// use tfhe::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(99);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let glwe_seeded_ciphertext = GlweSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     compression_seed,
    /// );
    ///
    /// let tensor_container = vec![0u8; polynomial_size.0];
    ///
    /// assert_eq!(
    ///     glwe_seeded_ciphertext.get_body().as_tensor().as_slice(),
    ///     &tensor_container[..]
    /// );
    /// ```
    pub fn get_body(&self) -> GlweBody<&[<Self as AsRefTensor>::Element]>
    where
        Self: AsRefTensor,
    {
        GlweBody {
            tensor: self.as_tensor().get_sub(0..),
        }
    }

    /// Returns a mutably borrowed [`GlweBody`] from the current ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::glwe::{GlweBody, GlweSeededCiphertext};
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::commons::math::tensor::{
    ///     AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
    /// };
    /// use tfhe::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
    ///
    /// let polynomial_size = PolynomialSize(10);
    /// let glwe_dimension = GlweDimension(99);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let mut glwe_seeded_ciphertext = GlweSeededCiphertext::<Vec<u8>>::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     compression_seed,
    /// );
    ///
    /// let mut tensor_container = vec![0u8; polynomial_size.0];
    ///
    /// assert_eq!(
    ///     glwe_seeded_ciphertext.get_mut_body().as_tensor().as_slice(),
    ///     &tensor_container[..]
    /// );
    ///
    /// glwe_seeded_ciphertext
    ///     .get_mut_body()
    ///     .as_mut_tensor()
    ///     .as_mut_slice()[0] = 1;
    ///
    /// tensor_container[0] = 1;
    ///
    /// assert_eq!(
    ///     glwe_seeded_ciphertext.get_mut_body().as_tensor().as_slice(),
    ///     &tensor_container[..]
    /// );
    /// ```
    pub fn get_mut_body(&mut self) -> GlweBody<&mut [<Self as AsRefTensor>::Element]>
    where
        Self: AsMutTensor,
    {
        GlweBody {
            tensor: self.as_mut_tensor().get_sub_mut(0..),
        }
    }

    pub fn expand_into_with_existing_generator<Scalar, OutputCont, Gen>(
        self,
        output: &mut GlweCiphertext<OutputCont>,
        generator: &mut RandomGenerator<Gen>,
    ) where
        Scalar: Copy + RandomGenerable<Uniform> + Numeric,
        GlweCiphertext<OutputCont>: AsMutTensor<Element = Scalar>,
        Self: IntoTensor<Element = Scalar> + AsRefTensor,
        Gen: ByteRandomGenerator,
    {
        let (mut output_body, mut output_mask) = output.get_mut_body_and_mask();

        // generate a uniformly random mask
        generator.fill_tensor_with_random_uniform(output_mask.as_mut_tensor());

        output_body
            .as_mut_tensor()
            .as_mut_slice()
            .clone_from_slice(self.into_tensor().as_slice());
    }

    /// Returns the ciphertext as a full fledged GlweCiphertext
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::crypto::glwe::{GlweCiphertext, GlweSeededCiphertext};
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::random::CompressionSeed;
    /// use tfhe::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
    ///
    /// let polynomial_size = PolynomialSize(5);
    /// let glwe_dimension = GlweDimension(256);
    ///
    /// let mut seeded_ciphertext = GlweSeededCiphertext::allocate(
    ///     polynomial_size,
    ///     glwe_dimension,
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    ///
    /// let mut ciphertext = GlweCiphertext::allocate(
    ///     0 as u32,
    ///     seeded_ciphertext.polynomial_size(),
    ///     seeded_ciphertext.size(),
    /// );
    ///
    /// seeded_ciphertext.expand_into::<_, _, SoftwareRandomGenerator>(&mut ciphertext);
    ///
    /// assert_eq!(ciphertext.mask_size(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    /// ```
    pub fn expand_into<Scalar, OutCont, Gen>(self, output: &mut GlweCiphertext<OutCont>)
    where
        Scalar: Copy + RandomGenerable<Uniform> + Numeric,
        GlweCiphertext<OutCont>: AsMutTensor<Element = Scalar>,
        Self: IntoTensor<Element = Scalar> + AsRefTensor,
        Gen: ByteRandomGenerator,
    {
        let mut generator = RandomGenerator::<Gen>::new(self.compression_seed().seed);

        self.expand_into_with_existing_generator::<_, _, Gen>(output, &mut generator);
    }
}
