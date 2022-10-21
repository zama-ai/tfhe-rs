#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::prelude::{LweDimension, LweSize};

use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, CompressionSeed, RandomGenerable, RandomGenerator, Uniform,
};
use crate::core_crypto::commons::math::tensor::AsMutTensor;

use super::{LweBody, LweCiphertext};

/// A seeded ciphertext encrypted using the LWE scheme.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededCiphertext<Scalar> {
    pub(crate) body: LweBody<Scalar>,
    pub(crate) lwe_dimension: LweDimension,
    pub(crate) compression_seed: CompressionSeed,
}

impl<Scalar: Numeric> LweSeededCiphertext<Scalar> {
    /// Allocates a seeded ciphertext whose body is 0.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::{LweBody, LweSeededCiphertext};
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{LweDimension, LweSize};
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let ciphertext = LweSeededCiphertext::allocate(LweDimension(3), compression_seed);
    /// assert_eq!(*ciphertext.get_body(), LweBody(0_u8));
    /// assert_eq!(ciphertext.lwe_size(), LweSize(4));
    /// assert_eq!(ciphertext.compression_seed(), compression_seed);
    /// ```
    pub fn allocate(lwe_dimension: LweDimension, seed: CompressionSeed) -> Self {
        Self::from_scalar(Scalar::ZERO, lwe_dimension, seed)
    }

    /// Allocates a new seeded ciphertext from elementary components.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::{LweBody, LweSeededCiphertext};
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{LweDimension, LweSize};
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let ciphertext = LweSeededCiphertext::from_scalar(0_u8, LweDimension(3), compression_seed);
    /// assert_eq!(*ciphertext.get_body(), LweBody(0_u8));
    /// assert_eq!(ciphertext.lwe_size(), LweSize(4));
    /// assert_eq!(ciphertext.compression_seed(), compression_seed);
    /// ```
    pub fn from_scalar(value: Scalar, lwe_dimension: LweDimension, seed: CompressionSeed) -> Self {
        Self {
            body: LweBody(value),
            lwe_dimension,
            compression_seed: seed,
        }
    }

    /// Returns the size of the ciphertext, e.g. the size of the mask + 1 for the body.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededCiphertext;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{LweDimension, LweSize};
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let ciphertext = LweSeededCiphertext::from_scalar(0_u8, LweDimension(3), compression_seed);
    /// assert_eq!(ciphertext.lwe_size(), LweSize(4));
    /// ```
    pub fn lwe_size(&self) -> LweSize {
        self.lwe_dimension.to_lwe_size()
    }

    /// Returns the body of the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::{LweBody, LweSeededCiphertext};
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::LweDimension;
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let ciphertext = LweSeededCiphertext::from_scalar(0_u8, LweDimension(3), compression_seed);
    /// let body = ciphertext.get_body();
    /// assert_eq!(*body, LweBody(0_u8));
    /// ```
    pub fn get_body(&self) -> &LweBody<Scalar> {
        &self.body
    }

    /// Returns the mutable body of the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::{LweBody, LweSeededCiphertext};
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::LweDimension;
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let mut ciphertext = LweSeededCiphertext::from_scalar(0_u8, LweDimension(3), compression_seed);
    /// let mut body = ciphertext.get_mut_body();
    /// assert_eq!(*body, LweBody(0_u8));
    /// *body = LweBody(8);
    /// let body = ciphertext.get_body();
    /// assert_eq!(body, &LweBody(8_u8));
    /// ```
    pub fn get_mut_body(&mut self) -> &mut LweBody<Scalar> {
        &mut self.body
    }

    /// Returns the seed of the ciphertext.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::{LweBody, LweSeededCiphertext};
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::LweDimension;
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let ciphertext = LweSeededCiphertext::from_scalar(0_u8, LweDimension(3), compression_seed);
    /// assert_eq!(ciphertext.compression_seed(), compression_seed);
    /// ```
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed
    }

    /// Returns the ciphertext as a fully fledged LweCiphertext
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::lwe::{
    ///     LweBody, LweCiphertext, LweSeededCiphertext,
    /// };
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{LweDimension, LweSize};
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let seeded_ciphertext: LweSeededCiphertext<u8> =
    ///     LweSeededCiphertext::allocate(LweDimension(9), compression_seed);
    /// let mut ciphertext = LweCiphertext::allocate(0_u8, LweSize(10));
    /// seeded_ciphertext.expand_into::<_, SoftwareRandomGenerator>(&mut ciphertext);
    /// let (body, mask) = ciphertext.get_mut_body_and_mask();
    /// assert_eq!(body, &mut LweBody(0));
    /// assert_eq!(mask.mask_size(), LweDimension(9));
    /// ```
    pub fn expand_into<Cont, Gen>(self, output: &mut LweCiphertext<Cont>)
    where
        LweCiphertext<Cont>: AsMutTensor<Element = Scalar>,
        Scalar: Copy + RandomGenerable<Uniform> + Numeric,
        Gen: ByteRandomGenerator,
    {
        let mut generator = RandomGenerator::<Gen>::new(self.compression_seed.seed);
        let (output_body, mut output_mask) = output.get_mut_body_and_mask();

        // generate a uniformly random mask
        generator.fill_tensor_with_random_uniform(output_mask.as_mut_tensor());

        output_body.0 = self.body.0;
    }
}
