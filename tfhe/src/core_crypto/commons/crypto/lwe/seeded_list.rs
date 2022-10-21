#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::prelude::{CiphertextCount, LweDimension, LweSize};

use crate::core_crypto::commons::crypto::lwe::LweList;
use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, CompressionSeed, RandomGenerable, RandomGenerator, Uniform,
};
use crate::core_crypto::commons::math::tensor::{
    tensor_traits, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};

use super::LweBody;

/// A seeded list of ciphertexts encrypted using the LWE scheme.
///
/// Note: all ciphertexts in an [`LweSeededList`] share the same seed for mask generation and have
/// the same [`LweDimension`]. If you need mixed seeds or dimensions you can use a container storing
/// seeded ciphertexts directly. The bytes used to generate their masks however are not the same.
/// The bytes index to use for each mask is dependant on the ciphertext position in the list.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededList<Cont> {
    tensor: Tensor<Cont>,
    lwe_dimension: LweDimension,
    pub(crate) compression_seed: CompressionSeed,
}

tensor_traits!(LweSeededList);

impl<Scalar> LweSeededList<Vec<Scalar>>
where
    Scalar: Numeric,
{
    /// Allocates a list of seeded LWE ciphertexts whose bodies are 0.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweDimension, LweSize};
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list =
    ///     LweSeededList::<Vec<u8>>::allocate(LweDimension(9), CiphertextCount(20), compression_seed);
    ///
    /// assert_eq!(list.count(), CiphertextCount(20));
    /// assert_eq!(list.lwe_size(), LweSize(10));
    /// assert_eq!(list.get_compression_seed(), compression_seed);
    /// ```
    pub fn allocate(
        lwe_dimension: LweDimension,
        lwe_count: CiphertextCount,
        compression_seed: CompressionSeed,
    ) -> Self {
        LweSeededList {
            tensor: Tensor::from_container(vec![Scalar::ZERO; lwe_count.0]),
            lwe_dimension,
            compression_seed,
        }
    }
}

impl<Cont> LweSeededList<Cont> {
    /// Creates a list from a container, an [`LweDimension`] a [`Seed`] and a usize representing the
    /// index of the first byte to generate for the masks of the list.
    ///
    /// # Example:
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweDimension, LweSize};
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list =
    ///     LweSeededList::<Vec<u8>>::allocate(LweDimension(9), CiphertextCount(20), compression_seed);
    ///
    /// assert_eq!(list.count(), CiphertextCount(20));
    /// assert_eq!(list.lwe_size(), LweSize(10));
    /// assert_eq!(list.get_compression_seed(), compression_seed);
    /// ```
    pub fn from_container(cont: Cont, lwe_dimension: LweDimension, seed: CompressionSeed) -> Self
    where
        Cont: AsRefSlice,
    {
        let tensor = Tensor::from_container(cont);
        LweSeededList {
            tensor,
            lwe_dimension,
            compression_seed: seed,
        }
    }

    /// Returns the number of ciphertexts in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweDimension, LweSize};
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list =
    ///     LweSeededList::<Vec<u8>>::allocate(LweDimension(9), CiphertextCount(20), compression_seed);
    ///
    /// assert_eq!(list.count(), CiphertextCount(20));
    /// ```
    pub fn count(&self) -> CiphertextCount
    where
        Self: AsRefTensor,
    {
        CiphertextCount(self.as_tensor().len())
    }

    /// Returns the size of the ciphertexts in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweDimension, LweSize};
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list =
    ///     LweSeededList::<Vec<u8>>::allocate(LweDimension(9), CiphertextCount(20), compression_seed);
    ///
    /// assert_eq!(list.lwe_size(), LweSize(10));
    /// ```
    pub fn lwe_size(&self) -> LweSize {
        self.lwe_dimension.to_lwe_size()
    }

    /// Returns the number of masks of the ciphertexts in the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweDimension};
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list =
    ///     LweSeededList::<Vec<u8>>::allocate(LweDimension(9), CiphertextCount(20), compression_seed);
    ///
    /// assert_eq!(list.mask_size(), LweDimension(9));
    /// ```
    pub fn mask_size(&self) -> LweDimension {
        self.lwe_dimension
    }

    /// Returns the seed of the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededList;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweDimension};
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list =
    ///     LweSeededList::<Vec<u8>>::allocate(LweDimension(9), CiphertextCount(20), compression_seed);
    ///
    /// assert_eq!(list.get_compression_seed(), compression_seed);
    /// ```
    pub fn get_compression_seed(&self) -> CompressionSeed {
        self.compression_seed
    }

    /// Returns an iterator over seeded ciphertexts from the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::{LweBody, LweSeededList};
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweDimension};
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let list =
    ///     LweSeededList::<Vec<u8>>::allocate(LweDimension(9), CiphertextCount(20), compression_seed);
    ///
    /// for body in list.body_iter() {
    ///     assert_eq!(body, &LweBody(0));
    /// }
    /// assert_eq!(list.body_iter().count(), 20);
    /// ```
    pub fn body_iter(&self) -> impl Iterator<Item = &LweBody<<Self as AsRefTensor>::Element>>
    where
        Self: AsRefTensor,
    {
        self.as_tensor()
            .iter()
            .map(|scalar| unsafe { std::mem::transmute(scalar) })
    }

    /// Returns an iterator over seeded ciphertexts from the list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::lwe::{LweBody, LweSeededList};
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweDimension};
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let mut list =
    ///     LweSeededList::<Vec<u8>>::allocate(LweDimension(9), CiphertextCount(20), compression_seed);
    ///
    /// for mut body in list.body_iter_mut() {
    ///     assert_eq!(body, &LweBody(0));
    ///     body.0 = 1;
    /// }
    /// for mut body in list.body_iter() {
    ///     assert_eq!(body, &LweBody(1));
    /// }
    /// assert_eq!(list.body_iter().count(), 20);
    /// ```
    pub fn body_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut LweBody<<Self as AsRefTensor>::Element>>
    where
        Self: AsMutTensor,
    {
        self.as_mut_tensor()
            .iter_mut()
            .map(|scalar| unsafe { std::mem::transmute(scalar) })
    }

    pub fn expand_into_with_existing_generator<OutCont, Scalar, Gen>(
        self,
        output: &mut LweList<OutCont>,
        generator: &mut RandomGenerator<Gen>,
    ) where
        LweList<OutCont>: AsMutTensor<Element = Scalar>,
        Self: AsRefTensor<Element = Scalar>,
        Scalar: RandomGenerable<Uniform> + Numeric,
        Gen: ByteRandomGenerator,
    {
        for (mut lwe_out, body_in) in output.ciphertext_iter_mut().zip(self.body_iter()) {
            let (output_body, mut output_mask) = lwe_out.get_mut_body_and_mask();

            // generate a uniformly random mask
            generator.fill_tensor_with_random_uniform(output_mask.as_mut_tensor());
            output_body.0 = body_in.0;
        }
    }

    /// Returns the ciphertext list as a full fledged LweList
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::lwe::{LweList, LweSeededList};
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{CiphertextCount, LweDimension, LweSize};
    ///
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let seeded_list =
    ///     LweSeededList::<Vec<u8>>::allocate(LweDimension(9), CiphertextCount(20), compression_seed);
    ///
    /// let mut list = LweList::allocate(0u8, seeded_list.lwe_size(), seeded_list.count());
    /// seeded_list.expand_into::<_, _, SoftwareRandomGenerator>(&mut list);
    /// assert_eq!(list.mask_size(), LweDimension(9));
    /// ```
    pub fn expand_into<OutCont, Scalar, Gen>(self, output: &mut LweList<OutCont>)
    where
        LweList<OutCont>: AsMutTensor<Element = Scalar>,
        Self: AsRefTensor<Element = Scalar>,
        Scalar: RandomGenerable<Uniform> + Numeric,
        Gen: ByteRandomGenerator,
    {
        let mut generator = RandomGenerator::<Gen>::new(self.compression_seed.seed);

        self.expand_into_with_existing_generator(output, &mut generator);
    }
}
