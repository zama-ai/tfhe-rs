#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

use crate::core_crypto::commons::numeric::Numeric;

use crate::core_crypto::prelude::{
    BinaryKeyKind, CiphertextCount, DecompositionBaseLog, DecompositionLevelCount,
    DispersionParameter, LweDimension, LweSize,
};

use crate::core_crypto::commons::crypto::encoding::{Plaintext, PlaintextList};
use crate::core_crypto::commons::crypto::secret::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::crypto::secret::LweSecretKey;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm};
use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, CompressionSeed, RandomGenerable, RandomGenerator, Seeder, Uniform,
};
use crate::core_crypto::commons::math::tensor::{
    ck_dim_div, tensor_traits, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;

use super::{LweKeyswitchKey, LweList, LweSeededList};

/// A seeded Lwe Keyswithing key.
///
/// See [`LweKeyswitchKey`] for more details on keyswitching keys.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededKeyswitchKey<Cont> {
    tensor: Tensor<Cont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    // Output LweSize
    lwe_size: LweSize,
    compression_seed: CompressionSeed,
}

tensor_traits!(LweSeededKeyswitchKey);

impl<Scalar> LweSeededKeyswitchKey<Vec<Scalar>>
where
    Scalar: Copy + Numeric,
{
    /// Allocates a seeded keyswitching key, the underlying container has a size of
    /// `level_decomp * input_dimension`. This seeded version of the keyswitch key stores the
    /// bodies of ciphertexts encrypting each bit of the input LWE secret key level_decomp times.
    ///
    /// # Note
    ///
    /// This function does *not* generate a seeded keyswitch key, but merely allocates a container
    /// of the right size. See [`LweSeededKeyswitchKey::fill_with_seeded_keyswitch_key`] to fill
    /// the container with a proper seeded keyswitching key.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededKeyswitchKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
    ///
    /// let levels = DecompositionLevelCount(10);
    /// let base_log = DecompositionBaseLog(16);
    /// let input_dimension = LweDimension(15);
    /// let output_dimension = LweDimension(20);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let ksk: LweSeededKeyswitchKey<Vec<u64>> = LweSeededKeyswitchKey::allocate(
    ///     levels,
    ///     base_log,
    ///     input_dimension,
    ///     output_dimension,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(ksk.decomposition_level_count(), levels);
    /// assert_eq!(ksk.decomposition_base_log(), base_log);
    /// assert_eq!(ksk.input_lwe_dimension(), input_dimension);
    /// assert_eq!(ksk.output_lwe_dimension(), output_dimension);
    /// assert_eq!(ksk.compression_seed(), compression_seed);
    /// ```
    pub fn allocate(
        decomp_level_count: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
        input_dimension: LweDimension,
        output_dimension: LweDimension,
        compression_seed: CompressionSeed,
    ) -> Self {
        Self {
            tensor: Tensor::from_container(vec![
                Scalar::ZERO;
                decomp_level_count.0 * input_dimension.0
            ]),
            decomp_base_log,
            decomp_level_count,
            lwe_size: output_dimension.to_lwe_size(),
            compression_seed,
        }
    }
}

impl<Cont> LweSeededKeyswitchKey<Cont> {
    /// Return the LWE dimension of the output key.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededKeyswitchKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
    ///
    /// let levels = DecompositionLevelCount(10);
    /// let base_log = DecompositionBaseLog(16);
    /// let input_dimension = LweDimension(15);
    /// let output_dimension = LweDimension(20);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let ksk: LweSeededKeyswitchKey<Vec<u64>> = LweSeededKeyswitchKey::allocate(
    ///     levels,
    ///     base_log,
    ///     input_dimension,
    ///     output_dimension,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(ksk.output_lwe_dimension(), output_dimension);
    /// ```
    pub fn output_lwe_dimension(&self) -> LweDimension
    where
        Self: AsRefTensor,
    {
        self.lwe_size.to_lwe_dimension()
    }

    /// Returns the LWE dimension of the input key. This is also the LWE dimension of the
    /// ciphertexts encoding each level of decomposition of the input key bits.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededKeyswitchKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
    ///
    /// let levels = DecompositionLevelCount(10);
    /// let base_log = DecompositionBaseLog(16);
    /// let input_dimension = LweDimension(15);
    /// let output_dimension = LweDimension(20);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let ksk: LweSeededKeyswitchKey<Vec<u64>> = LweSeededKeyswitchKey::allocate(
    ///     levels,
    ///     base_log,
    ///     input_dimension,
    ///     output_dimension,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(ksk.input_lwe_dimension(), input_dimension);
    /// ```
    pub fn input_lwe_dimension(&self) -> LweDimension
    where
        Self: AsRefTensor,
    {
        LweDimension(self.as_tensor().len() / self.decomp_level_count.0)
    }

    /// Returns the number of levels used for the decomposition of the input key bits.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededKeyswitchKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
    ///
    /// let levels = DecompositionLevelCount(10);
    /// let base_log = DecompositionBaseLog(16);
    /// let input_dimension = LweDimension(15);
    /// let output_dimension = LweDimension(20);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let ksk: LweSeededKeyswitchKey<Vec<u64>> = LweSeededKeyswitchKey::allocate(
    ///     levels,
    ///     base_log,
    ///     input_dimension,
    ///     output_dimension,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(ksk.decomposition_level_count(), levels);
    /// ```
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount
    where
        Self: AsRefTensor,
    {
        self.decomp_level_count
    }

    /// Returns the logarithm of the base used for the decomposition of the input key bits.
    ///
    /// Indeed, the basis used is always of the form $2^N$. This function returns $N$.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededKeyswitchKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
    ///
    /// let levels = DecompositionLevelCount(10);
    /// let base_log = DecompositionBaseLog(16);
    /// let input_dimension = LweDimension(15);
    /// let output_dimension = LweDimension(20);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let ksk: LweSeededKeyswitchKey<Vec<u64>> = LweSeededKeyswitchKey::allocate(
    ///     levels,
    ///     base_log,
    ///     input_dimension,
    ///     output_dimension,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(ksk.decomposition_base_log(), base_log);
    /// ```
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog
    where
        Self: AsRefTensor,
    {
        self.decomp_base_log
    }

    /// Fills the current seeded keyswitch key container with an actual seeded keyswitching key
    /// constructed from an input and an output key.
    ///
    /// # Example
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::UnixSeeder;
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededKeyswitchKey;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::LweSecretKey;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::commons::math::tensor::AsRefTensor;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LogStandardDev, LweDimension, LweSize,
    /// };
    ///
    /// let input_size = LweDimension(10);
    /// let output_size = LweDimension(20);
    /// let decomp_log_base = DecompositionBaseLog(3);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let cipher_size = LweSize(55);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut seeder = UnixSeeder::new(0);
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut seeder);
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    ///
    /// let input_key = LweSecretKey::generate_binary(input_size, &mut secret_generator);
    /// let output_key = LweSecretKey::generate_binary(output_size, &mut secret_generator);
    ///
    /// let mut ksk: LweSeededKeyswitchKey<Vec<u32>> = LweSeededKeyswitchKey::allocate(
    ///     decomp_level_count,
    ///     decomp_log_base,
    ///     input_size,
    ///     output_size,
    ///     compression_seed,
    /// );
    ///
    /// ksk.fill_with_seeded_keyswitch_key::<_, _, _, _, _, SoftwareRandomGenerator>(
    ///     &input_key,
    ///     &output_key,
    ///     noise,
    ///     &mut seeder,
    /// );
    ///
    /// assert!(!ksk.as_tensor().iter().all(|a| *a == 0));
    /// ```
    pub fn fill_with_seeded_keyswitch_key<
        InKeyCont,
        OutKeyCont,
        Scalar,
        NoiseParameter,
        NoiseSeeder,
        Gen,
    >(
        &mut self,
        before_key: &LweSecretKey<BinaryKeyKind, InKeyCont>,
        after_key: &LweSecretKey<BinaryKeyKind, OutKeyCont>,
        noise_parameters: NoiseParameter,
        noise_seeder: &mut NoiseSeeder,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        LweSecretKey<BinaryKeyKind, InKeyCont>: AsRefTensor<Element = Scalar>,
        LweSecretKey<BinaryKeyKind, OutKeyCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        NoiseParameter: DispersionParameter,
        NoiseSeeder: Seeder,
        Gen: ByteRandomGenerator,
    {
        // We instantiate a buffer
        let mut messages = PlaintextList::from_container(vec![
            <Self as AsMutTensor>::Element::ZERO;
            self.decomp_level_count.0
        ]);

        // We retrieve decomposition arguments
        let decomp_level_count = self.decomp_level_count;
        let decomp_base_log = self.decomp_base_log;

        let mut generator =
            EncryptionRandomGenerator::<Gen>::new(self.compression_seed.seed, noise_seeder);

        // loop over the before key blocks
        for (input_key_bit, keyswitch_key_block) in before_key
            .as_tensor()
            .iter()
            .zip(self.bit_decomp_iter_mut())
        {
            // We reset the buffer
            messages
                .as_mut_tensor()
                .fill_with_element(<Self as AsMutTensor>::Element::ZERO);

            // We fill the buffer with the powers of the key bits
            for (level, message) in (1..=decomp_level_count.0)
                .map(DecompositionLevel)
                .zip(messages.plaintext_iter_mut())
            {
                *message = Plaintext(
                    DecompositionTerm::new(level, decomp_base_log, *input_key_bit)
                        .to_recomposition_summand(),
                );
            }

            // We encrypt the buffer
            after_key.encrypt_seeded_lwe_list_with_existing_generator::<_, _, _, _, Gen>(
                &mut keyswitch_key_block.into_seeded_lwe_list(),
                &messages,
                noise_parameters,
                &mut generator,
            );
        }
    }

    /// Iterates over borrowed `SeededLweKeyBitDecomposition` elements.
    ///
    /// One `SeededLweKeyBitDecomposition` being a set of seeded lwe ciphertexts, encrypting under
    /// the output key, the $l$ levels of the signed decomposition of a single bit of the input
    /// key.
    pub(crate) fn bit_decomp_iter(
        &self,
    ) -> impl Iterator<Item = SeededLweKeyBitDecomposition<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.decomp_level_count.0);
        let level_count = self.decomp_level_count.0;
        let lwe_size = self.lwe_size;
        let compression_seed = self.compression_seed();
        self.as_tensor()
            .subtensor_iter(level_count)
            .map(move |sub| {
                SeededLweKeyBitDecomposition::from_container(
                    sub.into_container(),
                    lwe_size,
                    compression_seed,
                )
            })
    }

    /// Iterates over mutably borrowed `SeededLweKeyBitDecomposition` elements.
    ///
    /// One `SeededLweKeyBitDecomposition` being a set of seeded lwe ciphertexts, encrypting under
    /// the output key, the $l$ levels of the signed decomposition of a single bit of the input
    /// key.
    pub(crate) fn bit_decomp_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = SeededLweKeyBitDecomposition<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        ck_dim_div!(self.as_tensor().len() => self.decomp_level_count.0);
        let level_count = self.decomp_level_count.0;
        let lwe_size = self.lwe_size;
        let compression_seed = self.compression_seed();
        self.as_mut_tensor()
            .subtensor_iter_mut(level_count)
            .map(move |sub| {
                SeededLweKeyBitDecomposition::from_container(
                    sub.into_container(),
                    lwe_size,
                    compression_seed,
                )
            })
    }

    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::crypto::lwe::LweSeededKeyswitchKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
    ///
    /// let levels = DecompositionLevelCount(10);
    /// let base_log = DecompositionBaseLog(16);
    /// let input_dimension = LweDimension(15);
    /// let output_dimension = LweDimension(20);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let ksk: LweSeededKeyswitchKey<Vec<u64>> = LweSeededKeyswitchKey::allocate(
    ///     levels,
    ///     base_log,
    ///     input_dimension,
    ///     output_dimension,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(ksk.compression_seed(), compression_seed);
    /// ```
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed
    }

    /// # Example
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::lwe::{LweKeyswitchKey, LweSeededKeyswitchKey};
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
    ///
    /// let levels = DecompositionLevelCount(3);
    /// let base_log = DecompositionBaseLog(5);
    /// let input_dimension = LweDimension(15);
    /// let output_dimension = LweDimension(20);
    /// let compression_seed = CompressionSeed { seed: Seed(42) };
    ///
    /// let ksk: LweSeededKeyswitchKey<Vec<u64>> = LweSeededKeyswitchKey::allocate(
    ///     levels,
    ///     base_log,
    ///     input_dimension,
    ///     output_dimension,
    ///     compression_seed,
    /// );
    ///
    /// let mut output_ksk = LweKeyswitchKey::allocate(
    ///     0,
    ///     ksk.decomposition_level_count(),
    ///     ksk.decomposition_base_log(),
    ///     ksk.input_lwe_dimension(),
    ///     ksk.output_lwe_dimension(),
    /// );
    ///
    /// ksk.expand_into::<_, _, SoftwareRandomGenerator>(&mut output_ksk);
    /// ```
    pub fn expand_into<OutCont, Scalar, Gen>(self, output: &mut LweKeyswitchKey<OutCont>)
    where
        LweKeyswitchKey<OutCont>: AsMutTensor<Element = Scalar>,
        Self: AsRefTensor<Element = Scalar>,
        Scalar: Copy + RandomGenerable<Uniform> + Numeric,
        Gen: ByteRandomGenerator,
    {
        let mut generator = RandomGenerator::<Gen>::new(self.compression_seed.seed);

        for (mut output_tensor, keyswitch_key_block) in output
            .as_mut_tensor()
            // We need enough space for decomp_level_count ciphertexts of size lwe_size
            .subtensor_iter_mut(self.decomp_level_count.0 * self.lwe_size.0)
            .zip(self.bit_decomp_iter())
        {
            let mut lwe_list = LweList::from_container(output_tensor.as_mut_slice(), self.lwe_size);
            keyswitch_key_block
                .into_seeded_lwe_list()
                .expand_into_with_existing_generator::<_, _, Gen>(&mut lwe_list, &mut generator);
        }
    }
}

/// The encryption of a single bit of the output key.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq)]
pub(crate) struct SeededLweKeyBitDecomposition<Cont> {
    pub(super) tensor: Tensor<Cont>,
    pub(super) lwe_size: LweSize,
    pub(super) compression_seed: CompressionSeed,
}

tensor_traits!(SeededLweKeyBitDecomposition);

impl<Cont> SeededLweKeyBitDecomposition<Cont> {
    /// Creates a key bit decomposition from a container.
    ///
    /// # Notes
    ///
    /// This method does not decompose a key bit in a basis, but merely wraps a container in the
    /// right structure. See [`LweSeededKeyswitchKey::bit_decomp_iter`] for an iterator that returns
    /// key bit decompositions.
    pub fn from_container(
        cont: Cont,
        lwe_size: LweSize,
        compression_seed: CompressionSeed,
    ) -> Self {
        SeededLweKeyBitDecomposition {
            tensor: Tensor::from_container(cont),
            lwe_size,
            compression_seed,
        }
    }

    /// Returns the size of the lwe ciphertexts encoding each level of the key bit decomposition.
    #[allow(dead_code)]
    pub fn lwe_size(&self) -> LweSize {
        self.lwe_size
    }

    /// Returns the number of ciphertexts in the decomposition.
    ///
    /// Note that this is actually equals to the number of levels in the decomposition.
    #[allow(dead_code)]
    pub fn count(&self) -> CiphertextCount
    where
        Self: AsRefTensor,
    {
        CiphertextCount(self.as_tensor().len())
    }

    /// Consumes the current key bit decomposition and returns a seeded lwe list.
    ///
    /// Note that this operation is super cheap, as it merely rewraps the current container in a
    /// seeded lwe list structure.
    pub fn into_seeded_lwe_list(self) -> LweSeededList<Cont>
    where
        Cont: AsRefSlice,
    {
        LweSeededList::from_container(
            self.tensor.into_container(),
            self.lwe_size.to_lwe_dimension(),
            self.compression_seed,
        )
    }
}
