use super::StandardBootstrapKey;
use crate::core_crypto::commons::crypto::encoding::Plaintext;
use crate::core_crypto::commons::crypto::ggsw::StandardGgswSeededCiphertext;
use crate::core_crypto::commons::crypto::secret::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
#[cfg(feature = "__commons_parallel")]
use crate::core_crypto::commons::math::random::ParallelByteRandomGenerator;
use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, CompressionSeed, RandomGenerable, RandomGenerator, Seeder, Uniform,
};
use crate::core_crypto::commons::math::tensor::{
    ck_dim_div, ck_dim_eq, tensor_traits, AsMutTensor, AsRefSlice, AsRefTensor, Tensor,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::commons::utils::{zip, zip_args};
use crate::core_crypto::prelude::{
    BinaryKeyKind, DecompositionBaseLog, DecompositionLevelCount, DispersionParameter, GlweSize,
    LweDimension, PolynomialSize,
};
#[cfg(feature = "__commons_parallel")]
use rayon::{iter::IndexedParallelIterator, prelude::*};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

/// A seeded bootstrapping key represented in the standard domain.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardSeededBootstrapKey<Cont> {
    tensor: Tensor<Cont>,
    poly_size: PolynomialSize,
    glwe_size: GlweSize,
    decomp_level: DecompositionLevelCount,
    decomp_base_log: DecompositionBaseLog,
    compression_seed: CompressionSeed,
}

tensor_traits!(StandardSeededBootstrapKey);

impl<Scalar> StandardSeededBootstrapKey<Vec<Scalar>> {
    /// Allocates a new seeded bootstrapping key in the standard domain whose polynomials
    /// coefficients are all `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardSeededBootstrapKey::<Vec<u32>>::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    /// assert_eq!(bsk.polynomial_size(), PolynomialSize(9));
    /// assert_eq!(bsk.glwe_size(), GlweSize(7));
    /// assert_eq!(bsk.level_count(), DecompositionLevelCount(3));
    /// assert_eq!(bsk.base_log(), DecompositionBaseLog(5));
    /// assert_eq!(bsk.key_size(), LweDimension(4));
    /// assert_eq!(bsk.compression_seed(), CompressionSeed { seed: Seed(42) });
    /// ```
    pub fn allocate(
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomp_level: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
        key_size: LweDimension,
        compression_seed: CompressionSeed,
    ) -> Self
    where
        Scalar: UnsignedTorus,
    {
        StandardSeededBootstrapKey {
            tensor: Tensor::from_container(vec![
                Scalar::ZERO;
                key_size.0
                    * decomp_level.0
                    * glwe_size.0
                    * poly_size.0
            ]),
            decomp_level,
            decomp_base_log,
            glwe_size,
            poly_size,
            compression_seed,
        }
    }
}

impl<Cont> StandardSeededBootstrapKey<Cont> {
    /// Creates a seeded bootstrapping key from an existing container of values.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    ///
    /// let key_size = LweDimension(4);
    /// let decomp_level = DecompositionLevelCount(3);
    /// let decomp_base_log = DecompositionBaseLog(5);
    /// let glwe_size = GlweSize(7);
    /// let poly_size = PolynomialSize(9);
    ///
    /// let container = vec![0u32; key_size.0 * decomp_level.0 * glwe_size.0 * poly_size.0];
    ///
    /// let bsk = StandardSeededBootstrapKey::from_container(
    ///     container,
    ///     glwe_size,
    ///     poly_size,
    ///     decomp_level,
    ///     decomp_base_log,
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    /// assert_eq!(bsk.polynomial_size(), PolynomialSize(9));
    /// assert_eq!(bsk.glwe_size(), GlweSize(7));
    /// assert_eq!(bsk.level_count(), DecompositionLevelCount(3));
    /// assert_eq!(bsk.base_log(), DecompositionBaseLog(5));
    /// assert_eq!(bsk.key_size(), LweDimension(4));
    /// assert_eq!(bsk.compression_seed(), CompressionSeed { seed: Seed(42) });
    /// ```
    pub fn from_container<Coef>(
        cont: Cont,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomp_level: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
        compression_seed: CompressionSeed,
    ) -> Self
    where
        Cont: AsRefSlice<Element = Coef>,
        Coef: UnsignedTorus,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() =>
            decomp_level.0,
            glwe_size.0,
            poly_size.0
        );
        StandardSeededBootstrapKey {
            tensor,
            glwe_size,
            poly_size,
            decomp_level,
            decomp_base_log,
            compression_seed,
        }
    }

    /// Generate a new seeded bootstrap key from the input parameters, and fills the current
    /// container with it.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use tfhe::core_crypto::commons::math::random::CompressionSeed;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LogStandardDev, LweDimension,
    ///     PolynomialSize,
    /// };
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut seeder = UnixSeeder::new(0);
    ///
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(9));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let mut bsk = StandardSeededBootstrapKey::<Vec<u32>>::allocate(
    ///     glwe_dim.to_glwe_size(),
    ///     poly_size,
    ///     dec_lc,
    ///     dec_bl,
    ///     lwe_dim,
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    /// let lwe_sk = LweSecretKey::generate_binary(lwe_dim, &mut secret_generator);
    /// let glwe_sk = GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);
    /// bsk.fill_with_new_key::<_, _, _, _, _, SoftwareRandomGenerator>(
    ///     &lwe_sk,
    ///     &glwe_sk,
    ///     LogStandardDev::from_log_standard_dev(-15.),
    ///     &mut seeder,
    /// );
    /// ```
    pub fn fill_with_new_key<LweCont, GlweCont, Scalar, NoiseParameters, NoiseSeeder, Gen>(
        &mut self,
        lwe_secret_key: &LweSecretKey<BinaryKeyKind, LweCont>,
        glwe_secret_key: &GlweSecretKey<BinaryKeyKind, GlweCont>,
        noise_parameters: NoiseParameters,
        seeder: &mut NoiseSeeder,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        LweSecretKey<BinaryKeyKind, LweCont>: AsRefTensor<Element = Scalar>,
        GlweSecretKey<BinaryKeyKind, GlweCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        NoiseParameters: DispersionParameter,
        NoiseSeeder: Seeder,
        Gen: ByteRandomGenerator,
    {
        ck_dim_eq!(self.key_size().0 => lwe_secret_key.key_size().0);
        self.as_mut_tensor()
            .fill_with_element(<Scalar as Numeric>::ZERO);

        let mut generator =
            EncryptionRandomGenerator::<Gen>::new(self.compression_seed().seed, seeder);

        let gen_iter = generator
            .fork_bsk_to_ggsw::<Scalar>(
                lwe_secret_key.key_size(),
                self.decomp_level,
                glwe_secret_key.key_size().to_glwe_size(),
                self.poly_size,
            )
            .unwrap();

        for zip_args!(mut ggsw, sk_scalar, mut generator) in zip!(
            self.ggsw_iter_mut(),
            lwe_secret_key.as_tensor().iter(),
            gen_iter
        ) {
            let encoded = Plaintext(*sk_scalar);
            glwe_secret_key.encrypt_constant_seeded_ggsw_with_existing_generator(
                &mut ggsw,
                &encoded,
                noise_parameters,
                &mut generator,
            );
        }
    }

    /// Generate a new bootstrap key from the input parameters, and fills the current container
    /// with it, using all the available threads.
    ///
    /// # Note
    ///
    /// This method uses _rayon_ internally, and is hidden behind the "__commons_parallel" feature
    /// gate.
    ///
    /// # Example
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use tfhe::core_crypto::commons::math::random::CompressionSeed;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LogStandardDev, LweDimension,
    ///     PolynomialSize,
    /// };
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut seeder = UnixSeeder::new(0);
    ///
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(9));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let mut bsk = StandardSeededBootstrapKey::<Vec<u32>>::allocate(
    ///     glwe_dim.to_glwe_size(),
    ///     poly_size,
    ///     dec_lc,
    ///     dec_bl,
    ///     lwe_dim,
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    /// let lwe_sk = LweSecretKey::generate_binary(lwe_dim, &mut secret_generator);
    /// let glwe_sk = GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);
    /// bsk.par_fill_with_new_key::<_, _, _, _, _, SoftwareRandomGenerator>(
    ///     &lwe_sk,
    ///     &glwe_sk,
    ///     LogStandardDev::from_log_standard_dev(-15.),
    ///     &mut seeder,
    /// );
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_fill_with_new_key<LweCont, GlweCont, Scalar, NoiseParameters, NoiseSeeder, Gen>(
        &mut self,
        lwe_secret_key: &LweSecretKey<BinaryKeyKind, LweCont>,
        glwe_secret_key: &GlweSecretKey<BinaryKeyKind, GlweCont>,
        noise_parameters: NoiseParameters,
        seeder: &mut NoiseSeeder,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        LweSecretKey<BinaryKeyKind, LweCont>: AsRefTensor<Element = Scalar>,
        GlweSecretKey<BinaryKeyKind, GlweCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus + Sync + Send,
        GlweCont: Sync + Send,
        Cont: Sync + Send,
        NoiseParameters: DispersionParameter + Sync + Send,
        NoiseSeeder: Seeder + Sync + Send,
        Gen: ParallelByteRandomGenerator,
    {
        ck_dim_eq!(self.key_size().0 => lwe_secret_key.key_size().0);
        self.as_mut_tensor()
            .fill_with_element(<Scalar as Numeric>::ZERO);

        let mut generator =
            EncryptionRandomGenerator::<Gen>::new(self.compression_seed().seed, seeder);

        let gen_iter = generator
            .par_fork_bsk_to_ggsw::<Scalar>(
                lwe_secret_key.key_size(),
                self.decomp_level,
                glwe_secret_key.key_size().to_glwe_size(),
                self.poly_size,
            )
            .unwrap();

        self.par_ggsw_iter_mut()
            .zip(lwe_secret_key.as_tensor().par_iter())
            .zip(gen_iter)
            .for_each(|((mut ggsw, sk_scalar), mut generator)| {
                let encoded = Plaintext(*sk_scalar);
                glwe_secret_key.par_encrypt_constant_seeded_ggsw_with_existing_generator(
                    &mut ggsw,
                    &encoded,
                    noise_parameters,
                    &mut generator,
                );
            });
    }

    /// Returns the size of the polynomials used in the bootstrapping key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardSeededBootstrapKey::<Vec<u32>>::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    ///
    /// assert_eq!(bsk.polynomial_size(), PolynomialSize(9));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns the size of the GLWE ciphertexts used in the bootstrapping key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardSeededBootstrapKey::<Vec<u32>>::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    ///
    /// assert_eq!(bsk.glwe_size(), GlweSize(7));
    /// ```
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the number of levels used to decompose the key bits.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardSeededBootstrapKey::<Vec<u32>>::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    ///
    /// assert_eq!(bsk.level_count(), DecompositionLevelCount(3));
    /// ```
    pub fn level_count(&self) -> DecompositionLevelCount {
        self.decomp_level
    }

    /// Returns the logarithm of the base used to decompose the key bits.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardSeededBootstrapKey::<Vec<u32>>::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    ///
    /// assert_eq!(bsk.base_log(), DecompositionBaseLog(5));
    /// ```
    pub fn base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Returns the size of the LWE encrypted key.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardSeededBootstrapKey::<Vec<u32>>::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    ///
    /// assert_eq!(bsk.key_size(), LweDimension(4));
    /// ```
    pub fn key_size(&self) -> LweDimension
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() =>
            self.poly_size.0,
            self.glwe_size.0,
            self.decomp_level.0
        );
        LweDimension(
            self.as_tensor().len() / (self.glwe_size.0 * self.poly_size.0 * self.decomp_level.0),
        )
    }

    /// Returns the compression seed used for the seeded entity.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardSeededBootstrapKey::<Vec<u32>>::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    ///
    /// assert_eq!(bsk.compression_seed(), CompressionSeed { seed: Seed(42) });
    /// ```
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed
    }

    /// Returns an iterator over the borrowed seeded GGSW ciphertext composing the key.
    ///
    /// # Example
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardSeededBootstrapKey::<Vec<u32>>::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    /// for ggsw in bsk.ggsw_iter() {
    ///     assert_eq!(ggsw.polynomial_size(), PolynomialSize(9));
    ///     assert_eq!(ggsw.glwe_size(), GlweSize(7));
    ///     assert_eq!(ggsw.decomposition_level_count(), DecompositionLevelCount(3));
    /// }
    /// assert_eq!(bsk.ggsw_iter().count(), 4);
    /// ```
    pub fn ggsw_iter(
        &self,
    ) -> impl Iterator<Item = StandardGgswSeededCiphertext<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        let chunks_size = self.glwe_size.0 * self.poly_size.0 * self.decomp_level.0;
        let glwe_size = self.glwe_size;
        let poly_size = self.poly_size;
        let base_log = self.decomp_base_log;
        let compression_seed = self.compression_seed;
        self.as_tensor()
            .subtensor_iter(chunks_size)
            .map(move |tensor| {
                StandardGgswSeededCiphertext::from_container(
                    tensor.into_container(),
                    poly_size,
                    glwe_size,
                    base_log,
                    compression_seed,
                )
            })
    }

    /// Returns a parallel iterator over the mutably borrowed seeded GGSW ciphertext composing the
    /// key.
    ///
    /// # Notes
    ///
    /// This iterator is hidden behind the "__commons_parallel" feature gate.
    ///
    /// # Example
    /// ```
    /// use rayon::iter::ParallelIterator;
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let mut bsk = StandardSeededBootstrapKey::<Vec<u32>>::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    /// bsk.par_ggsw_iter_mut().for_each(|mut ggsw| {
    ///     ggsw.as_mut_tensor().fill_with_element(1);
    /// });
    /// assert!(bsk.as_tensor().iter().all(|a| *a == 1));
    /// assert_eq!(bsk.ggsw_iter_mut().count(), 4);
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_ggsw_iter_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<
        Item = StandardGgswSeededCiphertext<&mut [<Self as AsRefTensor>::Element]>,
    >
    where
        Self: AsMutTensor,
        <Self as AsRefTensor>::Element: Sync + Send,
        Cont: Sync + Send,
    {
        let chunks_size = self.glwe_size.0 * self.poly_size.0 * self.decomp_level.0;
        let glwe_size = self.glwe_size;
        let poly_size = self.poly_size;
        let base_log = self.decomp_base_log;
        let compression_seed = self.compression_seed;

        self.as_mut_tensor()
            .par_subtensor_iter_mut(chunks_size)
            .map(move |tensor| {
                StandardGgswSeededCiphertext::from_container(
                    tensor.into_container(),
                    poly_size,
                    glwe_size,
                    base_log,
                    compression_seed,
                )
            })
    }

    /// Returns an iterator over the mutably borrowed seeded GGSW ciphertext composing the key.
    ///
    /// # Example
    /// # Example
    /// ```
    /// use rayon::iter::ParallelIterator;
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardSeededBootstrapKey;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let mut bsk = StandardSeededBootstrapKey::<Vec<u32>>::allocate(
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    /// for mut ggsw in bsk.ggsw_iter_mut() {
    ///     ggsw.as_mut_tensor().fill_with_element(1);
    /// }
    /// assert!(bsk.as_tensor().iter().all(|a| *a == 1));
    /// assert_eq!(bsk.ggsw_iter_mut().count(), 4);
    /// ```
    pub fn ggsw_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = StandardGgswSeededCiphertext<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        let chunks_size = self.glwe_size.0 * self.poly_size.0 * self.decomp_level.0;
        let glwe_size = self.glwe_size;
        let poly_size = self.poly_size;
        let base_log = self.decomp_base_log;
        let compression_seed = self.compression_seed;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(move |tensor| {
                StandardGgswSeededCiphertext::from_container(
                    tensor.into_container(),
                    poly_size,
                    glwe_size,
                    base_log,
                    compression_seed,
                )
            })
    }

    /// Returns the key as a full fledged StandardBootstrapKey
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::bootstrap::{
    ///     StandardBootstrapKey, StandardSeededBootstrapKey,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use tfhe::core_crypto::commons::math::random::CompressionSeed;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LogStandardDev,
    ///     LweDimension, PolynomialSize,
    /// };
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut seeder = UnixSeeder::new(0);
    ///
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(9));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let mut seeded_bsk = StandardSeededBootstrapKey::<Vec<u32>>::allocate(
    ///     glwe_dim.to_glwe_size(),
    ///     poly_size,
    ///     dec_lc,
    ///     dec_bl,
    ///     lwe_dim,
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    /// let lwe_sk = LweSecretKey::generate_binary(lwe_dim, &mut secret_generator);
    /// let glwe_sk = GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);
    /// seeded_bsk.fill_with_new_key::<_, _, _, _, _, SoftwareRandomGenerator>(
    ///     &lwe_sk,
    ///     &glwe_sk,
    ///     LogStandardDev::from_log_standard_dev(-15.),
    ///     &mut seeder,
    /// );
    ///
    /// // expansion of the bootstrapping key
    /// let mut coef_bsk_expanded = StandardBootstrapKey::allocate(
    ///     0u32,
    ///     glwe_dim.to_glwe_size(),
    ///     poly_size,
    ///     dec_lc,
    ///     dec_bl,
    ///     lwe_dim,
    /// );
    /// seeded_bsk.expand_into::<_, _, SoftwareRandomGenerator>(&mut coef_bsk_expanded);
    /// ```
    pub fn expand_into<Scalar, OutCont, Gen>(self, output: &mut StandardBootstrapKey<OutCont>)
    where
        Scalar: Copy + RandomGenerable<Uniform> + Numeric,
        StandardBootstrapKey<OutCont>: AsMutTensor<Element = Scalar>,
        Self: AsRefTensor<Element = Scalar>,
        Gen: ByteRandomGenerator,
    {
        let mut generator = RandomGenerator::<Gen>::new(self.compression_seed().seed);

        output
            .ggsw_iter_mut()
            .zip(self.ggsw_iter())
            .for_each(|(mut ggsw_out, ggsw_in)| {
                ggsw_in.expand_into_with_existing_generator(&mut ggsw_out, &mut generator);
            });
    }
}
