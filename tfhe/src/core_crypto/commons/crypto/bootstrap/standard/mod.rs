use crate::core_crypto::commons::crypto::encoding::Plaintext;
use crate::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
use crate::core_crypto::commons::crypto::secret::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
use crate::core_crypto::commons::math::polynomial::Polynomial;
use crate::core_crypto::commons::math::random::ByteRandomGenerator;
#[cfg(feature = "__commons_parallel")]
use crate::core_crypto::commons::math::random::ParallelByteRandomGenerator;
use crate::core_crypto::commons::math::tensor::{
    ck_dim_div, ck_dim_eq, tensor_traits, AsMutTensor, AsRefSlice, AsRefTensor, Container, Tensor,
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

/// A bootstrapping key represented in the standard domain.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardBootstrapKey<Cont> {
    pub(crate) tensor: Tensor<Cont>,
    poly_size: PolynomialSize,
    rlwe_size: GlweSize,
    decomp_level: DecompositionLevelCount,
    decomp_base_log: DecompositionBaseLog,
}

tensor_traits!(StandardBootstrapKey);

impl<Scalar> StandardBootstrapKey<Vec<Scalar>> {
    /// Allocates a new bootstrapping key in the standard domain whose polynomials coefficients are
    /// all `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(bsk.polynomial_size(), PolynomialSize(9));
    /// assert_eq!(bsk.glwe_size(), GlweSize(7));
    /// assert_eq!(bsk.level_count(), DecompositionLevelCount(3));
    /// assert_eq!(bsk.base_log(), DecompositionBaseLog(5));
    /// assert_eq!(bsk.key_size(), LweDimension(4));
    /// ```
    pub fn allocate(
        value: Scalar,
        rlwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomp_level: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
        key_size: LweDimension,
    ) -> StandardBootstrapKey<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
    {
        StandardBootstrapKey {
            tensor: Tensor::from_container(vec![
                value;
                key_size.0
                    * decomp_level.0
                    * rlwe_size.0
                    * rlwe_size.0
                    * poly_size.0
            ]),
            decomp_level,
            decomp_base_log,
            rlwe_size,
            poly_size,
        }
    }
}

impl<Cont> StandardBootstrapKey<Cont> {
    /// Creates a bootstrapping key from an existing container of values.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let vector = vec![0u32; 10 * 5 * 4 * 4 * 15];
    /// let bsk = StandardBootstrapKey::from_container(
    ///     vector.as_slice(),
    ///     GlweSize(4),
    ///     PolynomialSize(10),
    ///     DecompositionLevelCount(5),
    ///     DecompositionBaseLog(4),
    /// );
    /// assert_eq!(bsk.polynomial_size(), PolynomialSize(10));
    /// assert_eq!(bsk.glwe_size(), GlweSize(4));
    /// assert_eq!(bsk.level_count(), DecompositionLevelCount(5));
    /// assert_eq!(bsk.base_log(), DecompositionBaseLog(4));
    /// assert_eq!(bsk.key_size(), LweDimension(15));
    /// ```
    pub fn from_container<Coef>(
        cont: Cont,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomp_level: DecompositionLevelCount,
        decomp_base_log: DecompositionBaseLog,
    ) -> StandardBootstrapKey<Cont>
    where
        Cont: AsRefSlice<Element = Coef>,
    {
        let tensor = Tensor::from_container(cont);
        ck_dim_div!(tensor.len() =>
            decomp_level.0,
            glwe_size.0 * glwe_size.0,
            poly_size.0
        );
        StandardBootstrapKey {
            tensor,
            rlwe_size: glwe_size,
            poly_size,
            decomp_level,
            decomp_base_log,
        }
    }

    pub fn into_container(self) -> Cont {
        self.tensor.into_container()
    }

    pub fn as_view(&self) -> StandardBootstrapKey<&'_ [Cont::Element]>
    where
        Cont: Container,
    {
        StandardBootstrapKey {
            tensor: Tensor::from_container(self.tensor.as_container().as_ref()),
            rlwe_size: self.rlwe_size,
            poly_size: self.poly_size,
            decomp_level: self.decomp_level,
            decomp_base_log: self.decomp_base_log,
        }
    }

    pub fn as_mut_view(&mut self) -> StandardBootstrapKey<&'_ mut [Cont::Element]>
    where
        Cont: Container,
        Cont: AsMut<[Cont::Element]>,
    {
        StandardBootstrapKey {
            tensor: Tensor::from_container(self.tensor.as_mut_container().as_mut()),
            rlwe_size: self.rlwe_size,
            poly_size: self.poly_size,
            decomp_level: self.decomp_level,
            decomp_base_log: self.decomp_base_log,
        }
    }

    /// Generate a new bootstrap key from the input parameters, and fills the current container
    /// with it.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LogStandardDev, LweDimension,
    ///     PolynomialSize,
    /// };
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    ///
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(9));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let mut bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     glwe_dim.to_glwe_size(),
    ///     poly_size,
    ///     dec_lc,
    ///     dec_bl,
    ///     lwe_dim,
    /// );
    /// let lwe_sk = LweSecretKey::generate_binary(lwe_dim, &mut secret_generator);
    /// let glwe_sk = GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);
    /// bsk.fill_with_new_key(
    ///     &lwe_sk,
    ///     &glwe_sk,
    ///     LogStandardDev::from_log_standard_dev(-15.),
    ///     &mut encryption_generator,
    /// );
    /// ```
    pub fn fill_with_new_key<LweCont, RlweCont, Scalar, Gen>(
        &mut self,
        lwe_secret_key: &LweSecretKey<BinaryKeyKind, LweCont>,
        glwe_secret_key: &GlweSecretKey<BinaryKeyKind, RlweCont>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        LweSecretKey<BinaryKeyKind, LweCont>: AsRefTensor<Element = Scalar>,
        GlweSecretKey<BinaryKeyKind, RlweCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
    {
        ck_dim_eq!(self.key_size().0 => lwe_secret_key.key_size().0);
        self.as_mut_tensor()
            .fill_with_element(<Scalar as Numeric>::ZERO);

        let gen_iter = generator
            .fork_bsk_to_ggsw::<Scalar>(
                lwe_secret_key.key_size(),
                self.decomp_level,
                glwe_secret_key.key_size().to_glwe_size(),
                self.poly_size,
            )
            .unwrap();

        for zip_args!(mut rgsw, sk_scalar, mut generator) in zip!(
            self.ggsw_iter_mut(),
            lwe_secret_key.as_tensor().iter(),
            gen_iter
        ) {
            let encoded = Plaintext(*sk_scalar);
            glwe_secret_key.encrypt_constant_ggsw(
                &mut rgsw,
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
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LogStandardDev, LweDimension,
    ///     PolynomialSize,
    /// };
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(9));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let mut bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     glwe_dim.to_glwe_size(),
    ///     poly_size,
    ///     dec_lc,
    ///     dec_bl,
    ///     lwe_dim,
    /// );
    /// let lwe_sk = LweSecretKey::generate_binary(lwe_dim, &mut secret_generator);
    /// let glwe_sk = GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);
    /// let mut secret_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// bsk.par_fill_with_new_key(
    ///     &lwe_sk,
    ///     &glwe_sk,
    ///     LogStandardDev::from_log_standard_dev(-15.),
    ///     &mut secret_generator,
    /// );
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_fill_with_new_key<LweCont, RlweCont, Scalar, Gen>(
        &mut self,
        lwe_secret_key: &LweSecretKey<BinaryKeyKind, LweCont>,
        glwe_secret_key: &GlweSecretKey<BinaryKeyKind, RlweCont>,
        noise_parameters: impl DispersionParameter + Sync + Send,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        LweSecretKey<BinaryKeyKind, LweCont>: AsRefTensor<Element = Scalar>,
        GlweSecretKey<BinaryKeyKind, RlweCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus + Sync + Send,
        RlweCont: Sync,
        Gen: ParallelByteRandomGenerator,
    {
        ck_dim_eq!(self.key_size().0 => lwe_secret_key.key_size().0);
        self.as_mut_tensor()
            .fill_with_element(<Scalar as Numeric>::ZERO);
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
            .for_each(|((mut rgsw, sk_scalar), mut generator)| {
                let encoded = Plaintext(*sk_scalar);
                glwe_secret_key.par_encrypt_constant_ggsw(
                    &mut rgsw,
                    &encoded,
                    noise_parameters,
                    &mut generator,
                );
            });
    }

    /// Generate a new bootstrap key from the input parameters, and fills the current container
    /// with it.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LogStandardDev, LweDimension,
    ///     PolynomialSize,
    /// };
    ///
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(9));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// let mut bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     glwe_dim.to_glwe_size(),
    ///     poly_size,
    ///     dec_lc,
    ///     dec_bl,
    ///     lwe_dim,
    /// );
    /// let lwe_sk = LweSecretKey::generate_binary(lwe_dim, &mut secret_generator);
    /// let glwe_sk = GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);
    /// bsk.fill_with_new_trivial_key(
    ///     &lwe_sk,
    ///     &glwe_sk,
    ///     LogStandardDev::from_log_standard_dev(-15.),
    ///     &mut encryption_generator,
    /// );
    /// ```
    pub fn fill_with_new_trivial_key<LweCont, RlweCont, Scalar, Gen>(
        &mut self,
        lwe_secret_key: &LweSecretKey<BinaryKeyKind, LweCont>,
        rlwe_secret_key: &GlweSecretKey<BinaryKeyKind, RlweCont>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsMutTensor<Element = Scalar>,
        LweSecretKey<BinaryKeyKind, LweCont>: AsRefTensor<Element = Scalar>,
        GlweSecretKey<BinaryKeyKind, RlweCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
    {
        ck_dim_eq!(self.key_size().0 => lwe_secret_key.key_size().0);
        for (mut rgsw, sk_scalar) in self.ggsw_iter_mut().zip(lwe_secret_key.as_tensor().iter()) {
            let encoded = Plaintext(*sk_scalar);
            rlwe_secret_key.trivial_encrypt_constant_ggsw(
                &mut rgsw,
                &encoded,
                noise_parameters,
                generator,
            );
        }
    }

    /// Returns the size of the polynomials used in the bootstrapping key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
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
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(bsk.glwe_size(), GlweSize(7));
    /// ```
    pub fn glwe_size(&self) -> GlweSize {
        self.rlwe_size
    }

    /// Returns the number of levels used to decompose the key bits.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(bsk.level_count(), DecompositionLevelCount(3));
    /// ```
    pub fn level_count(&self) -> DecompositionLevelCount {
        self.decomp_level
    }

    /// Returns the logarithm of the base used to decompose the key bits.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(bsk.base_log(), DecompositionBaseLog(5));
    /// ```
    pub fn base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Returns the size of the LWE encrypted key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// assert_eq!(bsk.key_size(), LweDimension(4));
    /// ```
    pub fn key_size(&self) -> LweDimension
    where
        Self: AsRefTensor,
    {
        ck_dim_div!(self.as_tensor().len() =>
            self.poly_size.0,
            self.rlwe_size.0 * self.rlwe_size.0,
            self.decomp_level.0
        );
        LweDimension(
            self.as_tensor().len()
                / (self.rlwe_size.0 * self.rlwe_size.0 * self.poly_size.0 * self.decomp_level.0),
        )
    }

    /// Returns an iterator over the borrowed GGSW ciphertext composing the key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
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
    ) -> impl Iterator<Item = StandardGgswCiphertext<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        let chunks_size =
            self.rlwe_size.0 * self.rlwe_size.0 * self.poly_size.0 * self.decomp_level.0;
        let rlwe_size = self.rlwe_size;
        let poly_size = self.poly_size;
        let base_log = self.decomp_base_log;
        self.as_tensor()
            .subtensor_iter(chunks_size)
            .map(move |tensor| {
                StandardGgswCiphertext::from_container(
                    tensor.into_container(),
                    rlwe_size,
                    poly_size,
                    base_log,
                )
            })
    }

    /// Returns a parallel iterator over the mutably borrowed GGSW ciphertext composing the
    /// key.
    ///
    /// # Notes
    ///
    /// This iterator is hidden behind the "__commons_parallel" feature gate.
    ///
    /// # Example
    ///
    /// ```
    /// use rayon::iter::ParallelIterator;
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let mut bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// bsk.par_ggsw_iter_mut().for_each(|mut ggsw| {
    ///     ggsw.as_mut_tensor().fill_with_element(0);
    /// });
    /// assert!(bsk.as_tensor().iter().all(|a| *a == 0));
    /// assert_eq!(bsk.ggsw_iter_mut().count(), 4);
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_ggsw_iter_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = StandardGgswCiphertext<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
        <Self as AsRefTensor>::Element: Sync + Send,
    {
        let chunks_size =
            self.rlwe_size.0 * self.rlwe_size.0 * self.poly_size.0 * self.decomp_level.0;
        let rlwe_size = self.rlwe_size;
        let poly_size = self.poly_size;
        let base_log = self.decomp_base_log;

        self.as_mut_tensor()
            .par_subtensor_iter_mut(chunks_size)
            .map(move |tensor| {
                StandardGgswCiphertext::from_container(
                    tensor.into_container(),
                    rlwe_size,
                    poly_size,
                    base_log,
                )
            })
    }

    /// Returns an iterator over the mutably borrowed GGSW ciphertext composing the key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let mut bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(9),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// for mut ggsw in bsk.ggsw_iter_mut() {
    ///     ggsw.as_mut_tensor().fill_with_element(0);
    /// }
    /// assert!(bsk.as_tensor().iter().all(|a| *a == 0));
    /// assert_eq!(bsk.ggsw_iter_mut().count(), 4);
    /// ```
    pub fn ggsw_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = StandardGgswCiphertext<&mut [<Self as AsRefTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        let chunks_size =
            self.rlwe_size.0 * self.rlwe_size.0 * self.poly_size.0 * self.decomp_level.0;
        let rlwe_size = self.rlwe_size;
        let poly_size = self.poly_size;
        let base_log = self.decomp_base_log;
        self.as_mut_tensor()
            .subtensor_iter_mut(chunks_size)
            .map(move |tensor| {
                StandardGgswCiphertext::from_container(
                    tensor.into_container(),
                    rlwe_size,
                    poly_size,
                    base_log,
                )
            })
    }

    /// Returns an iterator over borrowed polynomials composing the key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// for poly in bsk.poly_iter() {
    ///     assert_eq!(poly.polynomial_size(), PolynomialSize(256));
    /// }
    /// assert_eq!(bsk.poly_iter().count(), 7 * 7 * 3 * 4)
    /// ```
    pub fn poly_iter(&self) -> impl Iterator<Item = Polynomial<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
        <Self as AsRefTensor>::Element: UnsignedTorus,
    {
        let poly_size = self.poly_size.0;
        self.as_tensor()
            .subtensor_iter(poly_size)
            .map(|chunk| Polynomial::from_container(chunk.into_container()))
    }

    /// Returns an iterator over mutably borrowed polynomials composing the key.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    /// };
    /// let mut bsk = StandardBootstrapKey::allocate(
    ///     9u32,
    ///     GlweSize(7),
    ///     PolynomialSize(256),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(5),
    ///     LweDimension(4),
    /// );
    /// for mut poly in bsk.poly_iter_mut() {
    ///     poly.as_mut_tensor().fill_with_element(0u32);
    /// }
    /// assert!(bsk.as_tensor().iter().all(|a| *a == 0));
    /// assert_eq!(bsk.poly_iter_mut().count(), 7 * 7 * 3 * 4)
    /// ```
    pub fn poly_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = Polynomial<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
        <Self as AsMutTensor>::Element: UnsignedTorus,
    {
        let poly_size = self.poly_size.0;
        self.as_mut_tensor()
            .subtensor_iter_mut(poly_size)
            .map(|chunk| Polynomial::from_container(chunk.into_container()))
    }
}
