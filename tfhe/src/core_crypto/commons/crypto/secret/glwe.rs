use crate::core_crypto::commons::crypto::encoding::{Plaintext, PlaintextList};
use crate::core_crypto::commons::crypto::ggsw::{
    StandardGgswCiphertext, StandardGgswSeededCiphertext,
};
use crate::core_crypto::commons::crypto::glwe::{
    GlweBody, GlweCiphertext, GlweList, GlweMask, GlweSeededCiphertext, GlweSeededList,
};
use crate::core_crypto::commons::crypto::secret::generators::{
    EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::commons::crypto::secret::LweSecretKey;
use crate::core_crypto::commons::math::polynomial::PolynomialList;
#[cfg(feature = "__commons_parallel")]
use crate::core_crypto::commons::math::random::ParallelByteRandomGenerator;
use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, Gaussian, RandomGenerable, Seeder,
};
use crate::core_crypto::commons::math::tensor::{
    ck_dim_div, ck_dim_eq, AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, IntoTensor, Tensor,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::prelude::{
    BinaryKeyKind, DispersionParameter, GaussianKeyKind, GlweDimension, KeyKind, PlaintextCount,
    PolynomialSize, TernaryKeyKind, UniformKeyKind,
};
#[cfg(feature = "__commons_parallel")]
use rayon::{iter::IndexedParallelIterator, prelude::*};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::ops::Add;

/// A GLWE secret key
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweSecretKey<Kind, Container>
where
    Kind: KeyKind,
{
    tensor: Tensor<Container>,
    poly_size: PolynomialSize,
    kind: PhantomData<Kind>,
}

impl<Scalar> GlweSecretKey<BinaryKeyKind, Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    /// Allocates a container for a new key, and fills it with random binary values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{BinaryKeyKind, GlweDimension, PolynomialSize};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: GlweSecretKey<BinaryKeyKind, Vec<u32>> =
    ///     GlweSecretKey::generate_binary(GlweDimension(256), PolynomialSize(10), &mut generator);
    /// assert_eq!(secret_key.key_size(), GlweDimension(256));
    /// assert_eq!(secret_key.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn generate_binary<Gen: ByteRandomGenerator>(
        dimension: GlweDimension,
        poly_size: PolynomialSize,
        generator: &mut SecretRandomGenerator<Gen>,
    ) -> Self {
        GlweSecretKey {
            tensor: generator.random_binary_tensor(poly_size.0 * dimension.0),
            poly_size,
            kind: PhantomData,
        }
    }
}

impl<Scalar> GlweSecretKey<TernaryKeyKind, Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    /// Allocates a container for a new key, and fill it with random ternary values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, TernaryKeyKind};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: GlweSecretKey<_, Vec<u32>> = GlweSecretKey::generate_ternary(
    ///     GlweDimension(256),
    ///     PolynomialSize(10),
    ///     &mut secret_generator,
    /// );
    /// assert_eq!(secret_key.key_size(), GlweDimension(256));
    /// assert_eq!(secret_key.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn generate_ternary<Gen: ByteRandomGenerator>(
        dimension: GlweDimension,
        poly_size: PolynomialSize,
        generator: &mut SecretRandomGenerator<Gen>,
    ) -> Self {
        GlweSecretKey {
            tensor: generator.random_ternary_tensor(poly_size.0 * dimension.0),
            poly_size,
            kind: PhantomData,
        }
    }
}

impl<Scalar> GlweSecretKey<GaussianKeyKind, Vec<Scalar>>
where
    (Scalar, Scalar): RandomGenerable<Gaussian<f64>>,
    Scalar: UnsignedTorus,
{
    /// Allocates a container for a new key, and fill it with random gaussian values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{GaussianKeyKind, GlweDimension, LweDimension, PolynomialSize};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: GlweSecretKey<GaussianKeyKind, Vec<u32>> = GlweSecretKey::generate_gaussian(
    ///     GlweDimension(256),
    ///     PolynomialSize(10),
    ///     &mut secret_generator,
    /// );
    /// assert_eq!(secret_key.key_size(), GlweDimension(256));
    /// assert_eq!(secret_key.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn generate_gaussian<Gen: ByteRandomGenerator>(
        dimension: GlweDimension,
        poly_size: PolynomialSize,
        generator: &mut SecretRandomGenerator<Gen>,
    ) -> Self {
        GlweSecretKey {
            tensor: generator.random_gaussian_tensor(poly_size.0 * dimension.0),
            poly_size,
            kind: PhantomData,
        }
    }
}

impl<Scalar> GlweSecretKey<UniformKeyKind, Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    /// Allocates a container for a new key, and fill it with random uniform values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, UniformKeyKind};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: GlweSecretKey<UniformKeyKind, Vec<u32>> = GlweSecretKey::generate_uniform(
    ///     GlweDimension(256),
    ///     PolynomialSize(10),
    ///     &mut secret_generator,
    /// );
    /// assert_eq!(secret_key.key_size(), GlweDimension(256));
    /// assert_eq!(secret_key.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn generate_uniform<Gen: ByteRandomGenerator>(
        dimension: GlweDimension,
        poly_size: PolynomialSize,
        generator: &mut SecretRandomGenerator<Gen>,
    ) -> Self {
        GlweSecretKey {
            tensor: generator.random_uniform_tensor(poly_size.0 * dimension.0),
            poly_size,
            kind: PhantomData,
        }
    }
}

impl<Cont> GlweSecretKey<BinaryKeyKind, Cont> {
    /// Creates a binary key from a container.
    ///
    /// # Notes
    ///
    /// This method does not fill the container with random data. It merely wraps the container in
    /// the appropriate type. For a method that generate a new random key see
    /// [`GlweSecretKey::generate_binary`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize};
    /// let secret_key =
    ///     GlweSecretKey::binary_from_container(vec![0 as u8; 11 * 256], PolynomialSize(11));
    /// assert_eq!(secret_key.key_size(), GlweDimension(256));
    /// assert_eq!(secret_key.polynomial_size(), PolynomialSize(11));
    /// ```
    pub fn binary_from_container(cont: Cont, poly_size: PolynomialSize) -> Self
    where
        Cont: AsRefSlice,
    {
        ck_dim_div!(cont.as_slice().len() => poly_size.0);
        GlweSecretKey {
            tensor: Tensor::from_container(cont),
            poly_size,
            kind: PhantomData,
        }
    }
}

impl<Cont> GlweSecretKey<TernaryKeyKind, Cont> {
    /// Creates a ternary key from a container.
    ///
    /// # Notes
    ///
    /// This method does not fill the container with random data. It merely wraps the container in
    /// the appropriate type. For a method that generate a new random key see
    /// [`GlweSecretKey::generate_ternary`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize};
    /// let secret_key =
    ///     GlweSecretKey::ternary_from_container(vec![0 as u8; 11 * 256], PolynomialSize(11));
    /// assert_eq!(secret_key.key_size(), GlweDimension(256));
    /// assert_eq!(secret_key.polynomial_size(), PolynomialSize(11));
    /// ```
    pub fn ternary_from_container(cont: Cont, poly_size: PolynomialSize) -> Self
    where
        Cont: AsRefSlice,
    {
        ck_dim_div!(cont.as_slice().len() => poly_size.0);
        GlweSecretKey {
            tensor: Tensor::from_container(cont),
            poly_size,
            kind: PhantomData,
        }
    }
}

impl<Cont> GlweSecretKey<GaussianKeyKind, Cont> {
    /// Creates a gaussian key from a container.
    ///
    /// # Notes
    ///
    /// This method does not fill the container with random data. It merely wraps the container in
    /// the appropriate type. For a method that generate a new random key see
    /// [`GlweSecretKey::generate_gaussian`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize};
    /// let secret_key =
    ///     GlweSecretKey::binary_from_container(vec![0 as u8; 11 * 256], PolynomialSize(11));
    /// assert_eq!(secret_key.key_size(), GlweDimension(256));
    /// assert_eq!(secret_key.polynomial_size(), PolynomialSize(11));
    /// ```
    pub fn gaussian_from_container(cont: Cont, poly_size: PolynomialSize) -> Self
    where
        Cont: AsRefSlice,
    {
        ck_dim_div!(cont.as_slice().len() => poly_size.0);
        GlweSecretKey {
            tensor: Tensor::from_container(cont),
            poly_size,
            kind: PhantomData,
        }
    }
}

impl<Cont> GlweSecretKey<UniformKeyKind, Cont> {
    /// Creates a uniform key from a container.
    ///
    /// # Notes
    ///
    /// This method does not fill the container with random data. It merely wraps the container in
    /// the appropriate type. For a method that generate a new random key see
    /// [`GlweSecretKey::generate_uniform`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize};
    /// let secret_key =
    ///     GlweSecretKey::binary_from_container(vec![0 as u8; 11 * 256], PolynomialSize(11));
    /// assert_eq!(secret_key.key_size(), GlweDimension(256));
    /// assert_eq!(secret_key.polynomial_size(), PolynomialSize(11));
    /// ```
    pub fn uniform_from_container(cont: Cont, poly_size: PolynomialSize) -> Self
    where
        Cont: AsRefSlice,
    {
        ck_dim_div!(cont.as_slice().len() => poly_size.0);
        GlweSecretKey {
            tensor: Tensor::from_container(cont),
            poly_size,
            kind: PhantomData,
        }
    }
}

impl<Kind, Scalar> GlweSecretKey<Kind, Vec<Scalar>>
where
    Kind: KeyKind,
{
    /// Consumes the current GLWE secret key and turns it into an LWE secret key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::GlweSecretKey;
    /// use tfhe::core_crypto::prelude::{GlweDimension, LweDimension, PolynomialSize};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let glwe_secret_key: GlweSecretKey<_, Vec<u32>> =
    ///     GlweSecretKey::generate_binary(GlweDimension(2), PolynomialSize(10), &mut secret_generator);
    /// let lwe_secret_key = glwe_secret_key.into_lwe_secret_key();
    /// assert_eq!(lwe_secret_key.key_size(), LweDimension(20))
    /// ```
    pub fn into_lwe_secret_key(self) -> LweSecretKey<Kind, Vec<Scalar>> {
        LweSecretKey {
            tensor: self.tensor,
            kind: PhantomData,
        }
    }
}

impl<Kind, Cont> GlweSecretKey<Kind, Cont>
where
    Kind: KeyKind,
{
    /// Returns the size of the secret key.
    ///
    /// This is equivalent to the number of masks in the [`GlweCiphertext`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: GlweSecretKey<_, Vec<u32>> = GlweSecretKey::generate_binary(
    ///     GlweDimension(256),
    ///     PolynomialSize(10),
    ///     &mut secret_generator,
    /// );
    /// assert_eq!(secret_key.key_size(), GlweDimension(256));
    /// ```
    pub fn key_size(&self) -> GlweDimension
    where
        Self: AsRefTensor,
    {
        GlweDimension(self.as_tensor().len() / self.poly_size.0)
    }

    /// Returns the size of the secret key polynomials.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: GlweSecretKey<_, Vec<u32>> = GlweSecretKey::generate_binary(
    ///     GlweDimension(256),
    ///     PolynomialSize(10),
    ///     &mut secret_generator,
    /// );
    /// assert_eq!(secret_key.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Returns a borrowed polynomial list from the current key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialCount, PolynomialSize};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: GlweSecretKey<_, Vec<u32>> = GlweSecretKey::generate_binary(
    ///     GlweDimension(256),
    ///     PolynomialSize(10),
    ///     &mut secret_generator,
    /// );
    /// let poly = secret_key.as_polynomial_list();
    /// assert_eq!(poly.polynomial_count(), PolynomialCount(256));
    /// assert_eq!(poly.polynomial_size(), PolynomialSize(10));
    /// ```
    pub fn as_polynomial_list(&self) -> PolynomialList<&[<Self as AsRefTensor>::Element]>
    where
        Self: AsRefTensor,
    {
        PolynomialList::from_container(self.as_tensor().as_slice(), self.poly_size)
    }

    /// Returns a mutably borrowed polynomial list from the current key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut secret_key: GlweSecretKey<_, Vec<u32>> = GlweSecretKey::generate_binary(
    ///     GlweDimension(256),
    ///     PolynomialSize(10),
    ///     &mut secret_generator,
    /// );
    /// let mut poly = secret_key.as_mut_polynomial_list();
    /// poly.as_mut_tensor().fill_with_element(1);
    /// assert!(secret_key.as_tensor().iter().all(|a| *a == 1));
    /// ```
    pub fn as_mut_polynomial_list(
        &mut self,
    ) -> PolynomialList<&mut [<Self as AsRefTensor>::Element]>
    where
        Self: AsMutTensor,
    {
        let poly_size = self.poly_size;
        PolynomialList::from_container(self.as_mut_tensor().as_mut_slice(), poly_size)
    }

    fn fill_glwe_mask_and_body_for_encryption<InputCont, BodyCont, MaskCont, Scalar, Gen>(
        &self,
        mut output_body: GlweBody<BodyCont>,
        mut output_mask: GlweMask<MaskCont>,
        encoded: &PlaintextList<InputCont>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        GlweBody<BodyCont>: AsMutTensor<Element = Scalar>,
        GlweMask<MaskCont>: AsMutTensor<Element = Scalar>,
        PlaintextList<InputCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
    {
        generator.fill_tensor_with_random_noise(&mut output_body, noise_parameters);

        generator.fill_tensor_with_random_mask(&mut output_mask);

        output_body
            .as_mut_polynomial()
            .update_with_wrapping_add_multisum(
                &output_mask.as_polynomial_list(),
                &self.as_polynomial_list(),
            );
        output_body
            .as_mut_polynomial()
            .update_with_wrapping_add(&encoded.as_polynomial());
    }

    /// Encrypts a single GLWE ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::PlaintextList;
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     GlweDimension, GlweSize, LogStandardDev, PolynomialSize,
    /// };
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key = GlweSecretKey::generate_binary(
    ///     GlweDimension(256),
    ///     PolynomialSize(5),
    ///     &mut secret_generator,
    /// );
    /// let noise = LogStandardDev::from_log_standard_dev(-50.);
    /// let plaintexts =
    ///     PlaintextList::from_container(vec![100000 as u32, 200000, 300000, 400000, 500000]);
    /// let mut ciphertext = GlweCiphertext::allocate(0 as u32, PolynomialSize(5), GlweSize(257));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// secret_key.encrypt_glwe(
    ///     &mut ciphertext,
    ///     &plaintexts,
    ///     noise,
    ///     &mut encryption_generator,
    /// );
    /// let mut decrypted = PlaintextList::from_container(vec![0 as u32, 0, 0, 0, 0]);
    /// secret_key.decrypt_glwe(&mut decrypted, &ciphertext);
    /// for (dec, plain) in decrypted.plaintext_iter().zip(plaintexts.plaintext_iter()) {
    ///     let d0 = dec.0.wrapping_sub(plain.0);
    ///     let d1 = plain.0.wrapping_sub(dec.0);
    ///     let dist = std::cmp::min(d0, d1);
    ///     assert!(dist < 400, "dist: {:?}", dist);
    /// }
    /// ```
    pub fn encrypt_glwe<Cont1, Cont2, Scalar, Gen>(
        &self,
        encrypted: &mut GlweCiphertext<Cont1>,
        encoded: &PlaintextList<Cont2>,
        noise_parameter: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        GlweCiphertext<Cont1>: AsMutTensor<Element = Scalar>,
        PlaintextList<Cont2>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
    {
        ck_dim_eq!(encoded.count().0 => encrypted.polynomial_size().0);
        ck_dim_eq!(encrypted.mask_size().0 => self.key_size().0);

        let (body, masks) = encrypted.get_mut_body_and_mask();

        self.fill_glwe_mask_and_body_for_encryption(
            body,
            masks,
            encoded,
            noise_parameter,
            generator,
        );
    }

    pub fn encrypt_seeded_glwe_with_existing_generator<Scalar, Cont1, Cont2, NoiseParameter, Gen>(
        &self,
        encrypted: &mut GlweSeededCiphertext<Cont1>,
        encoded: &PlaintextList<Cont2>,
        noise_parameter: NoiseParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Scalar: UnsignedTorus,
        Self: AsRefTensor<Element = Scalar>,
        GlweSeededCiphertext<Cont1>: AsMutTensor<Element = Scalar>,
        PlaintextList<Cont2>: AsRefTensor<Element = Scalar>,
        NoiseParameter: DispersionParameter,
        Gen: ByteRandomGenerator,
    {
        let masks = GlweMask {
            tensor: Tensor::allocate(Scalar::ZERO, self.polynomial_size().0 * self.key_size().0),
            poly_size: encrypted.polynomial_size(),
        };
        let body = encrypted.get_mut_body();

        self.fill_glwe_mask_and_body_for_encryption(
            body,
            masks,
            encoded,
            noise_parameter,
            generator,
        );
    }

    /// Encrypts a single seeded GLWE ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::PlaintextList;
    /// use tfhe::core_crypto::commons::crypto::glwe::{GlweCiphertext, GlweSeededCiphertext};
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::random::CompressionSeed;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{GlweDimension, GlweSize, LogStandardDev, PolynomialSize};
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key = GlweSecretKey::generate_binary(
    ///     GlweDimension(256),
    ///     PolynomialSize(5),
    ///     &mut secret_generator,
    /// );
    /// let noise = LogStandardDev::from_log_standard_dev(-50.);
    /// let plaintexts =
    ///     PlaintextList::from_container(vec![100000 as u32, 200000, 300000, 400000, 500000]);
    /// let mut seeded_ciphertext = GlweSeededCiphertext::allocate(
    ///     PolynomialSize(5),
    ///     GlweDimension(256),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    /// let mut seeder = UnixSeeder::new(0);
    /// secret_key.encrypt_seeded_glwe::<_, _, _, _, _, SoftwareRandomGenerator>(
    ///     &mut seeded_ciphertext,
    ///     &plaintexts,
    ///     noise,
    ///     &mut seeder,
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
    /// let mut decrypted = PlaintextList::from_container(vec![0 as u32, 0, 0, 0, 0]);
    /// secret_key.decrypt_glwe(&mut decrypted, &ciphertext);
    /// for (dec, plain) in decrypted.plaintext_iter().zip(plaintexts.plaintext_iter()) {
    ///     let d0 = dec.0.wrapping_sub(plain.0);
    ///     let d1 = plain.0.wrapping_sub(dec.0);
    ///     let dist = std::cmp::min(d0, d1);
    ///     assert!(dist < 400, "dist: {:?}", dist);
    /// }
    /// ```
    pub fn encrypt_seeded_glwe<Cont1, Cont2, Scalar, NoiseParameter, NoiseSeeder, Gen>(
        &self,
        encrypted: &mut GlweSeededCiphertext<Cont1>,
        encoded: &PlaintextList<Cont2>,
        noise_parameter: NoiseParameter,
        seeder: &mut NoiseSeeder,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        GlweSeededCiphertext<Cont1>: AsMutTensor<Element = Scalar>,
        PlaintextList<Cont2>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        NoiseParameter: DispersionParameter,
        NoiseSeeder: Seeder,
        Gen: ByteRandomGenerator,
    {
        ck_dim_eq!(encrypted.mask_size().0 => self.key_size().0);

        let mut generator =
            EncryptionRandomGenerator::<Gen>::new(encrypted.compression_seed().seed, seeder);

        self.encrypt_seeded_glwe_with_existing_generator(
            encrypted,
            encoded,
            noise_parameter,
            &mut generator,
        );
    }

    /// Encrypts a zero plaintext into a GLWE ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::PlaintextList;
    /// use tfhe::core_crypto::commons::crypto::glwe::GlweCiphertext;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     GlweDimension, GlweSize, LogStandardDev, PolynomialSize,
    /// };
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key = GlweSecretKey::generate_binary(
    ///     GlweDimension(256),
    ///     PolynomialSize(5),
    ///     &mut secret_generator,
    /// );
    /// let noise = LogStandardDev::from_log_standard_dev(-50.);
    /// let mut ciphertext = GlweCiphertext::allocate(0 as u32, PolynomialSize(5), GlweSize(257));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// secret_key.encrypt_zero_glwe(&mut ciphertext, noise, &mut encryption_generator);
    /// let mut decrypted = PlaintextList::from_container(vec![0 as u32, 0, 0, 0, 0]);
    /// secret_key.decrypt_glwe(&mut decrypted, &ciphertext);
    /// for dec in decrypted.plaintext_iter() {
    ///     let d0 = dec.0.wrapping_sub(0u32);
    ///     let d1 = 0u32.wrapping_sub(dec.0);
    ///     let dist = std::cmp::min(d0, d1);
    ///     assert!(dist < 500, "dist: {:?}", dist);
    /// }
    /// ```
    pub fn encrypt_zero_glwe<Scalar, Cont1, Gen>(
        &self,
        encrypted: &mut GlweCiphertext<Cont1>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        GlweCiphertext<Cont1>: AsMutTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
    {
        ck_dim_eq!(encrypted.mask_size().0 => self.key_size().0);
        let (mut body, mut masks) = encrypted.get_mut_body_and_mask();
        generator.fill_tensor_with_random_noise(&mut body, noise_parameters);
        generator.fill_tensor_with_random_mask(&mut masks);
        body.as_mut_polynomial().update_with_wrapping_add_multisum(
            &masks.as_mut_polynomial_list(),
            &self.as_polynomial_list(),
        );
    }

    /// Encrypts a list of GLWE ciphertexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::PlaintextList;
    /// use tfhe::core_crypto::commons::crypto::glwe::{GlweCiphertext, GlweList};
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, GlweDimension, LogStandardDev, PolynomialSize,
    /// };
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key = GlweSecretKey::generate_binary(
    ///     GlweDimension(256),
    ///     PolynomialSize(2),
    ///     &mut secret_generator,
    /// );
    /// let noise = LogStandardDev::from_log_standard_dev(-60.);
    /// let plaintexts = PlaintextList::from_container(vec![1000 as u32, 2000, 3000, 4000]);
    /// let mut ciphertexts = GlweList::allocate(
    ///     0 as u32,
    ///     PolynomialSize(2),
    ///     GlweDimension(256),
    ///     CiphertextCount(2),
    /// );
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// secret_key.encrypt_glwe_list(
    ///     &mut ciphertexts,
    ///     &plaintexts,
    ///     noise,
    ///     &mut encryption_generator,
    /// );
    /// let mut decrypted = PlaintextList::from_container(vec![0 as u32, 0, 0, 0]);
    /// secret_key.decrypt_glwe_list(&mut decrypted, &ciphertexts);
    /// for (dec, plain) in decrypted.plaintext_iter().zip(plaintexts.plaintext_iter()) {
    ///     let d0 = dec.0.wrapping_sub(plain.0);
    ///     let d1 = plain.0.wrapping_sub(dec.0);
    ///     let dist = std::cmp::min(d0, d1);
    ///     assert!(dist < 400, "dist: {:?}", dist);
    /// }
    /// ```
    pub fn encrypt_glwe_list<CiphCont, EncCont, Scalar, Gen>(
        &self,
        encrypt: &mut GlweList<CiphCont>,
        encoded: &PlaintextList<EncCont>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        GlweList<CiphCont>: AsMutTensor<Element = Scalar>,
        PlaintextList<EncCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        for<'a> PlaintextList<&'a [Scalar]>: AsRefTensor<Element = Scalar>,
        Gen: ByteRandomGenerator,
    {
        ck_dim_eq!(encrypt.ciphertext_count().0 * encrypt.polynomial_size().0 => encoded.count().0);
        ck_dim_eq!(encrypt.glwe_dimension().0 => self.key_size().0);

        let count = PlaintextCount(encrypt.polynomial_size().0);
        for (mut ciphertext, encoded) in encrypt
            .ciphertext_iter_mut()
            .zip(encoded.sublist_iter(count))
        {
            self.encrypt_glwe(&mut ciphertext, &encoded, noise_parameters, generator);
        }
    }

    /// Encrypts a list of seeded GLWE ciphertexts.
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
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key = GlweSecretKey::generate_binary(
    ///     GlweDimension(256),
    ///     PolynomialSize(2),
    ///     &mut secret_generator,
    /// );
    /// let noise = LogStandardDev::from_log_standard_dev(-60.);
    /// let plaintexts = PlaintextList::from_container(vec![1000 as u32, 2000, 3000, 4000]);
    /// let mut seeded_ciphertexts = GlweSeededList::allocate(
    ///     PolynomialSize(2),
    ///     GlweDimension(256),
    ///     CiphertextCount(2),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    /// let mut seeder = UnixSeeder::new(0);
    /// secret_key.encrypt_seeded_glwe_list::<_, _, _, _, _, SoftwareRandomGenerator>(
    ///     &mut seeded_ciphertexts,
    ///     &plaintexts,
    ///     noise,
    ///     &mut seeder,
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
    /// let mut decrypted = PlaintextList::from_container(vec![0 as u32, 0, 0, 0]);
    /// secret_key.decrypt_glwe_list(&mut decrypted, &ciphertexts);
    /// for (dec, plain) in decrypted.plaintext_iter().zip(plaintexts.plaintext_iter()) {
    ///     let d0 = dec.0.wrapping_sub(plain.0);
    ///     let d1 = plain.0.wrapping_sub(dec.0);
    ///     let dist = std::cmp::min(d0, d1);
    ///     assert!(dist < 400, "dist: {:?}", dist);
    /// }
    /// ```
    pub fn encrypt_seeded_glwe_list<CiphCont, EncCont, Scalar, NoiseParameter, NoiseSeeder, Gen>(
        &self,
        encrypt: &mut GlweSeededList<CiphCont>,
        encoded: &PlaintextList<EncCont>,
        noise_parameters: NoiseParameter,
        seeder: &mut NoiseSeeder,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        GlweSeededList<CiphCont>: AsMutTensor<Element = Scalar>,
        PlaintextList<EncCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        for<'a> PlaintextList<&'a [Scalar]>: AsRefTensor<Element = Scalar>,
        NoiseParameter: DispersionParameter,
        NoiseSeeder: Seeder,
        Gen: ByteRandomGenerator,
    {
        ck_dim_eq!(encrypt.ciphertext_count().0 * encrypt.polynomial_size().0 => encoded.count().0);
        ck_dim_eq!(encrypt.glwe_dimension().0 => self.key_size().0);

        let mut generator =
            EncryptionRandomGenerator::<Gen>::new(encrypt.compression_seed().seed, seeder);

        let count = PlaintextCount(encrypt.polynomial_size().0);
        let polynomial_size = encrypt.polynomial_size();
        for (body, encoded) in encrypt.body_iter_mut().zip(encoded.sublist_iter(count)) {
            let masks = GlweMask {
                tensor: Tensor::allocate(
                    Scalar::ZERO,
                    self.polynomial_size().0 * self.key_size().0,
                ),
                poly_size: polynomial_size,
            };

            self.fill_glwe_mask_and_body_for_encryption(
                body,
                masks,
                &encoded,
                noise_parameters,
                &mut generator,
            );
        }
    }

    /// Encrypts a list of GLWE ciphertexts, with a zero plaintext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::PlaintextList;
    /// use tfhe::core_crypto::commons::crypto::glwe::{GlweCiphertext, GlweList};
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, GlweDimension, LogStandardDev, PolynomialSize,
    /// };
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key = GlweSecretKey::generate_binary(
    ///     GlweDimension(256),
    ///     PolynomialSize(2),
    ///     &mut secret_generator,
    /// );
    /// let noise = LogStandardDev::from_log_standard_dev(-60.);
    /// let mut ciphertexts = GlweList::allocate(
    ///     0 as u32,
    ///     PolynomialSize(2),
    ///     GlweDimension(256),
    ///     CiphertextCount(2),
    /// );
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// secret_key.encrypt_zero_glwe_list(&mut ciphertexts, noise, &mut encryption_generator);
    /// let mut decrypted = PlaintextList::from_container(vec![0 as u32, 0, 0, 0]);
    /// secret_key.decrypt_glwe_list(&mut decrypted, &ciphertexts);
    /// for dec in decrypted.plaintext_iter() {
    ///     let d0 = dec.0.wrapping_sub(0u32);
    ///     let d1 = 0u32.wrapping_sub(dec.0);
    ///     let dist = std::cmp::min(d0, d1);
    ///     assert!(dist < 400, "dist: {:?}", dist);
    /// }
    /// ```
    pub fn encrypt_zero_glwe_list<Scalar, OutputCont, Gen>(
        &self,
        encrypted: &mut GlweList<OutputCont>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        GlweList<OutputCont>: AsMutTensor<Element = Scalar>,
        Scalar: UnsignedTorus + Add,
        Gen: ByteRandomGenerator,
    {
        for mut ciphertext in encrypted.ciphertext_iter_mut() {
            self.encrypt_zero_glwe(&mut ciphertext, noise_parameters, generator);
        }
    }

    /// Decrypts a single GLWE ciphertext.
    ///
    /// See ['GlweSecretKey::encrypt_glwe`] for an example.
    pub fn decrypt_glwe<CiphCont, EncCont, Scalar>(
        &self,
        encoded: &mut PlaintextList<EncCont>,
        encrypted: &GlweCiphertext<CiphCont>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        PlaintextList<EncCont>: AsMutTensor<Element = Scalar>,
        GlweCiphertext<CiphCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus + Add,
    {
        ck_dim_eq!(encoded.count().0 => encrypted.polynomial_size().0);
        let (body, masks) = encrypted.get_body_and_mask();
        encoded
            .as_mut_tensor()
            .fill_with_one(body.as_tensor(), |a| *a);
        encoded
            .as_mut_polynomial()
            .update_with_wrapping_sub_multisum(
                &masks.as_polynomial_list(),
                &self.as_polynomial_list(),
            );
    }

    /// Decrypts a list of GLWE ciphertexts.
    ///
    /// See ['GlweSecretKey::encrypt_glwe_list`] for an example.
    pub fn decrypt_glwe_list<CiphCont, EncCont, Scalar>(
        &self,
        encoded: &mut PlaintextList<EncCont>,
        encrypted: &GlweList<CiphCont>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        PlaintextList<EncCont>: AsMutTensor<Element = Scalar>,
        GlweList<CiphCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus + Add,
        for<'a> PlaintextList<&'a mut [Scalar]>: AsMutTensor<Element = Scalar>,
    {
        ck_dim_eq!(encrypted.ciphertext_count().0 * encrypted.polynomial_size().0 => encoded.count().0);
        ck_dim_eq!(encrypted.glwe_dimension().0 => self.key_size().0);
        for (ciphertext, mut encoded) in encrypted
            .ciphertext_iter()
            .zip(encoded.sublist_iter_mut(PlaintextCount(encrypted.polynomial_size().0)))
        {
            self.decrypt_glwe(&mut encoded, &ciphertext);
        }
    }

    fn encrypt_constant_ggsw_row<Scalar, InputCont, OutputCont, Gen>(
        &self,
        (row_index, last_row_index): (usize, usize),
        factor: &Scalar,
        sk_poly_list: &PolynomialList<InputCont>,
        row_as_glwe: &mut GlweCiphertext<OutputCont>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Scalar: UnsignedTorus,
        Self: AsRefTensor<Element = Scalar>,
        PolynomialList<InputCont>: AsRefTensor<Element = Scalar>,
        GlweCiphertext<OutputCont>: AsMutTensor<Element = Scalar>,
        Gen: ByteRandomGenerator,
    {
        if row_index < last_row_index {
            // Not the last row
            let sk_poly = sk_poly_list.get_polynomial(row_index);

            // We need a copy of the polynomial to not modify the GLWE secret key
            let mut sk_factored =
                Tensor::from_container(sk_poly.as_tensor().as_container().to_vec());

            sk_factored.update_with_wrapping_scalar_mul(factor);

            let encoded = PlaintextList::from_tensor(sk_factored);

            self.encrypt_glwe(row_as_glwe, &encoded, noise_parameters, generator)
        } else {
            // The last row needs a slightly different treatment
            let mut encoded =
                PlaintextList::allocate(Scalar::ZERO, PlaintextCount(self.poly_size.0));
            let first_coeff = encoded.as_mut_tensor().first_mut();
            *first_coeff = first_coeff.wrapping_add(factor.wrapping_neg());

            self.encrypt_glwe(row_as_glwe, &encoded, noise_parameters, generator);
        }
    }

    /// This function encrypts a message as a GGSW ciphertext.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::Plaintext;
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::GlweSecretKey;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LogStandardDev,
    ///     PolynomialSize,
    /// };
    /// let mut generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key =
    ///     GlweSecretKey::generate_binary(GlweDimension(2), PolynomialSize(10), &mut generator);
    /// let mut ciphertext = StandardGgswCiphertext::allocate(
    ///     0 as u32,
    ///     PolynomialSize(10),
    ///     GlweSize(3),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(7),
    /// );
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    /// let mut secret_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// secret_key.encrypt_constant_ggsw(
    ///     &mut ciphertext,
    ///     &Plaintext(10),
    ///     noise,
    ///     &mut secret_generator,
    /// );
    /// ```
    pub fn encrypt_constant_ggsw<OutputCont, Scalar, Gen>(
        &self,
        encrypted: &mut StandardGgswCiphertext<OutputCont>,
        encoded: &Plaintext<Scalar>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        StandardGgswCiphertext<OutputCont>: AsMutTensor<Element = Scalar>,
        OutputCont: AsMutSlice<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
    {
        ck_dim_eq!(self.polynomial_size() => encrypted.polynomial_size());
        ck_dim_eq!(self.key_size() => encrypted.glwe_size().to_glwe_dimension());

        let gen_iter = generator
            .fork_ggsw_to_ggsw_levels::<Scalar>(
                encrypted.decomposition_level_count(),
                self.key_size().to_glwe_size(),
                self.poly_size,
            )
            .expect("Failed to split generator into ggsw levels");

        let base_log = encrypted.decomposition_base_log();
        for (mut matrix, mut generator) in encrypted.level_matrix_iter_mut().zip(gen_iter) {
            let factor = encoded.0.wrapping_neg().wrapping_mul(
                Scalar::ONE << (Scalar::BITS - (base_log.0 * (matrix.decomposition_level().0))),
            );

            // We iterate over the rows of the level matrix, the last row needs special treatment
            let gen_iter = generator
                .fork_ggsw_level_to_glwe::<Scalar>(self.key_size().to_glwe_size(), self.poly_size)
                .expect("Failed to split generator into rlwe");

            let last_row_index = matrix.glwe_size().0 - 1;
            let sk_poly_list = &self.as_polynomial_list();

            for ((row_index, row), mut generator) in matrix.row_iter_mut().enumerate().zip(gen_iter)
            {
                self.encrypt_constant_ggsw_row(
                    (row_index, last_row_index),
                    &factor,
                    sk_poly_list,
                    &mut row.into_glwe(),
                    noise_parameters,
                    &mut generator,
                );
            }
        }
    }

    fn encrypt_constant_seeded_ggsw_row<Scalar, InputCont, OutputCont, Gen>(
        &self,
        (row_index, last_row_index): (usize, usize),
        factor: &Scalar,
        sk_poly_list: &PolynomialList<InputCont>,
        row_as_seeded_glwe: &mut GlweSeededCiphertext<OutputCont>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Scalar: UnsignedTorus,
        Self: AsRefTensor<Element = Scalar>,
        PolynomialList<InputCont>: AsRefTensor<Element = Scalar>,
        GlweCiphertext<OutputCont>: AsMutTensor<Element = Scalar>,
        OutputCont: AsMutSlice<Element = Scalar>,
        Gen: ByteRandomGenerator,
    {
        if row_index < last_row_index {
            // Not the last row
            let sk_poly = sk_poly_list.get_polynomial(row_index);

            // We need a copy of the polynomial to not modify the GLWE secret key
            let mut sk_factored =
                Tensor::from_container(sk_poly.as_tensor().as_container().to_vec());

            sk_factored.update_with_wrapping_scalar_mul(factor);

            let encoded = PlaintextList::from_tensor(sk_factored);

            self.encrypt_seeded_glwe_with_existing_generator(
                row_as_seeded_glwe,
                &encoded,
                noise_parameters,
                generator,
            );
        } else {
            // The last row needs a slightly different treatment
            let mut encoded =
                PlaintextList::allocate(Scalar::ZERO, PlaintextCount(self.poly_size.0));
            let first_coeff = encoded.as_mut_tensor().first_mut();
            *first_coeff = first_coeff.wrapping_add(factor.wrapping_neg());

            self.encrypt_seeded_glwe_with_existing_generator(
                row_as_seeded_glwe,
                &encoded,
                noise_parameters,
                generator,
            );
        }
    }

    /// Factorized function to be able to encrypt a GGSW with a generator in a particular state i.e.
    /// not freshly instantiated. The caller is responsible for maintaining consistency.
    pub fn encrypt_constant_seeded_ggsw_with_existing_generator<
        OutputCont,
        Scalar,
        NoiseParameter,
        Gen,
    >(
        &self,
        encrypted: &mut StandardGgswSeededCiphertext<OutputCont>,
        encoded: &Plaintext<Scalar>,
        noise_parameters: NoiseParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        StandardGgswCiphertext<OutputCont>: AsMutTensor<Element = Scalar>,
        OutputCont: AsMutSlice<Element = Scalar>,
        Scalar: UnsignedTorus,
        NoiseParameter: DispersionParameter,
        Gen: ByteRandomGenerator,
    {
        ck_dim_eq!(self.polynomial_size() => encrypted.polynomial_size());
        ck_dim_eq!(self.key_size() => encrypted.glwe_size().to_glwe_dimension());

        let gen_iter = generator
            .fork_ggsw_to_ggsw_levels::<Scalar>(
                encrypted.decomposition_level_count(),
                self.key_size().to_glwe_size(),
                self.poly_size,
            )
            .expect("Failed to split generator into ggsw levels");

        let base_log = encrypted.decomposition_base_log();
        for (mut matrix, mut generator) in encrypted.level_matrix_iter_mut().zip(gen_iter) {
            let factor = encoded.0.wrapping_neg().wrapping_mul(
                Scalar::ONE << (Scalar::BITS - (base_log.0 * (matrix.decomposition_level().0))),
            );

            // We iterate over the rows of the level matrix, the last row needs special treatment
            let gen_iter = generator
                .fork_ggsw_level_to_glwe::<Scalar>(self.key_size().to_glwe_size(), self.poly_size)
                .expect("Failed to split generator into glwe");

            let last_row_index = matrix.glwe_size().0 - 1;
            let sk_poly_list = &self.as_polynomial_list();

            for ((row_index, row), mut generator) in matrix.row_iter_mut().enumerate().zip(gen_iter)
            {
                self.encrypt_constant_seeded_ggsw_row(
                    (row_index, last_row_index),
                    &factor,
                    sk_poly_list,
                    &mut row.into_seeded_glwe(),
                    noise_parameters,
                    &mut generator,
                );
            }
        }
    }

    /// This function encrypts a message as a GGSW seeded ciphertext.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::Plaintext;
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswSeededCiphertext;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::GlweSecretKey;
    /// use tfhe::core_crypto::commons::math::random::CompressionSeed;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LogStandardDev,
    ///     PolynomialSize,
    /// };
    /// let mut generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key =
    ///     GlweSecretKey::generate_binary(GlweDimension(2), PolynomialSize(10), &mut generator);
    /// let mut seeded_ciphertext = StandardGgswSeededCiphertext::<Vec<u32>>::allocate(
    ///     PolynomialSize(10),
    ///     GlweSize(3),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(7),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    ///
    /// let mut seeder = UnixSeeder::new(0);
    ///
    /// secret_key.encrypt_constant_seeded_ggsw::<_, _, _, _, SoftwareRandomGenerator>(
    ///     &mut seeded_ciphertext,
    ///     &Plaintext(10),
    ///     noise,
    ///     &mut seeder,
    /// );
    /// ```
    pub fn encrypt_constant_seeded_ggsw<OutputCont, Scalar, NoiseParameter, NoiseSeeder, Gen>(
        &self,
        encrypted: &mut StandardGgswSeededCiphertext<OutputCont>,
        encoded: &Plaintext<Scalar>,
        noise_parameters: NoiseParameter,
        seeder: &mut NoiseSeeder,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        StandardGgswCiphertext<OutputCont>: AsMutTensor<Element = Scalar>,
        OutputCont: AsMutSlice<Element = Scalar>,
        Scalar: UnsignedTorus,
        NoiseParameter: DispersionParameter,
        NoiseSeeder: Seeder,
        Gen: ByteRandomGenerator,
    {
        let mut generator =
            EncryptionRandomGenerator::<Gen>::new(encrypted.compression_seed().seed, seeder);

        self.encrypt_constant_seeded_ggsw_with_existing_generator(
            encrypted,
            encoded,
            noise_parameters,
            &mut generator,
        )
    }

    /// This function encrypts a message as a GGSW ciphertext, using as many threads as possible.
    ///
    /// # Notes
    /// This method is hidden behind the "__commons_parallel" feature gate.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::Plaintext;
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::GlweSecretKey;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LogStandardDev,
    ///     PolynomialSize,
    /// };
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key =
    ///     GlweSecretKey::generate_binary(GlweDimension(2), PolynomialSize(10), &mut secret_generator);
    /// let mut ciphertext = StandardGgswCiphertext::allocate(
    ///     0 as u32,
    ///     PolynomialSize(10),
    ///     GlweSize(3),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(7),
    /// );
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// secret_key.par_encrypt_constant_ggsw(
    ///     &mut ciphertext,
    ///     &Plaintext(10),
    ///     noise,
    ///     &mut encryption_generator,
    /// );
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_encrypt_constant_ggsw<OutputCont, Scalar, Gen>(
        &self,
        encrypted: &mut StandardGgswCiphertext<OutputCont>,
        encoded: &Plaintext<Scalar>,
        noise_parameters: impl DispersionParameter + Send + Sync,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        StandardGgswCiphertext<OutputCont>: AsMutTensor<Element = Scalar>,
        OutputCont: AsMutSlice<Element = Scalar>,
        Scalar: UnsignedTorus + Send + Sync,
        Cont: Sync,
        Gen: ParallelByteRandomGenerator,
    {
        ck_dim_eq!(self.polynomial_size() => encrypted.polynomial_size());
        ck_dim_eq!(self.key_size() => encrypted.glwe_size().to_glwe_dimension());
        let generators = generator
            .par_fork_ggsw_to_ggsw_levels::<Scalar>(
                encrypted.decomposition_level_count(),
                self.key_size().to_glwe_size(),
                self.poly_size,
            )
            .expect("Failed to split generator into ggsw levels");
        let base_log = encrypted.decomposition_base_log();
        encrypted
            .par_level_matrix_iter_mut()
            .zip(generators)
            .for_each(move |(mut matrix, mut generator)| {
                let factor = encoded.0.wrapping_neg().wrapping_mul(
                    Scalar::ONE << (Scalar::BITS - (base_log.0 * (matrix.decomposition_level().0))),
                );

                let gen_iter = generator
                    .par_fork_ggsw_level_to_glwe::<Scalar>(
                        self.key_size().to_glwe_size(),
                        self.poly_size,
                    )
                    .expect("Failed to split generator into glwe");

                let last_row_index = matrix.glwe_size().0 - 1;

                let sk_poly_list = &self.as_polynomial_list();

                // We iterate over the rows of the level matrix
                matrix
                    .par_row_iter_mut()
                    .enumerate()
                    .zip(gen_iter)
                    .for_each(|((row_index, row), mut generator)| {
                        self.encrypt_constant_ggsw_row(
                            (row_index, last_row_index),
                            &factor,
                            sk_poly_list,
                            &mut row.into_glwe(),
                            noise_parameters,
                            &mut generator,
                        );
                    })
            })
    }

    /// Factorized function to be able to encrypt a GGSW with a generator in a particular state i.e.
    /// not freshly instantiated. The caller is responsible for maintaining consistency.
    #[cfg(feature = "__commons_parallel")]
    pub fn par_encrypt_constant_seeded_ggsw_with_existing_generator<
        OutputCont,
        Scalar,
        NoiseParameter,
        Gen,
    >(
        &self,
        encrypted: &mut StandardGgswSeededCiphertext<OutputCont>,
        encoded: &Plaintext<Scalar>,
        noise_parameters: NoiseParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        OutputCont: AsMutSlice<Element = Scalar>,
        Scalar: UnsignedTorus + Send + Sync,
        Cont: Send + Sync,
        NoiseParameter: DispersionParameter + Sync + Send,
        Gen: ParallelByteRandomGenerator,
    {
        ck_dim_eq!(self.polynomial_size() => encrypted.polynomial_size());
        ck_dim_eq!(self.key_size() => encrypted.glwe_size().to_glwe_dimension());

        let gen_iter = generator
            .par_fork_ggsw_to_ggsw_levels::<Scalar>(
                encrypted.decomposition_level_count(),
                self.key_size().to_glwe_size(),
                self.poly_size,
            )
            .expect("Failed to split generator into ggsw levels");

        let base_log = encrypted.decomposition_base_log();
        encrypted
            .par_level_matrix_iter_mut()
            .zip(gen_iter)
            .for_each(move |(mut matrix, mut generator)| {
                let factor = encoded.0.wrapping_neg().wrapping_mul(
                    Scalar::ONE << (Scalar::BITS - (base_log.0 * (matrix.decomposition_level().0))),
                );

                // We iterate over the rows of the level matrix, the last row needs special
                // treatment
                let gen_iter = generator
                    .par_fork_ggsw_level_to_glwe::<Scalar>(
                        self.key_size().to_glwe_size(),
                        self.poly_size,
                    )
                    .expect("Failed to split generator into rlwe");

                let last_row_index = matrix.glwe_size().0 - 1;
                let sk_poly_list = &self.as_polynomial_list();

                // We iterate over the rows of the level matrix
                matrix
                    .par_row_iter_mut()
                    .zip(gen_iter)
                    .enumerate()
                    .for_each(|(row_index, (row, mut generator))| {
                        self.encrypt_constant_seeded_ggsw_row(
                            (row_index, last_row_index),
                            &factor,
                            sk_poly_list,
                            &mut row.into_seeded_glwe(),
                            noise_parameters,
                            &mut generator,
                        );
                    });
            });
    }

    /// This function encrypts a message as a GGSW seeded ciphertext.
    ///
    /// # Notes
    /// This method is hidden behind the "multithread" feature gate.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::Plaintext;
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswSeededCiphertext;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::GlweSecretKey;
    /// use tfhe::core_crypto::commons::math::random::CompressionSeed;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LogStandardDev,
    ///     PolynomialSize,
    /// };
    /// let mut generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key =
    ///     GlweSecretKey::generate_binary(GlweDimension(2), PolynomialSize(10), &mut generator);
    /// let mut seeded_ciphertext = StandardGgswSeededCiphertext::<Vec<u32>>::allocate(
    ///     PolynomialSize(10),
    ///     GlweSize(3),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(7),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    ///
    /// let mut seeder = UnixSeeder::new(0);
    ///
    /// secret_key.par_encrypt_constant_seeded_ggsw::<_, _, _, _, SoftwareRandomGenerator>(
    ///     &mut seeded_ciphertext,
    ///     &Plaintext(10),
    ///     noise,
    ///     &mut seeder,
    /// );
    /// ```
    #[cfg(feature = "__commons_parallel")]
    pub fn par_encrypt_constant_seeded_ggsw<OutputCont, Scalar, NoiseParameter, NoiseSeeder, Gen>(
        &self,
        encrypted: &mut StandardGgswSeededCiphertext<OutputCont>,
        encoded: &Plaintext<Scalar>,
        noise_parameters: NoiseParameter,
        seeder: &mut NoiseSeeder,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        OutputCont: AsMutSlice<Element = Scalar>,
        Scalar: UnsignedTorus + Send + Sync,
        Cont: Send + Sync,
        NoiseParameter: DispersionParameter + Sync + Send,
        NoiseSeeder: Seeder + Send + Sync,
        Gen: ParallelByteRandomGenerator,
    {
        let mut generator =
            EncryptionRandomGenerator::<Gen>::new(encrypted.compression_seed().seed, seeder);

        self.par_encrypt_constant_seeded_ggsw_with_existing_generator(
            encrypted,
            encoded,
            noise_parameters,
            &mut generator,
        );
    }

    /// This function encrypts a message as a GGSW ciphertext whose rlwe masks are all zeros.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::Plaintext;
    /// use tfhe::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::GlweSecretKey;
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LogStandardDev,
    ///     PolynomialSize,
    /// };
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: GlweSecretKey<_, Vec<u32>> =
    ///     GlweSecretKey::generate_binary(GlweDimension(2), PolynomialSize(10), &mut secret_generator);
    /// let mut ciphertext = StandardGgswCiphertext::allocate(
    ///     0 as u32,
    ///     PolynomialSize(10),
    ///     GlweSize(3),
    ///     DecompositionLevelCount(3),
    ///     DecompositionBaseLog(7),
    /// );
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// secret_key.trivial_encrypt_constant_ggsw(
    ///     &mut ciphertext,
    ///     &Plaintext(10),
    ///     noise,
    ///     &mut encryption_generator,
    /// );
    /// ```
    pub fn trivial_encrypt_constant_ggsw<OutputCont, Scalar, Gen>(
        &self,
        encrypted: &mut StandardGgswCiphertext<OutputCont>,
        encoded: &Plaintext<Scalar>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        StandardGgswCiphertext<OutputCont>: AsMutTensor<Element = Scalar>,
        OutputCont: AsMutSlice<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
    {
        ck_dim_eq!(self.polynomial_size() => encrypted.polynomial_size());
        ck_dim_eq!(self.key_size() => encrypted.glwe_size().to_glwe_dimension());
        // We fill the ggsw with trivial glwe encryptions of zero:
        for mut glwe in encrypted.as_mut_glwe_list().ciphertext_iter_mut() {
            let (mut body, mut mask) = glwe.get_mut_body_and_mask();
            mask.as_mut_tensor().fill_with_element(Scalar::ZERO);
            generator.fill_tensor_with_random_noise(&mut body, noise_parameters);
        }
        let base_log = encrypted.decomposition_base_log();
        for mut matrix in encrypted.level_matrix_iter_mut() {
            let decomposition = encoded.0.wrapping_mul(
                Scalar::ONE
                    << (<Scalar as Numeric>::BITS
                        - (base_log.0 * (matrix.decomposition_level().0))),
            );
            // We iterate over the rowe of the level matrix
            for (index, row) in matrix.row_iter_mut().enumerate() {
                let rlwe_ct = row.into_glwe();
                // We retrieve the row as a polynomial list
                let mut polynomial_list = rlwe_ct.into_polynomial_list();
                // We retrieve the polynomial in the diagonal
                let mut level_polynomial = polynomial_list.get_mut_polynomial(index);
                // We get the first coefficient
                let first_coef = level_polynomial.as_mut_tensor().first_mut();
                // We update the first coefficient
                *first_coef = first_coef.wrapping_add(decomposition);
            }
        }
    }
}

impl<Kind, Element, Cont> AsRefTensor for GlweSecretKey<Kind, Cont>
where
    Kind: KeyKind,
    Cont: AsRefSlice<Element = Element>,
{
    type Element = Element;
    type Container = Cont;
    fn as_tensor(&self) -> &Tensor<Self::Container> {
        &self.tensor
    }
}

impl<Kind, Element, Cont> AsMutTensor for GlweSecretKey<Kind, Cont>
where
    Kind: KeyKind,
    Cont: AsMutSlice<Element = Element>,
{
    type Element = Element;
    type Container = Cont;
    fn as_mut_tensor(&mut self) -> &mut Tensor<<Self as AsMutTensor>::Container> {
        &mut self.tensor
    }
}

impl<Kind, Cont> IntoTensor for GlweSecretKey<Kind, Cont>
where
    Kind: KeyKind,
    Cont: AsRefSlice,
{
    type Element = <Cont as AsRefSlice>::Element;
    type Container = Cont;
    fn into_tensor(self) -> Tensor<Self::Container> {
        self.tensor
    }
}
