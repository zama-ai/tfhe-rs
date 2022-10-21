use crate::core_crypto::commons::crypto::encoding::{Plaintext, PlaintextList};
use crate::core_crypto::commons::crypto::lwe::{
    LweBody, LweCiphertext, LweList, LweMask, LweSeededCiphertext, LweSeededList,
};
use crate::core_crypto::commons::crypto::secret::generators::{
    EncryptionRandomGenerator, SecretRandomGenerator,
};
#[cfg(feature = "__commons_parallel")]
use crate::core_crypto::commons::math::random::ParallelByteRandomGenerator;
use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, Gaussian, RandomGenerable, Seeder,
};
use crate::core_crypto::commons::math::tensor::{
    AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, IntoTensor, Tensor,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
#[cfg(feature = "__commons_parallel")]
use crate::core_crypto::prelude::LweCiphertextCount;
use crate::core_crypto::prelude::{
    BinaryKeyKind, DispersionParameter, GaussianKeyKind, KeyKind, LweDimension, TernaryKeyKind,
    UniformKeyKind,
};
#[cfg(feature = "__commons_parallel")]
use rayon::{iter::IndexedParallelIterator, prelude::*};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// A LWE secret key.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSecretKey<Kind, Cont>
where
    Kind: KeyKind,
{
    pub(crate) tensor: Tensor<Cont>,
    pub(crate) kind: PhantomData<Kind>,
}

impl<Scalar> LweSecretKey<BinaryKeyKind, Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    /// Generates a new binary secret key; e.g. allocates a storage and samples random values for
    /// the key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: LweSecretKey<_, Vec<u32>> =
    ///     LweSecretKey::generate_binary(LweDimension(256), &mut generator);
    /// assert_eq!(secret_key.key_size(), LweDimension(256));
    /// ```
    pub fn generate_binary<Gen: ByteRandomGenerator>(
        size: LweDimension,
        generator: &mut SecretRandomGenerator<Gen>,
    ) -> Self {
        LweSecretKey {
            tensor: generator.random_binary_tensor(size.0),
            kind: PhantomData,
        }
    }
}

impl<Scalar> LweSecretKey<TernaryKeyKind, Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    /// Generates a new ternary secret key; e.g. allocates a storage and samples random values for
    /// the key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: LweSecretKey<_, Vec<u32>> =
    ///     LweSecretKey::generate_ternary(LweDimension(256), &mut generator);
    /// assert_eq!(secret_key.key_size(), LweDimension(256));
    /// ```
    pub fn generate_ternary<Gen: ByteRandomGenerator>(
        size: LweDimension,
        generator: &mut SecretRandomGenerator<Gen>,
    ) -> Self {
        LweSecretKey {
            tensor: generator.random_ternary_tensor(size.0),
            kind: PhantomData,
        }
    }
}

impl<Scalar> LweSecretKey<GaussianKeyKind, Vec<Scalar>>
where
    (Scalar, Scalar): RandomGenerable<Gaussian<f64>>,
    Scalar: UnsignedTorus,
{
    /// Generates a new gaussian secret key; e.g. allocates a storage and samples random values for
    /// the key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: LweSecretKey<_, Vec<u32>> =
    ///     LweSecretKey::generate_gaussian(LweDimension(256), &mut generator);
    /// assert_eq!(secret_key.key_size(), LweDimension(256));
    /// ```
    pub fn generate_gaussian<Gen: ByteRandomGenerator>(
        size: LweDimension,
        generator: &mut SecretRandomGenerator<Gen>,
    ) -> Self {
        LweSecretKey {
            tensor: generator.random_gaussian_tensor(size.0),
            kind: PhantomData,
        }
    }
}

impl<Scalar> LweSecretKey<UniformKeyKind, Vec<Scalar>>
where
    Scalar: UnsignedTorus,
{
    /// Generates a new gaussian secret key; e.g. allocates a storage and samples random values for
    /// the key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// let mut generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key: LweSecretKey<_, Vec<u32>> =
    ///     LweSecretKey::generate_uniform(LweDimension(256), &mut generator);
    /// assert_eq!(secret_key.key_size(), LweDimension(256));
    /// ```
    pub fn generate_uniform<Gen: ByteRandomGenerator>(
        size: LweDimension,
        generator: &mut SecretRandomGenerator<Gen>,
    ) -> Self {
        LweSecretKey {
            tensor: generator.random_uniform_tensor(size.0),
            kind: PhantomData,
        }
    }
}

impl<Cont> LweSecretKey<BinaryKeyKind, Cont> {
    /// Creates a binary lwe secret key from a container.
    ///
    /// # Notes
    ///
    /// This method does not fill the container with random values to create a new key. It merely
    /// wraps a container into the appropriate type. See [`LweSecretKey::generate_binary`] for a
    /// generation method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// let secret_key = LweSecretKey::binary_from_container(vec![true; 256]);
    /// assert_eq!(secret_key.key_size(), LweDimension(256));
    /// ```
    pub fn binary_from_container(cont: Cont) -> Self
    where
        Cont: AsRefSlice,
    {
        LweSecretKey {
            tensor: Tensor::from_container(cont),
            kind: PhantomData,
        }
    }
}

impl<Cont> LweSecretKey<TernaryKeyKind, Cont> {
    /// Creates a ternary lwe secret key from a container.
    ///
    /// # Notes
    ///
    /// This method does not fill the container with random values to create a new key. It merely
    /// wraps a container into the appropriate type. See [`LweSecretKey::generate_ternary`] for a
    /// generation method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// let secret_key = LweSecretKey::ternary_from_container(vec![true; 256]);
    /// assert_eq!(secret_key.key_size(), LweDimension(256));
    /// ```
    pub fn ternary_from_container(cont: Cont) -> Self
    where
        Cont: AsRefSlice,
    {
        LweSecretKey {
            tensor: Tensor::from_container(cont),
            kind: PhantomData,
        }
    }
}

impl<Cont> LweSecretKey<GaussianKeyKind, Cont> {
    /// Creates a gaussian lwe secret key from a container.
    ///
    /// # Notes
    ///
    /// This method does not fill the container with random values to create a new key. It merely
    /// wraps a container into the appropriate type. See [`LweSecretKey::generate_gaussian`] for a
    /// generation method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// let secret_key = LweSecretKey::gaussian_from_container(vec![true; 256]);
    /// assert_eq!(secret_key.key_size(), LweDimension(256));
    /// ```
    pub fn gaussian_from_container(cont: Cont) -> Self
    where
        Cont: AsRefSlice,
    {
        LweSecretKey {
            tensor: Tensor::from_container(cont),
            kind: PhantomData,
        }
    }
}

impl<Cont> LweSecretKey<UniformKeyKind, Cont> {
    /// Creates a uniform lwe secret key from a container.
    ///
    /// # Notes
    ///
    /// This method does not fill the container with random values to create a new key. It merely
    /// wraps a container into the appropriate type. See [`LweSecretKey::generate_uniform`] for a
    /// generation method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// let secret_key = LweSecretKey::uniform_from_container(vec![true; 256]);
    /// assert_eq!(secret_key.key_size(), LweDimension(256));
    /// ```
    pub fn uniform_from_container(cont: Cont) -> Self
    where
        Cont: AsRefSlice,
    {
        LweSecretKey {
            tensor: Tensor::from_container(cont),
            kind: PhantomData,
        }
    }
}

impl<Kind, Cont> LweSecretKey<Kind, Cont>
where
    Kind: KeyKind,
{
    /// Returns the size of the secret key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::LweDimension;
    /// let secret_key = LweSecretKey::binary_from_container(vec![true; 256]);
    /// assert_eq!(secret_key.key_size(), LweDimension(256));
    /// ```
    pub fn key_size(&self) -> LweDimension
    where
        Self: AsRefTensor,
    {
        LweDimension(self.as_tensor().len())
    }

    fn fill_lwe_mask_and_body_for_encryption<OutputCont, Scalar, Gen>(
        &self,
        output_body: &mut LweBody<Scalar>,
        output_mask: &mut LweMask<OutputCont>,
        encoded: &Plaintext<Scalar>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        OutputCont: AsMutSlice<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
    {
        // generate a uniformly random mask
        generator.fill_tensor_with_random_mask(output_mask);

        // generate an error from the normal distribution described by std_dev
        output_body.0 = generator.random_noise(noise_parameters);

        // compute the multisum between the secret key and the mask
        output_body.0 = output_body
            .0
            .wrapping_add(output_mask.compute_multisum(self));

        // add the encoded message
        output_body.0 = output_body.0.wrapping_add(encoded.0);
    }

    /// Encrypts a single ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{LogStandardDev, LweDimension, LweSize};
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key = LweSecretKey::generate_binary(LweDimension(256), &mut secret_generator);
    /// let encoder = RealEncoder {
    ///     offset: 0. as f32,
    ///     delta: 10.,
    /// };
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    ///
    /// let clear = Cleartext(2. as f32);
    /// let plain: Plaintext<u32> = encoder.encode(clear);
    /// let mut encrypted = LweCiphertext::allocate(0u32, LweSize(257));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// secret_key.encrypt_lwe(&mut encrypted, &plain, noise, &mut encryption_generator);
    ///
    /// let mut decrypted = Plaintext(0u32);
    /// secret_key.decrypt_lwe(&mut decrypted, &encrypted);
    /// let decoded = encoder.decode(decrypted);
    ///
    /// assert!((decoded.0 - clear.0).abs() < 0.1);
    /// ```
    pub fn encrypt_lwe<OutputCont, Scalar, Gen>(
        &self,
        output: &mut LweCiphertext<OutputCont>,
        encoded: &Plaintext<Scalar>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        LweCiphertext<OutputCont>: AsMutTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
    {
        let (output_body, mut output_mask) = output.get_mut_body_and_mask();

        self.fill_lwe_mask_and_body_for_encryption(
            output_body,
            &mut output_mask,
            encoded,
            noise_parameters,
            generator,
        );
    }

    /// Encrypts a single seeded ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::random::CompressionSeed;
    /// use tfhe::core_crypto::prelude::{LogStandardDev, LweDimension, LweSize};
    ///
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, Seeder, UnixSeeder};
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    ///
    /// let mut seeder = UnixSeeder::new(0);
    ///
    /// let secret_key = LweSecretKey::generate_binary(LweDimension(256), &mut secret_generator);
    /// let encoder = RealEncoder {
    ///     offset: 0. as f32,
    ///     delta: 10.,
    /// };
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    ///
    /// let clear = Cleartext(2. as f32);
    /// let plain: Plaintext<u32> = encoder.encode(clear);
    /// let mut encrypted: LweSeededCiphertext<u32> =
    ///     LweSeededCiphertext::allocate(LweDimension(256), CompressionSeed { seed: Seed(42) });
    /// secret_key.encrypt_seeded_lwe::<_, _, _, SoftwareRandomGenerator>(
    ///     &mut encrypted,
    ///     &plain,
    ///     noise,
    ///     &mut seeder,
    /// );
    ///
    /// let mut encrypted_expanded = LweCiphertext::allocate(0u32, LweSize(257));
    /// encrypted.expand_into::<_, SoftwareRandomGenerator>(&mut encrypted_expanded);
    ///
    /// let mut decrypted = Plaintext(0u32);
    /// secret_key.decrypt_lwe(&mut decrypted, &encrypted_expanded);
    /// let decoded = encoder.decode(decrypted);
    ///
    /// assert!((decoded.0 - clear.0).abs() < 0.1);
    /// ```
    pub fn encrypt_seeded_lwe<Scalar, NoiseParameter, NoiseSeeder, Gen>(
        &self,
        output: &mut LweSeededCiphertext<Scalar>,
        encoded: &Plaintext<Scalar>,
        noise_parameters: NoiseParameter,
        seeder: &mut NoiseSeeder,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
        // This will be removable when https://github.com/rust-lang/rust/issues/83701 is stabilized
        // We currently need to be able to specify concrete types for the generic type parameters
        // which cannot be done when some arguments use the `impl Trait` pattern
        NoiseParameter: DispersionParameter,
        NoiseSeeder: Seeder + ?Sized,
    {
        debug_assert!(
            output.lwe_size().to_lwe_dimension() == self.key_size(),
            "Output LweSeededCiphertext dimension is not compatible with LweSecretKey dimension"
        );

        // Create the generator for the encryption, seed it with the output seed, pass a seeder so
        // that the noise generator is seeded with a private seed
        let mut generator =
            EncryptionRandomGenerator::<Gen>::new(output.compression_seed().seed, seeder);

        let mut output_mask = LweMask::from_container(vec![Scalar::ZERO; self.key_size().0]);
        let output_body = output.get_mut_body();

        self.fill_lwe_mask_and_body_for_encryption(
            output_body,
            &mut output_mask,
            encoded,
            noise_parameters,
            &mut generator,
        );
    }

    /// Encrypts a list of ciphertexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seed, UnixSeeder};
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, CleartextCount, LogStandardDev, LweDimension, LweSize, PlaintextCount,
    /// };
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let secret_key = LweSecretKey::generate_binary(LweDimension(256), &mut secret_generator);
    /// let encoder = RealEncoder {
    ///     offset: 0. as f32,
    ///     delta: 10.,
    /// };
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    ///
    /// let clear_values = CleartextList::allocate(2. as f32, CleartextCount(100));
    /// let mut plain_values = PlaintextList::allocate(0u32, PlaintextCount(100));
    /// encoder.encode_list(&mut plain_values, &clear_values);
    /// let mut encrypted_values = LweList::allocate(0u32, LweSize(257), CiphertextCount(100));
    /// let mut encryption_generator =
    ///     EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0), &mut UnixSeeder::new(0));
    /// secret_key.encrypt_lwe_list(
    ///     &mut encrypted_values,
    ///     &plain_values,
    ///     noise,
    ///     &mut encryption_generator,
    /// );
    ///
    /// let mut decrypted_values = PlaintextList::allocate(0u32, PlaintextCount(100));
    /// secret_key.decrypt_lwe_list(&mut decrypted_values, &encrypted_values);
    /// let mut decoded_values = CleartextList::allocate(0. as f32, CleartextCount(100));
    /// encoder.decode_list(&mut decoded_values, &decrypted_values);
    /// for (clear, decoded) in clear_values
    ///     .cleartext_iter()
    ///     .zip(decoded_values.cleartext_iter())
    /// {
    ///     assert!((clear.0 - decoded.0).abs() < 0.1);
    /// }
    /// ```
    pub fn encrypt_lwe_list<OutputCont, InputCont, Scalar, Gen>(
        &self,
        output: &mut LweList<OutputCont>,
        encoded: &PlaintextList<InputCont>,
        noise_parameters: impl DispersionParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        LweList<OutputCont>: AsMutTensor<Element = Scalar>,
        PlaintextList<InputCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
    {
        debug_assert!(
            output.count().0 == encoded.count().0,
            "Lwe cipher list size and encoded list size are not compatible"
        );
        for (mut cipher, message) in output.ciphertext_iter_mut().zip(encoded.plaintext_iter()) {
            self.encrypt_lwe(&mut cipher, message, noise_parameters, generator);
        }
    }

    #[cfg(feature = "__commons_parallel")]
    pub fn par_encrypt_lwe_list<OutputCont, InputCont, Scalar, Gen>(
        &self,
        output: &mut LweList<OutputCont>,
        encoded: &PlaintextList<InputCont>,
        noise_parameters: impl DispersionParameter + Sync,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        LweList<OutputCont>: AsMutTensor<Element = Scalar>,
        PlaintextList<InputCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus + Send + Sync,
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
        Cont: Sync,
    {
        debug_assert!(
            output.count().0 == encoded.count().0,
            "Lwe cipher list size and encoded list size are not compatible"
        );
        let ct_count = LweCiphertextCount(output.count().0);
        let ct_size = output.lwe_size;
        output
            .par_ciphertext_iter_mut()
            .zip(encoded.par_plaintext_iter())
            .zip(
                generator
                    .par_fork_lwe_list_to_lwe::<Scalar>(ct_count, ct_size)
                    .unwrap(),
            )
            .for_each(|((mut cipher, message), mut generator)| {
                self.encrypt_lwe(&mut cipher, message, noise_parameters, &mut generator);
            })
    }

    pub fn encrypt_seeded_lwe_list_with_existing_generator<
        OutputCont,
        InputCont,
        Scalar,
        NoiseParameter,
        Gen,
    >(
        &self,
        output: &mut LweSeededList<OutputCont>,
        encoded: &PlaintextList<InputCont>,
        noise_parameters: NoiseParameter,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        LweSeededList<OutputCont>: AsMutTensor<Element = Scalar>,
        PlaintextList<InputCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
        // This will be removable when https://github.com/rust-lang/rust/issues/83701 is stabilized
        // We currently need to be able to specify concrete types for the generic type parameters
        // which cannot be done when some arguments use the `impl Trait` pattern
        NoiseParameter: DispersionParameter,
    {
        let mut mask_tensor = vec![Scalar::ZERO; self.key_size().0];
        let mut output_mask = LweMask::from_container(mask_tensor.as_mut_slice());

        for (output_body, encoded_message) in output.body_iter_mut().zip(encoded.plaintext_iter()) {
            self.fill_lwe_mask_and_body_for_encryption(
                output_body,
                &mut output_mask,
                encoded_message,
                noise_parameters,
                generator,
            );
        }
    }

    /// Encrypts a list of seeded ciphertexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextCount, LogStandardDev, LweDimension, PlaintextCount,
    /// };
    ///
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// use tfhe::core_crypto::commons::crypto::lwe::*;
    /// use tfhe::core_crypto::commons::crypto::secret::generators::{
    ///     EncryptionRandomGenerator, SecretRandomGenerator,
    /// };
    /// use tfhe::core_crypto::commons::crypto::secret::*;
    /// use tfhe::core_crypto::commons::crypto::*;
    /// use tfhe::core_crypto::commons::math::random::{CompressionSeed, Seed};
    ///
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::{Seeder, UnixSeeder};
    ///
    /// let mut secret_generator = SecretRandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    ///
    /// let mut seeder = UnixSeeder::new(0);
    ///
    /// let secret_key = LweSecretKey::generate_binary(LweDimension(256), &mut secret_generator);
    /// let noise = LogStandardDev::from_log_standard_dev(-15.);
    ///
    /// let mut plain_values = PlaintextList::allocate(3u32, PlaintextCount(100));
    /// let mut encrypted_values = LweSeededList::allocate(
    ///     LweDimension(256),
    ///     CiphertextCount(100),
    ///     CompressionSeed { seed: Seed(42) },
    /// );
    /// secret_key.encrypt_seeded_lwe_list::<_, _, _, _, _, SoftwareRandomGenerator>(
    ///     &mut encrypted_values,
    ///     &plain_values,
    ///     noise,
    ///     &mut seeder,
    /// );
    /// ```
    pub fn encrypt_seeded_lwe_list<
        OutputCont,
        InputCont,
        Scalar,
        NoiseParameter,
        NoiseSeeder,
        Gen,
    >(
        &self,
        output: &mut LweSeededList<OutputCont>,
        encoded: &PlaintextList<InputCont>,
        noise_parameters: NoiseParameter,
        seeder: &mut NoiseSeeder,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        LweSeededList<OutputCont>: AsMutTensor<Element = Scalar>,
        PlaintextList<InputCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
        // This will be removable when https://github.com/rust-lang/rust/issues/83701 is stabilized
        // We currently need to be able to specify concrete types for the generic type parameters
        // which cannot be done when some arguments use the `impl Trait` pattern
        NoiseParameter: DispersionParameter,
        NoiseSeeder: Seeder,
    {
        let mut generator =
            EncryptionRandomGenerator::<Gen>::new(output.get_compression_seed().seed, seeder);

        self.encrypt_seeded_lwe_list_with_existing_generator(
            output,
            encoded,
            noise_parameters,
            &mut generator,
        );
    }

    /// Decrypts a single ciphertext.
    ///
    /// See ['encrypt_lwe'] for an example.
    pub fn decrypt_lwe<Scalar, CipherCont>(
        &self,
        output: &mut Plaintext<Scalar>,
        cipher: &LweCiphertext<CipherCont>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        LweCiphertext<CipherCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        let (body, masks) = cipher.get_body_and_mask();
        // put body inside result
        output.0 = body.0;
        // subtract the multisum between the key and the mask
        output.0 = output.0.wrapping_sub(masks.compute_multisum(self));
    }

    /// Decrypts a list of ciphertexts.
    ///
    /// See ['encrypt_lwe_list'] for an example.
    pub fn decrypt_lwe_list<Scalar, EncodedCont, CipherCont>(
        &self,
        output: &mut PlaintextList<EncodedCont>,
        cipher: &LweList<CipherCont>,
    ) where
        Self: AsRefTensor<Element = Scalar>,
        PlaintextList<EncodedCont>: AsMutTensor<Element = Scalar>,
        LweList<CipherCont>: AsRefTensor<Element = Scalar>,
        Scalar: UnsignedTorus,
    {
        debug_assert!(
            output.count().0 == cipher.count().0,
            "Tried to decrypt a list into one with incompatible size.Expected {} found {}",
            output.count().0,
            cipher.count().0
        );
        for (cipher, output) in cipher.ciphertext_iter().zip(output.plaintext_iter_mut()) {
            self.decrypt_lwe(output, &cipher);
        }
    }
}

impl<Kind, Element, Cont> AsRefTensor for LweSecretKey<Kind, Cont>
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

impl<Kind, Element, Cont> AsMutTensor for LweSecretKey<Kind, Cont>
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

impl<Kind, Cont> IntoTensor for LweSecretKey<Kind, Cont>
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
