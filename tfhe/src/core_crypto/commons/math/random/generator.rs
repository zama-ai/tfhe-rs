use crate::core_crypto::backward_compatibility::commons::math::random::CompressionSeedVersions;
use crate::core_crypto::commons::math::random::{
    Distribution, Gaussian, RandomGenerable, Uniform, UniformBinary, UniformTernary,
};
use crate::core_crypto::commons::math::torus::{UnsignedInteger, UnsignedTorus};
use crate::core_crypto::commons::numeric::{CastInto, FloatingPoint};
use crate::core_crypto::commons::parameters::CiphertextModulus;
use rayon::prelude::*;
use tfhe_csprng::generators::{BytesPerChild, ChildrenCount, ForkError};

use serde::{Deserialize, Serialize};
pub use tfhe_csprng::generators::{
    ParallelRandomGenerator as ParallelByteRandomGenerator, RandomGenerator as ByteRandomGenerator,
};
use tfhe_csprng::seeders::SeedKind;
pub use tfhe_csprng::seeders::{Seed, Seeder, XofSeed};
use tfhe_versionable::Versionize;

#[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize, Versionize)]
#[versionize(CompressionSeedVersions)]
/// New type to manage seeds used for compressed/seeded types.
pub struct CompressionSeed {
    pub seed: Seed,
}

impl From<Seed> for CompressionSeed {
    fn from(seed: Seed) -> Self {
        Self { seed }
    }
}

/// A cryptographically secure random number generator.
///
/// This csprng is used by every objects that needs sampling in the library. If the proper
/// instructions are available on the machine, it will use an hardware-accelerated variant for
/// the generation. If not, a fallback software version will be used.
///
/// # Safe multithreaded use
///
/// When using a csprng in a multithreaded setting, it is important to make sure that the same
/// sequence of bytes is not generated twice on two different threads. This csprng offers a
/// simple way to ensure that: any generator can be _forked_ into several _bounded_ generators,
/// which are able to sample a fixed number of bytes. This forking operation has the effect of
/// shifting the state of the parent generator accordingly. This way, the children generators can be
/// used by the different threads safely:
///
/// ```rust
/// use tfhe::core_crypto::commons::math::random::RandomGenerator;
/// use tfhe_csprng::generators::SoftwareRandomGenerator;
/// use tfhe_csprng::seeders::Seed;
/// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
/// assert_eq!(generator.remaining_bytes(), None); // The generator is unbounded.
/// let children = generator
///     .try_fork(5, 2) // 5 generators each able to generate 2 bytes.
///     .unwrap()
///     .collect::<Vec<_>>();
/// for child in children.into_iter() {
///     assert_eq!(child.remaining_bytes(), Some(2));
///     std::thread::spawn(move || {
///         let child = child;
///         // use the prng to generate 2 bytes.
///         // ...
///     });
/// }
/// // use the parent to generate as many bytes as needed.
/// ```
pub struct RandomGenerator<G: ByteRandomGenerator>(G);

impl<G: ByteRandomGenerator> RandomGenerator<G> {
    pub fn generate_next(&mut self) -> u8 {
        self.0.next_byte().unwrap()
    }

    /// Generate a new generator, optionally seeding it with the given value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// ```
    pub fn new(seed: impl Into<SeedKind>) -> Self {
        Self(G::new(seed))
    }

    /// Return the number of bytes that can still be generated, if the generator is bounded.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// assert_eq!(generator.remaining_bytes(), None);
    /// let generator = generator.try_fork(1, 50).unwrap().next().unwrap();
    /// assert_eq!(generator.remaining_bytes(), Some(50));
    /// ```
    pub fn remaining_bytes(&self) -> Option<usize> {
        <u128 as TryInto<usize>>::try_into(self.0.remaining_bytes().0).ok()
    }

    /// Tries to fork the current generator into `n_child` generator bounded to `bytes_per_child`.
    /// If `n_child*bytes_per_child` exceeds the bound of the current generator, the method
    /// returns `None`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let children = generator.try_fork(5, 50).unwrap().collect::<Vec<_>>();
    /// ```
    pub fn try_fork(
        &mut self,
        n_child: usize,
        bytes_per_child: usize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        self.0
            .try_fork(
                ChildrenCount(n_child as u64),
                BytesPerChild(bytes_per_child as u64),
            )
            .map(|iter| iter.map(Self))
    }

    /// Generate a random scalar from the given distribution under the native modulus.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::{Gaussian, RandomGenerator, Uniform};
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    ///
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    ///
    /// let random = generator.random_from_distribution::<u8, _>(Uniform);
    /// let random = generator.random_from_distribution::<i8, _>(Uniform);
    /// let random = generator.random_from_distribution::<u64, _>(Gaussian {
    ///     mean: 0.0,
    ///     std: 1.0,
    /// });
    /// ```
    pub fn random_from_distribution<Scalar, D>(&mut self, distribution: D) -> Scalar
    where
        D: Distribution,
        Scalar: RandomGenerable<D>,
    {
        Scalar::generate_one(self, distribution)
    }

    /// Generate a random unsigned integer from the given distribution under a custom modulus. This
    /// is only supported for unsigned integers for now.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
    /// use tfhe::core_crypto::commons::math::random::{Gaussian, RandomGenerator, Uniform};
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    ///
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    ///
    /// let custom_modulus = CiphertextModulus::new((1 << 64) - (1 << 32) + 1);
    ///
    /// let random = generator.random_from_distribution_custom_mod::<u64, _>(Uniform, custom_modulus);
    /// let random = generator.random_from_distribution_custom_mod::<u64, _>(
    ///     Gaussian {
    ///         mean: 0.0,
    ///         std: 1.0,
    ///     },
    ///     custom_modulus,
    /// );
    /// ```
    pub fn random_from_distribution_custom_mod<Scalar, D>(
        &mut self,
        distribution: D,
        custom_modulus: CiphertextModulus<Scalar>,
    ) -> Scalar
    where
        D: Distribution,
        Scalar: UnsignedInteger + RandomGenerable<D, CustomModulus = Scalar>,
    {
        if custom_modulus.is_native_modulus() {
            return self.random_from_distribution(distribution);
        }

        Scalar::generate_one_custom_modulus(
            self,
            distribution,
            custom_modulus.get_custom_modulus().cast_into(),
        )
    }

    /// Generate a random scalar from the given distribution under the native modulus.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::{Gaussian, RandomGenerator, Uniform};
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    ///
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    ///
    /// let mut random = vec![0u8; 8];
    /// generator.fill_slice_with_random_from_distribution(&mut random, Uniform);
    /// let mut random = vec![0i8; 8];
    /// generator.fill_slice_with_random_from_distribution(&mut random, Uniform);
    /// let mut random = vec![0u64; 8];
    /// generator.fill_slice_with_random_from_distribution(
    ///     &mut random,
    ///     Gaussian {
    ///         mean: 0.0,
    ///         std: 1.0,
    ///     },
    /// );
    /// ```
    pub fn fill_slice_with_random_from_distribution<Scalar, D>(
        &mut self,
        output: &mut [Scalar],
        distribution: D,
    ) where
        D: Distribution,
        Scalar: RandomGenerable<D>,
    {
        Scalar::fill_slice(self, distribution, output);
    }

    /// Generate a random unsigned integer from the given distribution under a custom modulus. This
    /// is only supported for unsigned integers for now.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
    /// use tfhe::core_crypto::commons::math::random::{Gaussian, RandomGenerator, Uniform};
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    ///
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    ///
    /// let custom_modulus = CiphertextModulus::new((1 << 64) - (1 << 32) + 1);
    ///
    /// let mut random = vec![0u64; 8];
    /// generator.fill_slice_with_random_from_distribution_custom_mod(
    ///     &mut random,
    ///     Uniform,
    ///     custom_modulus,
    /// );
    /// let mut random = vec![0u64; 8];
    /// generator.fill_slice_with_random_from_distribution_custom_mod(
    ///     &mut random,
    ///     Gaussian {
    ///         mean: 0.0,
    ///         std: 1.0,
    ///     },
    ///     custom_modulus,
    /// );
    /// ```
    pub fn fill_slice_with_random_from_distribution_custom_mod<Scalar, D>(
        &mut self,
        output: &mut [Scalar],
        distribution: D,
        custom_modulus: CiphertextModulus<Scalar>,
    ) where
        D: Distribution,
        Scalar: UnsignedInteger + RandomGenerable<D, CustomModulus = Scalar>,
    {
        if custom_modulus.is_native_modulus() {
            return self.fill_slice_with_random_from_distribution(output, distribution);
        }

        Scalar::fill_slice_custom_mod(
            self,
            distribution,
            output,
            custom_modulus.get_custom_modulus().cast_into(),
        )
    }

    /// Add a random scalar from the given distribution under the native modulus.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::{Gaussian, RandomGenerator, Uniform};
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    ///
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    ///
    /// let mut random = vec![0u8; 8];
    /// generator
    ///     .unsigned_integer_slice_wrapping_add_random_from_distribution_assign(&mut random, Uniform);
    /// let mut random = vec![0u64; 8];
    /// generator.unsigned_integer_slice_wrapping_add_random_from_distribution_assign(
    ///     &mut random,
    ///     Gaussian {
    ///         mean: 0.0,
    ///         std: 1.0,
    ///     },
    /// );
    /// ```
    pub fn unsigned_integer_slice_wrapping_add_random_from_distribution_assign<Scalar, D>(
        &mut self,
        output: &mut [Scalar],
        distribution: D,
    ) where
        D: Distribution,
        Scalar: UnsignedInteger + RandomGenerable<D>,
    {
        for x in output.iter_mut() {
            let random = Scalar::generate_one(self, distribution);
            *x = (*x).wrapping_add(random);
        }
    }
    /// Add a random gaussian value to each element in a slice.
    ///
    /// # Example
    ///
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
    /// use tfhe::core_crypto::commons::math::random::{Gaussian, RandomGenerator, Uniform};
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    ///
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    ///
    /// let custom_mod_u8 = CiphertextModulus::try_new_power_of_2(7).unwrap();
    /// let mut random = vec![0u8; 8];
    /// generator.unsigned_integer_slice_wrapping_add_random_from_distribution_custom_mod_assign(
    ///     &mut random,
    ///     Uniform,
    ///     custom_mod_u8,
    /// );
    ///
    /// let custom_mod_u64 = CiphertextModulus::try_new_power_of_2(63).unwrap();
    /// let mut random = vec![0u64; 8];
    /// generator.unsigned_integer_slice_wrapping_add_random_from_distribution_custom_mod_assign(
    ///     &mut random,
    ///     Gaussian {
    ///         mean: 0.0,
    ///         std: 1.0,
    ///     },
    ///     custom_mod_u64,
    /// );
    /// ```
    pub fn unsigned_integer_slice_wrapping_add_random_from_distribution_custom_mod_assign<
        Scalar,
        D,
    >(
        &mut self,
        output: &mut [Scalar],
        distribution: D,
        custom_modulus: CiphertextModulus<Scalar>,
    ) where
        D: Distribution,
        Scalar: UnsignedInteger + RandomGenerable<D, CustomModulus = Scalar>,
    {
        if custom_modulus.is_native_modulus() {
            self.unsigned_integer_slice_wrapping_add_random_from_distribution_assign(
                output,
                distribution,
            );
            return;
        }

        let custom_modulus_as_scalar: Scalar = custom_modulus.get_custom_modulus().cast_into();
        for x in output.iter_mut() {
            let random =
                Scalar::generate_one_custom_modulus(self, distribution, custom_modulus_as_scalar);
            *x = (*x).wrapping_add_custom_mod(random, custom_modulus_as_scalar);
        }
    }

    /// Generate a random uniform unsigned integer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    ///
    /// let random = generator.random_uniform::<u8>();
    /// let random = generator.random_uniform::<u16>();
    /// let random = generator.random_uniform::<u32>();
    /// let random = generator.random_uniform::<u64>();
    /// let random = generator.random_uniform::<u128>();
    ///
    /// let random = generator.random_uniform::<i8>();
    /// let random = generator.random_uniform::<i16>();
    /// let random = generator.random_uniform::<i32>();
    /// let random = generator.random_uniform::<i64>();
    /// let random = generator.random_uniform::<i128>();
    /// ```
    pub fn random_uniform<Scalar>(&mut self) -> Scalar
    where
        Scalar: RandomGenerable<Uniform>,
    {
        Scalar::generate_one(self, Uniform)
    }

    /// Generate a random uniform unsigned integer. This is only supported for unsigned integers at
    /// the moment.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    ///
    /// let random =
    ///     generator.random_uniform_custom_mod::<u8>(CiphertextModulus::try_new(1 << 8).unwrap());
    /// let random =
    ///     generator.random_uniform_custom_mod::<u16>(CiphertextModulus::try_new(1 << 8).unwrap());
    /// let random =
    ///     generator.random_uniform_custom_mod::<u32>(CiphertextModulus::try_new(1 << 8).unwrap());
    /// let random =
    ///     generator.random_uniform_custom_mod::<u64>(CiphertextModulus::try_new(1 << 8).unwrap());
    /// let random =
    ///     generator.random_uniform_custom_mod::<u128>(CiphertextModulus::try_new(1 << 8).unwrap());
    /// ```
    pub fn random_uniform_custom_mod<Scalar>(
        &mut self,
        custom_modulus: CiphertextModulus<Scalar>,
    ) -> Scalar
    where
        Scalar: UnsignedInteger + RandomGenerable<Uniform, CustomModulus = Scalar>,
    {
        if custom_modulus.is_native_modulus() {
            return self.random_uniform();
        }

        Scalar::generate_one_custom_modulus(
            self,
            Uniform,
            custom_modulus.get_custom_modulus().cast_into(),
        )
    }

    /// Fill a slice with random uniform values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut vec = vec![0u32; 1000];
    /// generator.fill_slice_with_random_uniform(&mut vec);
    /// assert!(vec.iter().any(|&x| x != 0));
    /// ```
    pub fn fill_slice_with_random_uniform<Scalar>(&mut self, output: &mut [Scalar])
    where
        Scalar: RandomGenerable<Uniform>,
    {
        Scalar::fill_slice(self, Uniform, output);
    }

    /// Fill a slice with random uniform values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::parameters::CiphertextModulus;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut vec = vec![0u32; 1000];
    /// generator.fill_slice_with_random_uniform_custom_mod(
    ///     &mut vec,
    ///     CiphertextModulus::try_new_power_of_2(31).unwrap(),
    /// );
    /// assert!(vec.iter().any(|&x| x != 0));
    /// ```
    pub fn fill_slice_with_random_uniform_custom_mod<Scalar>(
        &mut self,
        output: &mut [Scalar],
        custom_modulus: CiphertextModulus<Scalar>,
    ) where
        Scalar: UnsignedInteger + RandomGenerable<Uniform, CustomModulus = Scalar>,
    {
        if custom_modulus.is_native_modulus() {
            self.fill_slice_with_random_uniform(output);
            return;
        }

        // This needs to be our Scalar in the RandomGenerable implementation
        let custom_modulus_scalar: Scalar = custom_modulus.get_custom_modulus().cast_into();
        Scalar::fill_slice_custom_mod(self, Uniform, output, custom_modulus_scalar);
    }

    /// Generate a random uniform binary value.
    /// This will draw one full byte from the underlying csprng.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let random: u32 = generator.random_uniform_binary();
    /// ```
    pub fn random_uniform_binary<Scalar>(&mut self) -> Scalar
    where
        Scalar: RandomGenerable<UniformBinary>,
    {
        Scalar::generate_one(self, UniformBinary)
    }

    /// Fill a slice with random uniform binary values.
    /// This will draw one full byte from the underlying csprng for every element of the slice.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut vec = vec![0u32; 1000];
    /// generator.fill_slice_with_random_uniform_binary(&mut vec);
    /// assert!(vec.iter().any(|&x| x != 0));
    /// ```
    pub fn fill_slice_with_random_uniform_binary<Scalar>(&mut self, output: &mut [Scalar])
    where
        Scalar: RandomGenerable<UniformBinary>,
    {
        Scalar::fill_slice(self, UniformBinary, output);
    }

    /// Fill a slice with random uniform binary values.
    /// This will only draw as many bytes needed from the underlying csprng to fill the slice with
    /// random bits. If the slice len is n, it will draw ceil(n/8) bytes from the csprng.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut vec = vec![0u32; 1000];
    /// generator.fill_slice_with_random_uniform_binary_bits(&mut vec);
    /// assert!(vec.iter().any(|&x| x != 0));
    /// ```
    pub fn fill_slice_with_random_uniform_binary_bits<Scalar>(&mut self, output: &mut [Scalar])
    where
        Scalar: UnsignedInteger,
    {
        for chunk in output.chunks_mut(8) {
            let mut random_byte = self.generate_next();
            for elem in chunk {
                *elem = Scalar::from((random_byte & 1) == 1);
                random_byte >>= 1;
            }
        }
    }

    /// Generate a random uniform ternary value.
    /// This will draw one full byte from the underlying csprng for every element of the slice.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let random: u32 = generator.random_uniform_ternary();
    /// ```
    pub fn random_uniform_ternary<Scalar>(&mut self) -> Scalar
    where
        Scalar: RandomGenerable<UniformTernary>,
    {
        Scalar::generate_one(self, UniformTernary)
    }

    /// Generate two floating point values drawn from a gaussian distribution with input mean and
    /// standard deviation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// // for f32
    /// let (g1, g2): (f32, f32) = generator.random_gaussian(0_f32, 1_f32);
    /// // check that both samples are in 6 sigmas.
    /// assert!(g1.abs() <= 6.);
    /// assert!(g2.abs() <= 6.);
    /// // for f64
    /// let (g1, g2): (f64, f64) = generator.random_gaussian(0_f64, 1_f64);
    /// // check that both samples are in 6 sigmas.
    /// assert!(g1.abs() <= 6.);
    /// assert!(g2.abs() <= 6.);
    /// ```
    pub fn random_gaussian<Float, Scalar>(&mut self, mean: Float, std: Float) -> (Scalar, Scalar)
    where
        Float: FloatingPoint,
        (Scalar, Scalar): RandomGenerable<Gaussian<Float>>,
    {
        <(Scalar, Scalar)>::generate_one(self, Gaussian { std, mean })
    }

    /// Fill a slice with random gaussian values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut vec = vec![0f32; 1000];
    /// generator.fill_slice_with_random_gaussian(&mut vec, 0., 1.);
    /// assert!(vec.iter().any(|&x| x != 0.));
    /// ```
    pub fn fill_slice_with_random_gaussian<Float, Scalar>(
        &mut self,
        output: &mut [Scalar],
        mean: Float,
        std: Float,
    ) where
        Float: FloatingPoint,
        (Scalar, Scalar): RandomGenerable<Gaussian<Float>>,
    {
        output.chunks_mut(2).for_each(|s| {
            let (g1, g2) = <(Scalar, Scalar)>::generate_one(self, Gaussian { std, mean });
            if let Some(elem) = s.get_mut(0) {
                *elem = g1;
            }
            if let Some(elem) = s.get_mut(1) {
                *elem = g2;
            }
        });
    }

    /// Fill a slice with random gaussian values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::parameters::CiphertextModulus;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut vec = vec![0u64; 1000];
    /// generator.fill_slice_with_random_gaussian_custom_mod(
    ///     &mut vec,
    ///     0.,
    ///     1.,
    ///     CiphertextModulus::try_new_power_of_2(63).unwrap(),
    /// );
    /// assert!(vec.iter().any(|&x| x != 0));
    /// ```
    pub fn fill_slice_with_random_gaussian_custom_mod<Float, Scalar>(
        &mut self,
        output: &mut [Scalar],
        mean: Float,
        std: Float,
        custom_modulus: CiphertextModulus<Scalar>,
    ) where
        Float: FloatingPoint,
        Scalar: UnsignedTorus + CastInto<Float>,
        (Scalar, Scalar): RandomGenerable<Gaussian<Float>, CustomModulus = Scalar>,
    {
        if custom_modulus.is_native_modulus() {
            self.fill_slice_with_random_gaussian(output, mean, std);
            return;
        }

        let custom_modulus_as_scalar: Scalar = custom_modulus.get_custom_modulus().cast_into();
        output.chunks_mut(2).for_each(|s| {
            let (g1, g2) = <(Scalar, Scalar)>::generate_one_custom_modulus(
                self,
                Gaussian { std, mean },
                custom_modulus_as_scalar,
            );
            if let Some(elem) = s.get_mut(0) {
                *elem = g1;
            }
            if let Some(elem) = s.get_mut(1) {
                *elem = g2;
            }
        });
    }

    /// Add a random gaussian value to each element in a slice.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut vec = vec![0u32; 1000];
    /// generator.unsigned_torus_slice_wrapping_add_random_gaussian_assign(&mut vec, 0., 1.);
    /// assert!(vec.iter().any(|&x| x != 0));
    /// ```
    pub fn unsigned_torus_slice_wrapping_add_random_gaussian_assign<Float, Scalar>(
        &mut self,
        output: &mut [Scalar],
        mean: Float,
        std: Float,
    ) where
        Scalar: UnsignedTorus,
        Float: FloatingPoint,
        (Scalar, Scalar): RandomGenerable<Gaussian<Float>>,
    {
        output.chunks_mut(2).for_each(|s| {
            let (g1, g2) = <(Scalar, Scalar)>::generate_one(self, Gaussian { std, mean });
            if let Some(elem) = s.get_mut(0) {
                *elem = (*elem).wrapping_add(g1);
            }
            if let Some(elem) = s.get_mut(1) {
                *elem = (*elem).wrapping_add(g2);
            }
        });
    }

    /// Add a random gaussian value to each element in a slice.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::parameters::CiphertextModulus;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut vec = vec![0u32; 1000];
    /// generator.unsigned_torus_slice_wrapping_add_random_gaussian_custom_mod_assign(
    ///     &mut vec,
    ///     0.,
    ///     1.,
    ///     CiphertextModulus::try_new_power_of_2(31).unwrap(),
    /// );
    /// assert!(vec.iter().any(|&x| x != 0));
    /// ```
    pub fn unsigned_torus_slice_wrapping_add_random_gaussian_custom_mod_assign<Float, Scalar>(
        &mut self,
        output: &mut [Scalar],
        mean: Float,
        std: Float,
        custom_modulus: CiphertextModulus<Scalar>,
    ) where
        Float: FloatingPoint,
        Scalar: UnsignedTorus + CastInto<Float>,
        (Scalar, Scalar): RandomGenerable<Gaussian<Float>, CustomModulus = Scalar>,
    {
        if custom_modulus.is_native_modulus() {
            self.unsigned_torus_slice_wrapping_add_random_gaussian_assign(output, mean, std);
            return;
        }

        let custom_modulus_as_scalar: Scalar = custom_modulus.get_custom_modulus().cast_into();
        output.chunks_mut(2).for_each(|s| {
            let (g1, g2) = <(Scalar, Scalar)>::generate_one_custom_modulus(
                self,
                Gaussian { std, mean },
                custom_modulus_as_scalar,
            );
            if let Some(elem) = s.get_mut(0) {
                *elem = (*elem).wrapping_add_custom_mod(g1, custom_modulus_as_scalar);
            }
            if let Some(elem) = s.get_mut(1) {
                *elem = (*elem).wrapping_add_custom_mod(g2, custom_modulus_as_scalar);
            }
        });
    }
}

impl<G: ParallelByteRandomGenerator> RandomGenerator<G> {
    /// Tries to fork the current generator into `n_child` generator bounded to `bytes_per_child`,
    /// as a parallel iterator.
    ///
    /// If `n_child*bytes_per_child` exceeds the bound of the current generator, the method
    /// returns `None`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe_csprng::generators::SoftwareRandomGenerator;
    /// use tfhe_csprng::seeders::Seed;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let children = generator.try_fork(5, 50).unwrap().collect::<Vec<_>>();
    /// ```
    pub fn par_try_fork(
        &mut self,
        n_child: usize,
        bytes_per_child: usize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        self.0
            .par_try_fork(
                ChildrenCount(n_child as u64),
                BytesPerChild(bytes_per_child as u64),
            )
            .map(|iter| iter.map(Self))
    }
}

impl<G: ByteRandomGenerator> rand_core::Rng for RandomGenerator<G> {
    fn next_u32(&mut self) -> u32 {
        <u32 as RandomGenerable<Uniform>>::generate_one(self, Uniform)
    }

    fn next_u64(&mut self) -> u64 {
        <u64 as RandomGenerable<Uniform>>::generate_one(self, Uniform)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = self.generate_next();
        }
    }
}
