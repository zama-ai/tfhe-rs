use crate::core_crypto::commons::math::random::{
    Gaussian, RandomGenerable, Uniform, UniformBinary, UniformLsb, UniformMsb, UniformTernary,
    UniformWithZeros,
};
use crate::core_crypto::commons::math::torus::{UnsignedInteger, UnsignedTorus};
use crate::core_crypto::commons::numeric::{CastInto, FloatingPoint};
use crate::core_crypto::commons::parameters::CiphertextModulus;
use concrete_csprng::generators::{BytesPerChild, ChildrenCount, ForkError};
use rayon::prelude::*;
use std::convert::TryInto;

pub use concrete_csprng::generators::{
    ParallelRandomGenerator as ParallelByteRandomGenerator, RandomGenerator as ByteRandomGenerator,
};
pub use concrete_csprng::seeders::{Seed, Seeder};

/// Module to proxy the serialization for `concrete-csprng::Seed` to avoid adding serde as a
/// dependency to `concrete-csprng`
pub mod serialization_proxy {
    pub(crate) use concrete_csprng::seeders::Seed;
    pub(crate) use serde::{Deserialize, Serialize};

    // See https://serde.rs/remote-derive.html
    // Serde calls this the definition of the remote type. It is just a copy of the remote data
    // structure. The `remote` attribute gives the path to the actual type we intend to derive code
    // for. This avoids having to introduce serde in concrete-csprng
    #[derive(Serialize, Deserialize)]
    #[serde(remote = "Seed")]
    pub(crate) struct SeedSerdeDef(pub u128);
}

pub(crate) use serialization_proxy::*;

#[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
/// New type to manage seeds used for compressed/seeded types.
pub struct CompressionSeed {
    #[serde(with = "SeedSerdeDef")]
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
/// use concrete_csprng::generators::SoftwareRandomGenerator;
/// use concrete_csprng::seeders::Seed;
/// use tfhe::core_crypto::commons::math::random::RandomGenerator;
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
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// ```
    pub fn new(seed: Seed) -> Self {
        Self(G::new(seed))
    }

    /// Return the number of bytes that can still be generated, if the generator is bounded.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// assert_eq!(generator.remaining_bytes(), None);
    /// let mut generator = generator.try_fork(1, 50).unwrap().next().unwrap();
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
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let children = generator.try_fork(5, 50).unwrap().collect::<Vec<_>>();
    /// ```
    pub fn try_fork(
        &mut self,
        n_child: usize,
        bytes_per_child: usize,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        self.0
            .try_fork(ChildrenCount(n_child), BytesPerChild(bytes_per_child))
            .map(|iter| iter.map(Self))
    }

    /// Generate a random uniform unsigned integer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
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
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
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
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
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
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::parameters::CiphertextModulus;
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
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
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
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
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

    /// Generate a random uniform ternary value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let random: u32 = generator.random_uniform_ternary();
    /// ```
    pub fn random_uniform_ternary<Scalar>(&mut self) -> Scalar
    where
        Scalar: RandomGenerable<UniformTernary>,
    {
        Scalar::generate_one(self, UniformTernary)
    }

    /// Generate an unsigned integer whose n least significant bits are uniformly random, and the
    /// other bits are zero.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let random: u8 = generator.random_uniform_n_lsb(3);
    /// assert!(random <= 7 as u8);
    /// ```
    pub fn random_uniform_n_lsb<Scalar>(&mut self, n: usize) -> Scalar
    where
        Scalar: RandomGenerable<UniformLsb>,
    {
        Scalar::generate_one(self, UniformLsb { n })
    }

    /// Generate an unsigned integer whose n most significant bits are uniformly random, and the
    /// other bits are zero.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let random: u8 = generator.random_uniform_n_msb(3);
    /// assert!(random == 0 || random >= 32);
    /// ```
    pub fn random_uniform_n_msb<Scalar>(&mut self, n: usize) -> Scalar
    where
        Scalar: RandomGenerable<UniformMsb>,
    {
        Scalar::generate_one(self, UniformMsb { n })
    }

    /// Generate a random uniform unsigned integer with probability `1-prob_zero`, and a zero value
    /// with probability `prob_zero`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let random = generator.random_uniform_with_zeros::<u8>(0.5);
    /// let random = generator.random_uniform_with_zeros::<u16>(0.5);
    /// let random = generator.random_uniform_with_zeros::<u32>(0.5);
    /// let random = generator.random_uniform_with_zeros::<u64>(0.5);
    /// let random = generator.random_uniform_with_zeros::<u128>(0.5);
    /// assert_eq!(generator.random_uniform_with_zeros::<u128>(1.), 0);
    /// assert_ne!(generator.random_uniform_with_zeros::<u128>(0.), 0);
    /// ```
    pub fn random_uniform_with_zeros<Scalar>(&mut self, prob_zero: f32) -> Scalar
    where
        Scalar: RandomGenerable<UniformWithZeros>,
    {
        Scalar::generate_one(self, UniformWithZeros { prob_zero })
    }

    /// Generate two floating point values drawn from a gaussian distribution with input mean and
    /// standard deviation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// // for f32
    /// let (g1, g2): (f32, f32) = generator.random_gaussian(0. as f32, 1. as f32);
    /// // check that both samples are in 6 sigmas.
    /// assert!(g1.abs() <= 6.);
    /// assert!(g2.abs() <= 6.);
    /// // for f64
    /// let (g1, g2): (f64, f64) = generator.random_gaussian(0. as f64, 1. as f64);
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
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
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
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::parameters::CiphertextModulus;
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
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
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
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::parameters::CiphertextModulus;
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
                *elem = (*elem).wrapping_add(g1);
            }
            if let Some(elem) = s.get_mut(1) {
                *elem = (*elem).wrapping_add(g2);
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
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let children = generator.try_fork(5, 50).unwrap().collect::<Vec<_>>();
    /// ```
    pub fn par_try_fork(
        &mut self,
        n_child: usize,
        bytes_per_child: usize,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        self.0
            .par_try_fork(ChildrenCount(n_child), BytesPerChild(bytes_per_child))
            .map(|iter| iter.map(Self))
    }
}
