use crate::core_crypto::commons::math::random::{
    Gaussian, RandomGenerable, Uniform, UniformBinary, UniformLsb, UniformMsb, UniformTernary,
    UniformWithZeros,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::FloatingPoint;
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
pub struct CompressionSeed {
    #[serde(with = "SeedSerdeDef")]
    pub seed: Seed,
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

    /// Generates a new generator, optionally seeding it with the given value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// ```
    pub fn new(seed: Seed) -> RandomGenerator<G> {
        RandomGenerator(G::new(seed))
    }

    /// Returns the number of bytes that can still be generated, if the generator is bounded.
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
    ) -> Result<impl Iterator<Item = RandomGenerator<G>>, ForkError> {
        self.0
            .try_fork(ChildrenCount(n_child), BytesPerChild(bytes_per_child))
            .map(|iter| iter.map(Self))
    }

    /// Generates a random uniform unsigned integer.
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
    pub fn random_uniform<Scalar: RandomGenerable<Uniform>>(&mut self) -> Scalar {
        Scalar::generate_one(self, Uniform)
    }

    /// Fills a slice with random uniform values.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut vec = vec![1u32; 100];
    /// generator.fill_slice_with_random_uniform(&mut vec);
    /// ```
    pub fn fill_slice_with_random_uniform<Scalar>(&mut self, output: &mut [Scalar])
    where
        Scalar: RandomGenerable<Uniform>,
    {
        Scalar::fill_slice(self, Uniform, output);
    }

    /// Generates a random uniform binary value.
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
    pub fn random_uniform_binary<Scalar: RandomGenerable<UniformBinary>>(&mut self) -> Scalar {
        Scalar::generate_one(self, UniformBinary)
    }

    /// Fills a slice with random uniform binary values.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut vec = vec![2u32; 100];
    /// generator.fill_slice_with_random_uniform_binary(&mut vec);
    /// ```
    pub fn fill_slice_with_random_uniform_binary<Scalar>(&mut self, output: &mut [Scalar])
    where
        Scalar: RandomGenerable<UniformBinary>,
    {
        Scalar::fill_slice(self, UniformBinary, output);
    }

    /// Generates a random uniform ternary value.
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
    pub fn random_uniform_ternary<Scalar: RandomGenerable<UniformTernary>>(&mut self) -> Scalar {
        Scalar::generate_one(self, UniformTernary)
    }

    /// Generates an unsigned integer whose n least significant bits are uniformly random, and the
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
    pub fn random_uniform_n_lsb<Scalar: RandomGenerable<UniformLsb>>(
        &mut self,
        n: usize,
    ) -> Scalar {
        Scalar::generate_one(self, UniformLsb { n })
    }

    /// Generates an unsigned integer whose n most significant bits are uniformly random, and the
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
    pub fn random_uniform_n_msb<Scalar: RandomGenerable<UniformMsb>>(
        &mut self,
        n: usize,
    ) -> Scalar {
        Scalar::generate_one(self, UniformMsb { n })
    }

    /// Generates a random uniform unsigned integer with probability `1-prob_zero`, and a zero value
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
    pub fn random_uniform_with_zeros<Scalar: RandomGenerable<UniformWithZeros>>(
        &mut self,
        prob_zero: f32,
    ) -> Scalar {
        Scalar::generate_one(self, UniformWithZeros { prob_zero })
    }

    /// Generates two floating point values drawn from a gaussian distribution with input mean and
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

    /// Fills a slice with random gaussian values.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut vec = vec![1000f32; 100];
    /// generator.fill_slice_with_random_gaussian(&mut vec, 0., 1.);
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

    /// Adds a random gaussian value to each element in a slice.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut vec = vec![1000u32; 100];
    /// generator.unsigned_torus_slice_wrapping_add_random_gaussian_assign(&mut vec, 0., 1.);
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
    ) -> Result<impl IndexedParallelIterator<Item = RandomGenerator<G>>, ForkError> {
        self.0
            .par_try_fork(ChildrenCount(n_child), BytesPerChild(bytes_per_child))
            .map(|iter| iter.map(Self))
    }
}
