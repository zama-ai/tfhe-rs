use crate::core_crypto::commons::math::random::{
    Gaussian, RandomGenerable, Uniform, UniformBinary, UniformLsb, UniformMsb, UniformTernary,
    UniformWithZeros,
};
use crate::core_crypto::commons::math::tensor::{AsMutSlice, AsMutTensor, Tensor};
use crate::core_crypto::commons::numeric::{FloatingPoint, Numeric};
use concrete_csprng::generators::{BytesPerChild, ChildrenCount, ForkError};
#[cfg(feature = "__commons_parallel")]
use rayon::prelude::*;
use std::convert::TryInto;

#[cfg(feature = "__commons_parallel")]
pub use concrete_csprng::generators::ParallelRandomGenerator as ParallelByteRandomGenerator;
pub use concrete_csprng::generators::RandomGenerator as ByteRandomGenerator;
pub use concrete_csprng::seeders::{Seed, Seeder};

/// Module to proxy the serialization for `concrete-csprng::Seed` to avoid adding serde as a
/// dependency to `concrete-csprng`
#[cfg(feature = "__commons_serialization")]
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

#[cfg(feature = "__commons_serialization")]
pub(crate) use serialization_proxy::*;

#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct CompressionSeed {
    #[cfg_attr(feature = "__commons_serialization", serde(with = "SeedSerdeDef"))]
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

    /// Fills an `AsMutTensor` value with random uniform values.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut tensor = Tensor::allocate(1000. as u32, 100);
    /// generator.fill_tensor_with_random_uniform(&mut tensor);
    /// ```
    pub fn fill_tensor_with_random_uniform<Scalar, Tensorable>(&mut self, output: &mut Tensorable)
    where
        Scalar: RandomGenerable<Uniform>,
        Tensorable: AsMutTensor<Element = Scalar>,
    {
        Scalar::fill_tensor(self, Uniform, output);
    }

    pub fn fill_slice_with_random_uniform<Scalar>(&mut self, output: &mut [Scalar])
    where
        Scalar: RandomGenerable<Uniform>,
    {
        Scalar::fill_slice(self, Uniform, output);
    }

    /// Generates a tensor of random uniform values of a given size.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let t: Tensor<Vec<u64>> = generator.random_uniform_tensor(10);
    /// assert_eq!(t.len(), 10);
    /// let first_val = t.get_element(0);
    /// for i in 1..10 {
    ///     assert_ne!(first_val, t.get_element(i));
    /// }
    /// ```
    pub fn random_uniform_tensor<Scalar: RandomGenerable<Uniform>>(
        &mut self,
        size: usize,
    ) -> Tensor<Vec<Scalar>> {
        Scalar::generate_tensor(self, Uniform, size)
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

    /// Fills an `AsMutTensor` value with random binary values.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut tensor = Tensor::allocate(1u32, 100);
    /// generator.fill_tensor_with_random_uniform_binary(&mut tensor);
    /// ```
    pub fn fill_tensor_with_random_uniform_binary<Scalar, Tensorable>(
        &mut self,
        output: &mut Tensorable,
    ) where
        Scalar: RandomGenerable<UniformBinary>,
        Tensorable: AsMutTensor<Element = Scalar>,
    {
        Scalar::fill_tensor(self, UniformBinary, output);
    }

    /// Generates a tensor of random binary values of a given size.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let t: Tensor<Vec<u32>> = generator.random_uniform_binary_tensor(10);
    /// assert_eq!(t.len(), 10);
    /// ```
    pub fn random_uniform_binary_tensor<Scalar: RandomGenerable<UniformBinary>>(
        &mut self,
        size: usize,
    ) -> Tensor<Vec<Scalar>> {
        Scalar::generate_tensor(self, UniformBinary, size)
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

    /// Fills an `AsMutTensor` value with random ternary values.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut tensor = Tensor::allocate(1u32, 100);
    /// generator.fill_tensor_with_random_uniform_ternary(&mut tensor);
    /// ```
    pub fn fill_tensor_with_random_uniform_ternary<Scalar, Tensorable>(
        &mut self,
        output: &mut Tensorable,
    ) where
        Scalar: RandomGenerable<UniformTernary>,
        Tensorable: AsMutTensor<Element = Scalar>,
    {
        Scalar::fill_tensor(self, UniformTernary, output);
    }

    /// Generates a tensor of random ternary values of a given size.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let t: Tensor<Vec<u32>> = generator.random_uniform_ternary_tensor(10);
    /// assert_eq!(t.len(), 10);
    /// ```
    pub fn random_uniform_ternary_tensor<Scalar: RandomGenerable<UniformTernary>>(
        &mut self,
        size: usize,
    ) -> Tensor<Vec<Scalar>> {
        Scalar::generate_tensor(self, UniformTernary, size)
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

    /// Fills an `AsMutTensor` value with random values whose n lsbs are sampled uniformly.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut tensor = Tensor::allocate(0 as u8, 100);
    /// generator.fill_tensor_with_random_uniform_n_lsb(&mut tensor, 3);
    /// ```
    pub fn fill_tensor_with_random_uniform_n_lsb<Scalar, Tensorable>(
        &mut self,
        output: &mut Tensorable,
        n: usize,
    ) where
        Scalar: RandomGenerable<UniformLsb>,
        Tensorable: AsMutTensor<Element = Scalar>,
    {
        Scalar::fill_tensor(self, UniformLsb { n }, output);
    }

    /// Generates a tensor of random uniform values, whose n lsbs are sampled uniformly.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let t: Tensor<Vec<u64>> = generator.random_uniform_n_lsb_tensor(10, 55);
    /// assert_eq!(t.len(), 10);
    /// let first_val = t.get_element(0);
    /// for i in 1..10 {
    ///     assert_ne!(first_val, t.get_element(i));
    /// }
    /// ```
    pub fn random_uniform_n_lsb_tensor<Scalar: RandomGenerable<UniformLsb>>(
        &mut self,
        size: usize,
        n: usize,
    ) -> Tensor<Vec<Scalar>> {
        Scalar::generate_tensor(self, UniformLsb { n }, size)
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

    /// Fills an `AsMutTensor` value with values whose n msbs are random.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut tensor = Tensor::allocate(8 as u8, 100);
    /// generator.fill_tensor_with_random_uniform_n_msb(&mut tensor, 5);
    /// ```
    pub fn fill_tensor_with_random_uniform_n_msb<Scalar, Tensorable>(
        &mut self,
        output: &mut Tensorable,
        n: usize,
    ) where
        Scalar: RandomGenerable<UniformMsb>,
        Tensorable: AsMutTensor<Element = Scalar>,
    {
        Scalar::fill_tensor(self, UniformMsb { n }, output)
    }

    /// Generates a tensor of random uniform values, whose n msbs are sampled uniformly.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let t: Tensor<Vec<u64>> = generator.random_uniform_n_msb_tensor(10, 55);
    /// assert_eq!(t.len(), 10);
    /// let first_val = t.get_element(0);
    /// for i in 1..10 {
    ///     assert_ne!(first_val, t.get_element(i));
    /// }
    /// ```
    pub fn random_uniform_n_msb_tensor<Scalar: RandomGenerable<UniformMsb>>(
        &mut self,
        size: usize,
        n: usize,
    ) -> Tensor<Vec<Scalar>> {
        Scalar::generate_tensor(self, UniformMsb { n }, size)
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

    /// Fills an `AsMutTensor` value with random values uniform with probability `prob` and zero
    /// with probability `1-prob`.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut tensor = Tensor::allocate(10 as u8, 100);
    /// generator.fill_tensor_with_random_uniform_with_zeros(&mut tensor, 0.5);
    /// ```
    pub fn fill_tensor_with_random_uniform_with_zeros<Scalar, Tensorable>(
        &mut self,
        output: &mut Tensorable,
        prob_zero: f32,
    ) where
        Scalar: RandomGenerable<UniformWithZeros>,
        Tensorable: AsMutTensor<Element = Scalar>,
    {
        output.as_mut_tensor().iter_mut().for_each(|s| {
            *s = self.random_uniform_with_zeros(prob_zero);
        });
    }

    /// Generates a tensor of a given size, whose coefficients are random uniform with probability
    /// `1-prob_zero`, and zero with probability `prob_zero`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let t: Tensor<Vec<u64>> = generator.random_uniform_with_zeros_tensor(10, 0.);
    /// assert_eq!(t.len(), 10);
    /// t.iter().for_each(|a| assert_ne!(*a, 0));
    /// let t: Tensor<Vec<u64>> = generator.random_uniform_with_zeros_tensor(10, 1.);
    /// t.iter().for_each(|a| assert_eq!(*a, 0));
    /// ```
    pub fn random_uniform_with_zeros_tensor<Scalar: RandomGenerable<UniformWithZeros>>(
        &mut self,
        size: usize,
        prob_zero: f32,
    ) -> Tensor<Vec<Scalar>> {
        (0..size)
            .map(|_| self.random_uniform_with_zeros(prob_zero))
            .collect()
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

    /// Fills an `AsMutTensor` value with random gaussian values.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let mut tensor = Tensor::allocate(1000. as f32, 100);
    /// generator.fill_tensor_with_random_gaussian(&mut tensor, 0., 1.);
    /// tensor.iter().for_each(|t| assert_ne!(*t, 1000.));
    /// ```
    pub fn fill_tensor_with_random_gaussian<Float, Scalar, Tensorable>(
        &mut self,
        output: &mut Tensorable,
        mean: Float,
        std: Float,
    ) where
        Float: FloatingPoint,
        (Scalar, Scalar): RandomGenerable<Gaussian<Float>>,
        Tensorable: AsMutTensor<Element = Scalar>,
    {
        output
            .as_mut_tensor()
            .as_mut_slice()
            .chunks_mut(2)
            .for_each(|s| {
                let (g1, g2) = <(Scalar, Scalar)>::generate_one(self, Gaussian { std, mean });
                if let Some(elem) = s.get_mut(0) {
                    *elem = g1;
                }
                if let Some(elem) = s.get_mut(1) {
                    *elem = g2;
                }
            });
    }

    /// Generates a new tensor of floating point values, randomly sampled from a gaussian
    /// distribution:
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_csprng::generators::SoftwareRandomGenerator;
    /// use concrete_csprng::seeders::Seed;
    /// use tfhe::core_crypto::commons::math::random::RandomGenerator;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// let mut generator = RandomGenerator::<SoftwareRandomGenerator>::new(Seed(0));
    /// let tensor: Tensor<Vec<f32>> = generator.random_gaussian_tensor(10_000, 0. as f32, 1. as f32);
    /// assert_eq!(tensor.len(), 10_000);
    /// tensor.iter().for_each(|a| assert!((*a).abs() <= 6.));
    /// ```
    pub fn random_gaussian_tensor<Float, Scalar>(
        &mut self,
        size: usize,
        mean: Float,
        std: Float,
    ) -> Tensor<Vec<Scalar>>
    where
        Float: FloatingPoint,
        (Scalar, Scalar): RandomGenerable<Gaussian<Float>>,
        Scalar: Numeric,
    {
        let mut tensor = Tensor::allocate(Scalar::ZERO, size);
        self.fill_tensor_with_random_gaussian(&mut tensor, mean, std);
        tensor
    }
}

#[cfg(feature = "__commons_parallel")]
impl<G: ParallelByteRandomGenerator> RandomGenerator<G> {
    /// Tries to fork the current generator into `n_child` generator bounded to `bytes_per_child`,
    /// as a parallel iterator.
    ///
    /// If `n_child*bytes_per_child` exceeds the bound of the current generator, the method
    /// returns `None`.
    ///
    /// # Notes
    ///
    /// This method necessitates the "__commons_parallel" feature to be used.
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
