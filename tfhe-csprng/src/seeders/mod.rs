//! A module containing seeders objects.
//!
//! When initializing a generator, one needs to provide a [`Seed`], which is then used as key to the
//! AES blockcipher. As a consequence, the quality of the outputs of the generator is directly
//! conditioned by the quality of this seed. This module proposes different mechanisms to deliver
//! seeds that can accommodate varying scenarios.

/// A seed value, used to initialize a generator.
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, Versionize)]
#[versionize(SeedVersions)]
pub struct Seed(pub u128);

/// A Seed as described in the [Threshold (Fully) Homomorphic Encryption]
///
/// This seed contains 2 information:
/// * The domain separator bytes (ASCII string)
/// * The seed bytes
///
/// [Threshold (Fully) Homomorphic Encryption]: https://eprint.iacr.org/2025/699
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, Versionize)]
#[versionize(XofSeedVersions)]
pub struct XofSeed {
    // We store the domain separator concatenated with the seed bytes (str||seed)
    // as it makes it easier to create the iterator of u128 blocks
    data: Vec<u8>,
}

impl XofSeed {
    pub const DOMAIN_SEP_LEN: usize = 8;

    // Creates a new seed of 128 bits
    pub fn new_u128(seed: u128, domain_separator: [u8; Self::DOMAIN_SEP_LEN]) -> Self {
        let mut data = vec![0u8; size_of::<u128>() + domain_separator.len()];
        data[..Self::DOMAIN_SEP_LEN].copy_from_slice(domain_separator.as_slice());
        data[Self::DOMAIN_SEP_LEN..].copy_from_slice(seed.to_le_bytes().as_slice());

        Self { data }
    }

    pub fn new(mut seed: Vec<u8>, domain_separator: [u8; Self::DOMAIN_SEP_LEN]) -> Self {
        seed.resize(domain_separator.len() + seed.len(), 0);
        seed.rotate_right(domain_separator.len());
        seed[..Self::DOMAIN_SEP_LEN].copy_from_slice(domain_separator.as_slice());
        Self { data: seed }
    }

    /// Returns the seed part
    pub fn seed(&self) -> &[u8] {
        &self.data[Self::DOMAIN_SEP_LEN..]
    }

    /// Returns the domain separator
    pub fn domain_separator(&self) -> [u8; Self::DOMAIN_SEP_LEN] {
        let mut sep = [0u8; Self::DOMAIN_SEP_LEN];
        sep.copy_from_slice(&self.data[..Self::DOMAIN_SEP_LEN]);
        sep
    }

    /// Total len (seed bytes + domain separator) in bits
    pub fn bit_len(&self) -> u128 {
        (self.data.len()) as u128 * 8
    }

    /// Returns an iterator that iterates over the concatenated seed||domain_separator
    /// as blocks of u128 bits
    pub(crate) fn iter_u128_blocks(&self) -> impl Iterator<Item = u128> + '_ {
        self.data.chunks(size_of::<u128>()).map(move |chunk| {
            let mut buf = [0u8; size_of::<u128>()];
            buf[..chunk.len()].copy_from_slice(chunk);
            u128::from_ne_bytes(buf)
        })
    }

    /// Creates a new XofSeed from raw bytes.
    ///
    /// # Panics
    ///
    /// Panics if the provided data is smaller than the domain separator length
    pub fn from_bytes(data: Vec<u8>) -> Self {
        assert!(
            data.len() >= Self::DOMAIN_SEP_LEN,
            "XofSeed must be at least {} bytes long (got {})",
            Self::DOMAIN_SEP_LEN,
            data.len()
        );
        Self { data }
    }

    pub fn bytes(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SeedKindVersions)]
pub enum SeedKind {
    /// Initializes the Aes-Ctr with a counter starting at 0
    /// and uses the seed as the Aes key.
    Ctr(Seed),
    /// Seed that initialized the Aes-Ctr following the Threshold (Fully) Homomorphic Encryption
    /// document (see [XofSeed]).
    ///
    /// An Aes-Key and starting counter will be derived from the XofSeed, to
    /// then initialize the Aes-Ctr random generator
    Xof(XofSeed),
}

impl From<Seed> for SeedKind {
    fn from(value: Seed) -> Self {
        Self::Ctr(value)
    }
}

impl From<XofSeed> for SeedKind {
    fn from(value: XofSeed) -> Self {
        Self::Xof(value)
    }
}

/// A trait representing a seeding strategy.
pub trait Seeder {
    /// Generates a new seed.
    fn seed(&mut self) -> Seed;

    /// Check whether the seeder can be used on the current machine. This function may check if some
    /// required CPU features are available or if some OS features are available for example.
    fn is_available() -> bool
    where
        Self: Sized;
}

pub mod backward_compatibility;
mod implem;
// This import statement can be empty if seeder features are disabled, rustc's behavior changed to
// warn of empty modules, we know this can happen, so allow it.
#[allow(unused_imports)]
pub use implem::*;
use tfhe_versionable::Versionize;

use crate::seeders::backward_compatibility::{SeedKindVersions, SeedVersions, XofSeedVersions};

#[cfg(test)]
mod generic_tests {
    use crate::seeders::{Seeder, XofSeed};

    /// Naively verifies that two fixed-size sequences generated by repeatedly calling the seeder
    /// are different.
    #[allow(unused)] // to please clippy when tests are not activated
    pub fn check_seeder_fixed_sequences_different<S: Seeder, F: Fn(u128) -> S>(
        construct_seeder: F,
    ) {
        const SEQUENCE_SIZE: usize = 500;
        const REPEATS: usize = 10_000;
        for i in 0..REPEATS {
            let mut seeder = construct_seeder(i as u128);
            let orig_seed = seeder.seed();
            for _ in 0..SEQUENCE_SIZE {
                assert_ne!(seeder.seed(), orig_seed);
            }
        }
    }

    #[test]
    fn test_xof_seed_getters() {
        let seed_bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let bits = u128::from_le_bytes(seed_bytes);
        let dsep = [b't', b'f', b'h', b'e', b'k', b's', b'p', b's'];
        let seed = XofSeed::new_u128(bits, dsep);

        let s = u128::from_le_bytes(seed.seed().try_into().unwrap());
        assert_eq!(s, bits);
        assert_eq!(seed.domain_separator(), dsep);
        assert_eq!(seed.bit_len(), 192);

        let collected_u128s = seed.iter_u128_blocks().collect::<Vec<_>>();
        // Those u128 are used in AES computations and are just a way to handle a [u8; 16] so those
        // are ok to check in ne_bytes
        assert_eq!(
            collected_u128s,
            vec![
                u128::from_ne_bytes([
                    b't', b'f', b'h', b'e', b'k', b's', b'p', b's', 1, 2, 3, 4, 5, 6, 7, 8
                ]),
                u128::from_ne_bytes([9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0]),
            ]
        );

        // To make sure both constructors yield the same results
        let seed2 = XofSeed::new(seed_bytes.to_vec(), dsep);
        assert_eq!(seed.data, seed2.data);
    }
}
