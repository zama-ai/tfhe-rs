//! Re-Randomization adds randomness to an existing ciphertext without changing the value it
//! encrypts.
//!
//! This works by encrypting zeros using a public key, then adding theses zeros to the ciphertext.
//! This process is seedable using the [`ReRandomizationContext`] and thus can be used in
//! deterministic contexts. It can be used to achieve sIND-CPAD security.
//!
//! # Example
//!
//! ```rust
//! use tfhe::prelude::*;
//! use tfhe::shortint::parameters::*;
//! use tfhe::{
//!     generate_keys, set_server_key, CompactPublicKey, ConfigBuilder, FheUint64,
//!     ReRandomizationContext,
//! };
//!
//! let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
//! let cpk_params = (
//!     PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
//!     PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
//! );
//! let re_rand_ks_params = PARAM_KEYSWITCH_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
//!
//! let config = ConfigBuilder::with_custom_parameters(params)
//!     .use_dedicated_compact_public_key_parameters(cpk_params)
//!     .enable_ciphertext_re_randomization(re_rand_ks_params)
//!     .build();
//!
//! let (cks, sks) = generate_keys(config);
//! let cpk = CompactPublicKey::new(&cks);
//!
//! let compact_public_encryption_domain_separator = *b"TFHE_Enc";
//! let rerand_domain_separator = *b"TFHE_Rrd";
//!
//! set_server_key(sks);
//!
//! let clear_a = 12u64;
//! let clear_b = 37u64;
//! let mut a = FheUint64::encrypt(clear_a, &cks);
//! let mut b = FheUint64::encrypt(clear_b, &cks);
//!
//! // Simulate a 256 bits hash added as metadata
//! let rand_a: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
//! let rand_b: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
//! a.re_randomization_metadata_mut().set_data(&rand_a);
//! b.re_randomization_metadata_mut().set_data(&rand_b);
//!
//! // Simulate a 256 bits nonce
//! let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
//!
//! let mut re_rand_context = ReRandomizationContext::new(
//!     rerand_domain_separator,
//!     // First is the function description, second is a nonce
//!     [b"FheUint64+FheUint64".as_slice(), nonce.as_slice()],
//!     compact_public_encryption_domain_separator,
//! );
//!
//! // Add ciphertexts to the context
//! re_rand_context.add_ciphertext(&a);
//! re_rand_context.add_ciphertext(&b);
//!
//! let mut seed_gen = re_rand_context.finalize();
//!
//! let a_re_rand = a.re_randomize(&cpk, seed_gen.next_seed()).unwrap();
//! let b_re_rand = b.re_randomize(&cpk, seed_gen.next_seed()).unwrap();
//!
//! let c = a_re_rand + b_re_rand;
//! let dec: u64 = c.decrypt(&cks);
//!
//! assert_eq!(clear_a.wrapping_add(clear_b), dec);
//! ```

use crate::backward_compatibility::cpk_re_randomization::ReRandomizationMetadataVersions;
use crate::core_crypto::commons::math::random::XofSeed;
use crate::high_level_api::keys::CompactPublicKey;
use crate::high_level_api::tag::SmallVec;
use crate::integer::ciphertext::{ReRandomizationSeed, ReRandomizationSeedHasher};
use tfhe_versionable::Versionize;

/// Makes a ciphertext type re-randomizable
pub trait ReRandomize
where
    Self: Sized,
{
    fn add_to_re_randomization_context(&self, context: &mut ReRandomizationContext);

    /// Re-randomize the ciphertext using the provided public key and seed.
    ///
    /// The random elements of the ciphertexts will be changed but it will still encrypt the same
    /// value.
    fn re_randomize(
        &self,
        compact_public_key: &CompactPublicKey,
        seed: ReRandomizationSeed,
    ) -> crate::Result<Self>;
}

/// The context in which the ciphertexts will be used
///
/// It can be updated with user provided elements and will then be finalized into a
/// [`ReRandomizationSeedGen`]
pub struct ReRandomizationContext {
    pub(in crate::high_level_api) inner: crate::integer::ciphertext::ReRandomizationContext,
}

impl ReRandomizationContext {
    /// Create a new re-randomization context with the default seed hasher (blake3).
    ///
    /// The rerand process is seeded in the following way:
    /// - First the context is hashed with the `rerand_root_seed_domain_separator` and the
    ///   `nonce_metadata` to derive a "re-rand root seed".
    /// - Then the "re-rand root seed" is used with the `public_encryption_domain_separator` to
    ///   create a [`DeterministicSeeder`](crate::core_crypto::commons::generators::DeterministicSeeder)
    /// - Finally the
    ///   [`DeterministicSeeder`](crate::core_crypto::commons::generators::DeterministicSeeder) is
    ///   used to generates seeds for the
    ///   [`SecretRandomGenerator`](crate::core_crypto::prelude::SecretRandomGenerator) and the
    ///   [`EncryptionRandomGenerator`](crate::core_crypto::prelude::EncryptionRandomGenerator) used
    ///   to generate the encryptions of zero
    ///
    /// (See [`XofSeed`] for more information)
    ///
    /// # Example
    /// ```rust
    /// use tfhe::ReRandomizationContext;
    /// // Simulate a 256 bits nonce
    /// let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
    /// let _re_rand_context = ReRandomizationContext::new(
    ///     *b"TFHE_Rrd",
    ///     [b"FheUint64+FheUint64".as_slice(), &nonce],
    ///     *b"TFHE_Enc"
    ///  );
    pub fn new<'a>(
        seed_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
        nonce_metadata: impl IntoIterator<Item = &'a [u8]>,
        public_encryption_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
    ) -> Self {
        Self {
            inner: crate::integer::ciphertext::ReRandomizationContext::new(
                seed_domain_separator,
                nonce_metadata,
                public_encryption_domain_separator,
            ),
        }
    }

    /// Create a new re-randomization context with the provided seed hasher.
    pub fn new_with_hasher<'a>(
        nonce_metadata: impl IntoIterator<Item = &'a [u8]>,
        public_encryption_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
        seed_hasher: ReRandomizationSeedHasher,
    ) -> Self {
        Self {
            inner: crate::integer::ciphertext::ReRandomizationContext::new_with_hasher(
                nonce_metadata,
                public_encryption_domain_separator,
                seed_hasher,
            ),
        }
    }

    /// Adds a new ciphertext to the re-randomization context
    pub fn add_ciphertext<Data: ReRandomize>(&mut self, data: &Data) {
        data.add_to_re_randomization_context(self);
    }

    /// Consumes the context to create a seed generator
    pub fn finalize(self) -> ReRandomizationSeedGen {
        ReRandomizationSeedGen {
            inner: self.inner.finalize(),
        }
    }
}

/// A generator that can be used to obtain seeds needed to re-randomize individual ciphertexts
pub struct ReRandomizationSeedGen {
    inner: crate::integer::ciphertext::ReRandomizationSeedGen,
}

impl ReRandomizationSeedGen {
    /// Produce the next seed for this context
    pub fn next_seed(&mut self) -> ReRandomizationSeed {
        self.inner.next_seed()
    }
}

/// Metadata linked to a ciphertext that will be used when updating the [`ReRandomizationContext`]
#[derive(
    Default, Clone, Debug, serde::Serialize, serde::Deserialize, Versionize, PartialEq, Eq,
)]
#[versionize(ReRandomizationMetadataVersions)]
pub struct ReRandomizationMetadata {
    inner: SmallVec,
}

impl ReRandomizationMetadata {
    pub fn new(data: &[u8]) -> Self {
        let mut inner = SmallVec::default();
        inner.set_data(data);

        Self { inner }
    }

    pub fn data(&self) -> &[u8] {
        self.inner.data()
    }

    pub fn set_data(&mut self, data: &[u8]) {
        self.inner.set_data(data);
    }
}
