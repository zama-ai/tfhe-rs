// This is linked to the standard ciphertext but has special code in it

use crate::core_crypto::commons::math::random::XofSeed;
use crate::integer::ciphertext::AsShortintCiphertextSlice;
use crate::integer::key_switching_key::KeySwitchingKeyMaterialView;
use crate::integer::CompactPublicKey;
pub use crate::shortint::ciphertext::{ReRandomizationSeed, ReRandomizationSeedHasher};
use crate::shortint::Ciphertext;

pub struct ReRandomizationContext {
    inner: crate::shortint::ciphertext::ReRandomizationContext,
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
    /// use tfhe::integer::ciphertext::ReRandomizationContext;
    /// // Simulate a 256 bits nonce
    /// let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
    /// let _re_rand_context = ReRandomizationContext::new(
    ///     *b"TFHE_Rrd",
    ///     [b"FheUint64+FheUint64".as_slice(), &nonce],
    ///     *b"TFHE_Enc"
    ///  );
    pub fn new<'a>(
        rerand_root_seed_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
        nonce_metadata: impl IntoIterator<Item = &'a [u8]>,
        public_encryption_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
    ) -> Self {
        Self {
            inner: crate::shortint::ciphertext::ReRandomizationContext::new(
                rerand_root_seed_domain_separator,
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
            inner: crate::shortint::ciphertext::ReRandomizationContext::new_with_hasher(
                nonce_metadata,
                public_encryption_domain_separator,
                seed_hasher,
            ),
        }
    }

    pub fn add_ciphertext<T: AsShortintCiphertextSlice>(&mut self, ciphertext: &T) {
        self.inner
            .add_ciphertext_iterator(ciphertext.as_ciphertext_slice());
    }

    pub fn add_bytes(&mut self, data: &[u8]) {
        self.inner.add_bytes(data);
    }

    pub fn finalize(self) -> ReRandomizationSeedGen {
        ReRandomizationSeedGen {
            inner: self.inner.finalize(),
        }
    }
}

pub struct ReRandomizationSeedGen {
    inner: crate::shortint::ciphertext::ReRandomizationSeedGen,
}

impl ReRandomizationSeedGen {
    pub fn next_seed(&mut self) -> ReRandomizationSeed {
        self.inner.next_seed()
    }
}

pub(crate) fn re_randomize_ciphertext_blocks(
    blocks: &[Ciphertext],
    compact_public_key: &CompactPublicKey,
    key_switching_key_material: &KeySwitchingKeyMaterialView,
    seed: ReRandomizationSeed,
) -> crate::Result<Vec<Ciphertext>> {
    compact_public_key.key.re_randomize_ciphertexts(
        blocks,
        &key_switching_key_material.material,
        seed,
    )
}
