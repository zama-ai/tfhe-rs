// This is linked to the standard ciphertext but has special code in it

use crate::core_crypto::commons::math::random::XofSeed;
use crate::integer::ciphertext::AsShortintCiphertextSlice;
use crate::integer::key_switching_key::KeySwitchingKeyMaterialView;
use crate::integer::CompactPublicKey;
pub use crate::shortint::ciphertext::{ReRandomizationSeed, ReRandomizationSeedHasher};
use crate::shortint::Ciphertext;
use crate::Result;

/// The context that will be hashed and used to generate unique [`ReRandomizationSeed`].
pub struct ReRandomizationContext {
    /// The inner hasher
    inner_context: crate::shortint::ciphertext::ReRandomizationContext,
    /// The number of integer ciphertexts added to the context. This will define the number of
    /// seeds that can be drawn from it
    ct_count: u64,
    /// Temporary buffer with all the individual shortint cts coefficients that will be hashed in
    /// the context
    ct_coeffs_buffer: Vec<u64>,
    /// Temporary buffer with all the ciphertext metadata
    meta_buffer: Vec<u8>,
    /// A piece of data that should be unique to the function being called
    fn_description: Vec<u8>,
}

impl ReRandomizationContext {
    /// Create a new re-randomization context with the default seed hasher (blake3).
    ///
    /// `rerand_seeder_domain_separator` is the domain separator that will be fed into the
    /// seed generator.
    /// `public_encryption_domain_separator` is the domain separator that will be used along this
    /// seed to generate the encryptions of zero.
    /// `fn_description` is a unique sequence of bytes that represents the functions called on the
    /// re-randomized values.
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
        rerand_seeder_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
        fn_description: impl IntoIterator<Item = &'a [u8]>,
        public_encryption_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
    ) -> Self {
        Self {
            inner_context: crate::shortint::ciphertext::ReRandomizationContext::new(
                rerand_seeder_domain_separator,
                public_encryption_domain_separator,
            ),
            ct_coeffs_buffer: Vec::new(),
            ct_count: 0,
            meta_buffer: Vec::new(),
            fn_description: fn_description.into_iter().flatten().copied().collect(),
        }
    }

    /// Create a new re-randomization context with the provided seed hasher.
    pub fn new_with_hasher<'a>(
        fn_description: impl IntoIterator<Item = &'a [u8]>,
        public_encryption_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
        seed_hasher: ReRandomizationSeedHasher,
    ) -> Self {
        Self {
            inner_context: crate::shortint::ciphertext::ReRandomizationContext::new_with_hasher(
                public_encryption_domain_separator,
                seed_hasher,
            ),
            ct_coeffs_buffer: Vec::new(),
            ct_count: 0,
            meta_buffer: Vec::new(),
            fn_description: fn_description.into_iter().flatten().copied().collect(),
        }
    }

    /// Add a new integer ciphertext to the context.
    ///
    /// The ciphertexts added like this will be stored in a temporary buffer and only hashed during
    /// the "finalize" step
    pub fn add_ciphertext<T: AsShortintCiphertextSlice>(&mut self, ciphertext: &T) {
        self.ct_coeffs_buffer.extend(
            ciphertext
                .as_ciphertext_slice()
                .iter()
                .flat_map(|ct| ct.ct.as_ref()),
        );
        self.ct_count += 1;
    }

    /// Add a metadata buffer to the context.
    ///
    /// These bytes will be added to a temporary buffer and will only be hashed during the
    /// "finalize" step
    pub fn add_bytes(&mut self, data: &[u8]) {
        self.meta_buffer.extend_from_slice(data);
    }

    /// Consumes the context to instantiate a seed generator
    pub fn finalize(mut self) -> ReRandomizationSeedGen {
        self.inner_context
            .add_ciphertext_data_slice(&self.ct_coeffs_buffer);
        self.inner_context.add_bytes(&self.meta_buffer);
        self.inner_context.add_bytes(&self.fn_description);

        ReRandomizationSeedGen {
            inner: self.inner_context.finalize(),
            remaining_seeds_count: self.ct_count,
        }
    }
}

/// A generator that can be used to obtain seeds needed to re-randomize individual ciphertexts.
///
/// This will refuse to generate more seeds than the number of ciphertext added into the context.
pub struct ReRandomizationSeedGen {
    inner: crate::shortint::ciphertext::ReRandomizationSeedGen,
    remaining_seeds_count: u64,
}

impl ReRandomizationSeedGen {
    /// Generate the next seed from the seeder.
    ///
    /// Returns an error if more seeds have been generated than the number of ciphertext added into
    /// the context.
    pub fn next_seed(&mut self) -> Result<ReRandomizationSeed> {
        if self.remaining_seeds_count > 0 {
            self.remaining_seeds_count -= 1;
            Ok(self.inner.next_seed())
        } else {
            Err(crate::error!("Trying to draw more seeds than the number of ciphertexts that were added to the context"))
        }
    }
}

pub(crate) fn re_randomize_ciphertext_blocks(
    blocks: &mut [Ciphertext],
    compact_public_key: &CompactPublicKey,
    key_switching_key_material: Option<&KeySwitchingKeyMaterialView>,
    seed: ReRandomizationSeed,
) -> crate::Result<()> {
    compact_public_key.key.re_randomize_ciphertexts(
        blocks,
        key_switching_key_material.map(|k| &k.material),
        seed,
    )
}
