// This is linked to the standard ciphertext but has special code in it

use crate::core_crypto::commons::math::random::XofSeed;
use crate::integer::ciphertext::AsShortintCiphertextSlice;
use crate::integer::key_switching_key::KeySwitchingKeyMaterialView;
use crate::integer::CompactPublicKey;
pub use crate::shortint::ciphertext::{
    ReRandomizationHashAlgo, ReRandomizationSeed, ReRandomizationSeedHasher,
};
use crate::shortint::public_key::compact::TFHE_PKE_DOMAIN_SEPARATOR;
use crate::shortint::Ciphertext;
use crate::Result;

#[cfg(feature = "zk-pok")]
use super::ProvenCompactCiphertextList;

#[derive(Clone, Copy)]
pub enum ReRandomizationKey<'key> {
    LegacyDedicatedCPK {
        cpk: &'key CompactPublicKey,
        ksk: KeySwitchingKeyMaterialView<'key>,
    },
    DerivedCPKWithoutKeySwitch {
        cpk: &'key CompactPublicKey,
    },
}

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

    #[cfg(feature = "zk-pok")]
    pub fn add_proven_ciphertext_list(&mut self, list: &ProvenCompactCiphertextList) {
        self.ct_coeffs_buffer.extend(
            list.ct_list
                .proved_lists
                .iter()
                .flat_map(|list| list.0.ct_list.as_ref()),
        );

        self.meta_buffer.extend(
            list.ct_list
                .proved_lists
                .iter()
                .flat_map(|list| list.1.to_le_bytes()),
        );

        // We draw only one seed for the full list
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
    pub(crate) fn new_prf_rerand_seed_gen(
        hash_algo: ReRandomizationHashAlgo,
        prf_seed: &[u8],
        output_bit_sizes: &[RadixRandomBitsRLE],
    ) -> Self {
        const PRF_RERAND_DOMAIN_SEPARATOR: [u8; XofSeed::DOMAIN_SEP_LEN] = *b"PRF_RRND";

        let meta_buffer: Vec<_> = prf_seed
            .iter()
            .copied()
            .chain(output_bit_sizes.iter().flat_map(|x| x.to_le_bytes()))
            .collect();

        let context = ReRandomizationContext {
            inner_context: crate::shortint::ciphertext::ReRandomizationContext::new_with_hasher(
                TFHE_PKE_DOMAIN_SEPARATOR,
                crate::shortint::ciphertext::ReRandomizationSeedHasher::new(
                    hash_algo,
                    PRF_RERAND_DOMAIN_SEPARATOR,
                ),
            ),
            // To be able to draw one seed
            ct_count: 1,
            ct_coeffs_buffer: Vec::new(),
            meta_buffer,
            fn_description: Vec::new(),
        };

        context.finalize()
    }

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
    re_randomization_key: ReRandomizationKey<'_>,
    seed: ReRandomizationSeed,
) -> crate::Result<()> {
    let (compact_public_key, key_switching_key_material) = match re_randomization_key {
        ReRandomizationKey::LegacyDedicatedCPK { cpk, ksk } => (cpk, Some(ksk)),
        ReRandomizationKey::DerivedCPKWithoutKeySwitch { cpk } => (cpk, None),
    };

    compact_public_key.key.re_randomize_ciphertexts(
        blocks,
        key_switching_key_material.map(|k| k.material).as_ref(),
        seed,
    )
}

pub(crate) struct RandomBitsRLE {
    block_count: u64,
    bits_per_block: u64,
}

impl RandomBitsRLE {
    pub(crate) fn to_le_bytes(&self) -> [u8; core::mem::size_of::<Self>()] {
        use itertools::Itertools;

        let mut out = [0u8; core::mem::size_of::<Self>()];

        let Self {
            block_count,
            bits_per_block,
        } = self;

        for (byte, out_value) in block_count
            .to_le_bytes()
            .into_iter()
            .chain(bits_per_block.to_le_bytes())
            .zip_eq(out.iter_mut())
        {
            *out_value = byte;
        }

        out
    }
}

pub(crate) struct RadixRandomBitsRLE {
    data: Vec<RandomBitsRLE>,
}

impl RadixRandomBitsRLE {
    pub(crate) fn new_boolean() -> Self {
        Self {
            data: vec![RandomBitsRLE {
                block_count: 1,
                bits_per_block: 1,
            }],
        }
    }

    pub(crate) fn new_radix(bit_count: u64, bits_per_block: u64) -> Self {
        let (full_blocks, bits_remainder) =
            (bit_count / bits_per_block, bit_count % bits_per_block);

        let data = if bits_remainder == 0 {
            vec![RandomBitsRLE {
                block_count: full_blocks,
                bits_per_block,
            }]
        } else {
            vec![
                RandomBitsRLE {
                    block_count: full_blocks,
                    bits_per_block,
                },
                RandomBitsRLE {
                    block_count: 1,
                    bits_per_block: bits_remainder,
                },
            ]
        };

        Self { data }
    }

    pub(crate) fn block_count(&self) -> u64 {
        self.data.iter().map(|x| x.block_count).sum()
    }

    pub(crate) fn to_le_bytes(&self) -> Vec<u8> {
        let block_count = self.block_count();

        block_count
            .to_le_bytes()
            .into_iter()
            .chain(self.data.iter().flat_map(|x| x.to_le_bytes()))
            .collect()
    }
}

impl ReRandomizationSeed {
    pub(crate) fn new_prf_rerand_seed(
        hash_algo: ReRandomizationHashAlgo,
        prf_seed: &[u8],
        output_bit_sizes: &[RadixRandomBitsRLE],
    ) -> Self {
        let mut seed_gen =
            ReRandomizationSeedGen::new_prf_rerand_seed_gen(hash_algo, prf_seed, output_bit_sizes);

        // Ok to unwrap, the generator setup means this call cannot panic
        seed_gen.next_seed().unwrap()
    }
}
