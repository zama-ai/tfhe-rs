//! Update the random elements (mask and noise) of a ciphertext without changing its plaintext value
//!
//! This works by generating encrypted zeros using a public key, that will be added to the input
//! ciphertexts

use crate::core_crypto::algorithms::{
    encrypt_lwe_compact_ciphertext_list_with_compact_public_key, keyswitch_lwe_ciphertext,
    lwe_ciphertext_add_assign,
};
use crate::core_crypto::commons::generators::NoiseRandomGenerator;
use crate::core_crypto::commons::math::random::{DefaultRandomGenerator, XofSeed};
use crate::core_crypto::commons::parameters::{LweCiphertextCount, PlaintextCount};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::{LweCiphertext, LweCompactCiphertextList, PlaintextList};
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::key_switching_key::KeySwitchingKeyMaterialView;
use crate::shortint::{Ciphertext, CompactPublicKey, PBSOrder};

use rayon::prelude::*;
use sha3::digest::{ExtendableOutput, Update};
use std::io::Read;

/// Size of the re-randomization seed in bits
const RERAND_SEED_BITS: usize = 256;

/// The XoF algorithm used to generate the re-randomization seed
#[derive(Copy, Clone, Default)]
pub enum ReRandomizationHashAlgo {
    /// Used for NIST compliance
    Shake256,
    /// Faster, should be preferred unless you have specific requirements
    #[default]
    Blake3,
}

/// The hash state used for the re-randomization seed generation
#[derive(Clone)]
// blake3 is the larger variant but we expect it to be used more in performance sensitive contexts
#[allow(clippy::large_enum_variant)]
pub enum ReRandomizationSeedHasher {
    Shake256(sha3::Shake256),
    Blake3(blake3::Hasher),
}

impl ReRandomizationSeedHasher {
    /// Create a new hash state for the provided algorithm
    pub fn new(
        algo: ReRandomizationHashAlgo,
        rerand_root_seed_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
    ) -> Self {
        let mut hasher = match algo {
            ReRandomizationHashAlgo::Shake256 => Self::Shake256(sha3::Shake256::default()),
            ReRandomizationHashAlgo::Blake3 => Self::Blake3(blake3::Hasher::default()),
        };

        hasher.update(&rerand_root_seed_domain_separator);
        hasher
    }

    /// Update the hash state with new data
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Shake256(hasher) => hasher.update(data),
            Self::Blake3(hasher) => {
                hasher.update(data);
            }
        }
    }

    /// Consume the state to generate a seed
    fn finalize(self) -> [u8; RERAND_SEED_BITS / 8] {
        let mut res = [0; RERAND_SEED_BITS / 8];
        match self {
            Self::Shake256(hasher) => {
                let mut reader = hasher.finalize_xof();
                reader
                    .read_exact(&mut res)
                    .expect("XoF reader should not EoF");
            }
            Self::Blake3(hasher) => {
                let mut reader = hasher.finalize_xof();
                reader
                    .read_exact(&mut res)
                    .expect("XoF reader should not EoF");
            }
        }
        res
    }
}

impl From<sha3::Shake256> for ReRandomizationSeedHasher {
    fn from(value: sha3::Shake256) -> Self {
        Self::Shake256(value)
    }
}

impl From<blake3::Hasher> for ReRandomizationSeedHasher {
    fn from(value: blake3::Hasher) -> Self {
        Self::Blake3(value)
    }
}

/// A seed that can be used to re-randomize a ciphertext
///
/// This type cannot be cloned or copied, as a seed should only be used once.
pub struct ReRandomizationSeed(pub(crate) XofSeed);

/// The context that will be hashed and used to generate unique [`ReRandomizationSeed`].
///
/// At this level, the context will directly hash any data passed to it.
/// This means that the order in which the data will be hashed matches exactly the order in which
/// the different `add_*` functions are called
pub struct ReRandomizationContext {
    hash_state: ReRandomizationSeedHasher,
    public_encryption_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
}

impl ReRandomizationContext {
    /// Create a new re-randomization context with the default seed hasher (blake3).
    ///
    /// `rerand_seeder_domain_separator` is the domain separator that will be fed into the
    /// seed generator.
    /// `public_encryption_domain_separator` is the domain separator that will be used along this
    /// seed to generate the encryptions of zero.
    ///
    /// (See [`XofSeed`] for more information)
    ///
    /// # Example
    /// ```rust
    /// use tfhe::shortint::ciphertext::ReRandomizationContext;
    /// // Simulate a 256 bits nonce
    /// let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
    /// let _re_rand_context = ReRandomizationContext::new(
    ///     *b"TFHE_Rrd",
    ///     *b"TFHE_Enc"
    ///  );
    pub fn new(
        rerand_seeder_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
        public_encryption_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
    ) -> Self {
        let seed_hasher = ReRandomizationSeedHasher::new(
            ReRandomizationHashAlgo::default(),
            rerand_seeder_domain_separator,
        );

        Self::new_with_hasher(public_encryption_domain_separator, seed_hasher)
    }

    /// Create a new re-randomization context with the provided seed hasher.
    pub fn new_with_hasher(
        public_encryption_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
        seed_hasher: ReRandomizationSeedHasher,
    ) -> Self {
        Self {
            hash_state: seed_hasher,
            public_encryption_domain_separator,
        }
    }

    /// Adds a new ciphertext to the re-randomization context
    pub fn add_ciphertext(&mut self, ciphertext: &Ciphertext) {
        self.add_ciphertext_iterator([ciphertext]);
    }

    /// Adds bytes to the re-randomization context
    pub fn add_bytes(&mut self, data: &[u8]) {
        self.hash_state.update(data);
    }

    pub fn add_ciphertext_iterator<'a, I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = &'a Ciphertext>,
    {
        // Blake3 algorithm is faster when fed with larger chunks of data, so we copy all the
        // ciphertexts into a single buffer.

        // We try to estimate the buffer size and preallocate it. This is an estimate based on the
        // following assumptions:
        // - all ciphertexts have the same size
        // - the iterator size hint is correct
        // This is not critical as a bad estimate only results in reallocations in the worst case.
        let mut iter = iter.into_iter();
        let Some(first) = iter.next() else {
            return;
        };

        let hint = iter.size_hint();
        // Use the max iterator size if it exists, or default to the min one.
        let iter_len = hint.1.unwrap_or(hint.0);
        let tot_len = first.ct.as_ref().len() * iter_len;
        let mut copied: Vec<u64> = Vec::with_capacity(tot_len);

        copied.extend(first.ct.as_ref());
        for ciphertext in iter {
            copied.extend(ciphertext.ct.as_ref());
        }

        self.add_ciphertext_data_slice(&copied);
    }

    pub(crate) fn add_ciphertext_data_slice(&mut self, slice: &[u64]) {
        self.hash_state.update(bytemuck::cast_slice(slice));
    }

    /// Consumes the context to create a seed generator
    pub fn finalize(self) -> ReRandomizationSeedGen {
        let Self {
            hash_state,
            public_encryption_domain_separator,
        } = self;

        ReRandomizationSeedGen {
            hash_state,
            next_seed_index: 0,
            public_encryption_domain_separator,
        }
    }
}

/// A generator that can be used to obtain seeds needed to re-randomize individual ciphertexts
pub struct ReRandomizationSeedGen {
    hash_state: ReRandomizationSeedHasher,
    next_seed_index: u64,
    public_encryption_domain_separator: [u8; XofSeed::DOMAIN_SEP_LEN],
}

impl ReRandomizationSeedGen {
    pub fn next_seed(&mut self) -> ReRandomizationSeed {
        let current_seed_index = self.next_seed_index;
        self.next_seed_index += 1;

        let mut hash_state = self.hash_state.clone();
        hash_state.update(&current_seed_index.to_le_bytes());

        let seed_256 = hash_state.finalize();

        ReRandomizationSeed(XofSeed::new(
            seed_256.to_vec(),
            self.public_encryption_domain_separator,
        ))
    }
}

impl CompactPublicKey {
    pub(crate) fn prepare_cpk_zero_for_rerand(
        &self,
        seed: ReRandomizationSeed,
        zero_count: LweCiphertextCount,
    ) -> LweCompactCiphertextList<Vec<u64>> {
        let mut encryption_generator =
            NoiseRandomGenerator::<DefaultRandomGenerator>::new_from_seed(seed.0);

        let mut encryption_of_zero = LweCompactCiphertextList::new(
            0,
            self.parameters().encryption_lwe_dimension.to_lwe_size(),
            zero_count,
            self.parameters().ciphertext_modulus,
        );

        let plaintext_list = PlaintextList::new(
            0,
            PlaintextCount(encryption_of_zero.lwe_ciphertext_count().0),
        );

        let cpk_encryption_noise_distribution = self.parameters().encryption_noise_distribution;

        encrypt_lwe_compact_ciphertext_list_with_compact_public_key(
            &self.key,
            &mut encryption_of_zero,
            &plaintext_list,
            cpk_encryption_noise_distribution,
            cpk_encryption_noise_distribution,
            &mut encryption_generator,
        );

        encryption_of_zero
    }

    /// Re-randomize a list of ciphertexts using the provided seed and compact public key
    ///
    /// The key and seed are used to generate encryptions of zero that will be added to the input
    /// ciphertexts
    pub fn re_randomize_ciphertexts(
        &self,
        cts: &mut [Ciphertext],
        key_switching_key_material: &KeySwitchingKeyMaterialView,
        seed: ReRandomizationSeed,
    ) -> crate::Result<()> {
        let ksk_pbs_order = key_switching_key_material.destination_key.into_pbs_order();
        let ksk_output_lwe_size = key_switching_key_material
            .key_switching_key
            .output_lwe_size();

        if let Some(msg) = cts.iter().find_map(|ct| {
            if ct.atomic_pattern.pbs_order() != ksk_pbs_order {
                Some(
                    "Mismatched PBSOrder between Ciphertext being re-randomized and provided \
                KeySwitchingKeyMaterialView.",
                )
            } else if ksk_output_lwe_size != ct.ct.lwe_size() {
                Some(
                    "Mismatched LweSwize between Ciphertext being re-randomized and provided \
                KeySwitchingKeyMaterialView.",
                )
            } else if ct.noise_level() > NoiseLevel::NOMINAL {
                Some("Tried to re-randomize a Ciphertext with non-nominal NoiseLevel.")
            } else {
                None
            }
        }) {
            return Err(crate::error!("{}", msg));
        }

        if ksk_pbs_order != PBSOrder::KeyswitchBootstrap {
            // message is ok since we know that ksk order == cts order
            return Err(crate::error!(
                "Tried to re-randomize a Ciphertext with unsupported PBSOrder. \
                Required PBSOrder::KeyswitchBootstrap.",
            ));
        }

        if key_switching_key_material.cast_rshift != 0 {
            return Err(crate::error!(
                "Tried to re-randomize a Ciphertext using KeySwitchingKeyMaterialView \
                with non-zero cast_rshift, this is unsupported.",
            ));
        }

        if key_switching_key_material
            .key_switching_key
            .input_key_lwe_dimension()
            != self.parameters().encryption_lwe_dimension
        {
            return Err(crate::error!(
                "Mismatched LweDimension between provided CompactPublicKey and \
                KeySwitchingKeyMaterialView input LweDimension.",
            ));
        }

        let encryption_of_zero =
            self.prepare_cpk_zero_for_rerand(seed, LweCiphertextCount(cts.len()));

        let zero_lwes = encryption_of_zero.expand_into_lwe_ciphertext_list();

        cts.par_iter_mut()
            .zip(zero_lwes.par_iter())
            .for_each(|(ct, lwe_randomizer_cpk)| {
                let mut lwe_randomizer_ksed = LweCiphertext::new(
                    0,
                    key_switching_key_material
                        .key_switching_key
                        .output_lwe_size(),
                    key_switching_key_material
                        .key_switching_key
                        .ciphertext_modulus(),
                );
                // Keyswitch used to convert from the cpk params to the compute ones.
                // In theory, with a cpk made from the compute secret key, this keyswitch could be
                // removed at the cost of an additional key.
                keyswitch_lwe_ciphertext(
                    key_switching_key_material.key_switching_key,
                    &lwe_randomizer_cpk,
                    &mut lwe_randomizer_ksed,
                );

                lwe_ciphertext_add_assign(&mut ct.ct, &lwe_randomizer_ksed);

                // We take ciphertexts whose noise level is Nominal or less i.e. Zero, so we can
                // unconditionally set the noise
                ct.set_noise_level_to_nominal();
            });

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::shortint::parameters::test_params::{
        TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
        TEST_META_PARAM_PROD_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    };
    use crate::shortint::parameters::MetaParameters;
    use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
    use crate::shortint::{gen_keys, CompactPrivateKey, KeySwitchingKey};

    /// Test the case where we rerand more ciphertexts that what can be stored in one cpk lwe
    /// Test the trivial case
    fn test_rerand(meta_params: MetaParameters) {
        let compute_params = meta_params.compute_parameters;
        let dedicated_cpk_params = meta_params
            .dedicated_compact_public_key_parameters
            .expect("MetaParameters should have dedicated_compact_public_key_parameters");
        let pke_params = dedicated_cpk_params.pke_params;
        let ks_params = dedicated_cpk_params.ksk_params;

        let (cks, sks) = gen_keys(compute_params);
        let privk = CompactPrivateKey::new(pke_params);
        let pubk = CompactPublicKey::new(&privk);
        let ksk = KeySwitchingKey::new((&privk, None), (&cks, &sks), ks_params);

        let pke_lwe_dim = pke_params.encryption_lwe_dimension.0;

        let msg1 = 1;
        let msg2 = 2;

        {
            let mut cts = Vec::with_capacity(pke_lwe_dim * 2);

            for _ in 0..pke_lwe_dim {
                let ct1 = cks.encrypt(msg1);
                cts.push(ct1);
                let ct2 = cks.encrypt(msg2);
                cts.push(ct2);
            }

            let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
            let mut re_rand_context = ReRandomizationContext::new(*b"TFHE_Rrd", *b"TFHE_Enc");

            re_rand_context.add_ciphertext_iterator(&cts);
            re_rand_context.add_bytes(b"ct_radix");
            re_rand_context.add_bytes(b"FheUint4".as_slice());
            re_rand_context.add_bytes(&nonce);
            let mut seeder = re_rand_context.finalize();

            pubk.re_randomize_ciphertexts(
                &mut cts,
                &ksk.key_switching_key_material.as_view(),
                seeder.next_seed(),
            )
            .unwrap();

            cts.par_chunks(2).for_each(|pair| {
                let sum = sks.add(&pair[0], &pair[1]);
                let dec = cks.decrypt(&sum);

                assert_eq!(dec, msg1 + msg2);
            });
        }

        {
            let mut trivial = sks.create_trivial(3);

            let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
            let mut re_rand_context = ReRandomizationContext::new(*b"TFHE_Rrd", *b"TFHE_Enc");

            re_rand_context.add_ciphertext(&trivial);
            re_rand_context.add_bytes(&nonce);
            re_rand_context.add_bytes(b"trivial");

            let mut seeder = re_rand_context.finalize();

            pubk.re_randomize_ciphertexts(
                core::slice::from_mut(&mut trivial),
                &ksk.key_switching_key_material.as_view(),
                seeder.next_seed(),
            )
            .unwrap();

            let not_trivial = trivial;

            assert!(not_trivial.noise_level() == NoiseLevel::NOMINAL);

            let dec = cks.decrypt(&not_trivial);
            assert_eq!(dec, 3);
        }
    }

    create_parameterized_test!(test_rerand {
        (TEST_META_PARAM_PROD_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128, CPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
        (TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128, CPU_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128)
    });
}
