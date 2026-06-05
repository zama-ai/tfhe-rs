//! Bitonic sorting network generator.
//!
//! A bitonic sorting network for n=2^k elements has k*(k+1)/2 stages,
//! each with n/2 comparators. It sorts any input sequence.
use crate::core_crypto::prelude::Container;
use crate::integer::ciphertext::{ReRandomizationHashAlgo, ReRandomizationKey};
use crate::integer::oprf::GenericOprfServerKey;
use crate::integer::prelude::ServerKeyDefaultCMux;
use crate::integer::{IntegerRadixCiphertext, RadixCiphertext, ServerKey};
use crate::shortint::{Ciphertext, MessageModulus};
use crate::OprfSeed;
use rayon::prelude::*;
use tfhe_fft::c64;

/// Generates a bitonic sorting network for n elements (n must be a power of 2).
///
/// Returns a list of stages, where each stage contains disjoint (i, j, ascending) triples.
/// Each triple represents a compare-and-swap: if ascending, put the smaller element at i;
/// if descending, put the larger element at i.
pub(crate) fn bitonic_network(n: usize) -> Vec<Vec<(usize, usize, bool)>> {
    assert!(
        n.is_power_of_two() && n >= 2,
        "bitonic_network requires n to be a power of 2 and >= 2, got n={n}"
    );
    let log_n = n.trailing_zeros() as usize;
    let mut stages = Vec::with_capacity(log_n * (log_n + 1) / 2);

    // Bitonic network indexing trick
    //
    //   - At step `step` of phase `phase`, comparator partners differ in exactly bit `step` of
    //     their index, so `j = i ^ (1 << step)`.
    //   - The `j > i` filter ensures bit `step` of `i` is 0, so each unordered pair {i, j} is
    //     emitted exactly once.
    //   - A "sequence" (the bitonic subsequence being merged in this phase) has length `2^(phase +
    //     1)`, so `i >> (phase + 1)` is its index; even-indexed sequences sort ascending,
    //     odd-indexed descending.
    for phase in 0..log_n {
        for step in (0..=phase).rev() {
            let mut comparators = Vec::with_capacity(n / 2);
            for i in 0..n {
                let j = i ^ (1 << step);
                if j > i {
                    let ascending = (i >> (phase + 1)) & 1 == 0;
                    comparators.push((i, j, ascending));
                }
            }
            stages.push(comparators);
        }
    }

    stages
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct CollisionProbability(f64);

impl CollisionProbability {
    pub fn try_new(proba: f64) -> Option<Self> {
        if 0.0 < proba && proba < 1.0 {
            Some(Self(proba))
        } else {
            None
        }
    }

    pub fn new(proba: f64) -> Self {
        Self::try_new(proba).expect("Invalid probability, it must be in ]0, 1.0[")
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum BitonicShuffleKeySize {
    CollisionProbability(CollisionProbability),
    NumBits(u32),
}

impl BitonicShuffleKeySize {
    pub fn try_collision_probability(proba: f64) -> Option<Self> {
        CollisionProbability::try_new(proba).map(Self::CollisionProbability)
    }

    pub fn collision_probability(proba: f64) -> Self {
        Self::CollisionProbability(CollisionProbability::new(proba))
    }

    pub fn num_bits(num_bits: u32) -> Self {
        Self::NumBits(num_bits)
    }

    fn num_blocks_of_keys(&self, num_elements: usize, msg_mod: MessageModulus) -> u32 {
        let bits = match self {
            Self::CollisionProbability(CollisionProbability(proba)) => {
                let n_squared = (num_elements * num_elements) as f64;
                (n_squared / (2.0 * proba)).log2().ceil() as u32
            }
            Self::NumBits(n) => *n,
        };
        bits.div_ceil(msg_mod.0.ilog2())
    }
}

impl ServerKey {
    /// Shuffles `data` into a uniformly random permutation using a bitonic sorting network
    /// with random sort keys.
    ///
    /// `key_size` controls the bit-width of the random sort keys used internally, either
    /// by specifying a target collision probability or by passing a raw bit count.
    /// The bit count is rounded up to a multiple of `log2(message_modulus)` so each
    /// OPRF-generated random block is fully consumed. Larger keys reduce collision
    /// probability — and thus improve shuffle uniformity — at the cost of more
    /// computation per comparison/swap.
    ///
    /// # Errors
    ///
    /// Returns an error if the resolved key block count is 0.
    pub fn bitonic_shuffle<T, S, C>(
        &self,
        oprf_key: &GenericOprfServerKey<C>,
        data: Vec<T>,
        key_size: BitonicShuffleKeySize,
        seed: S,
    ) -> Result<Vec<T>, crate::Error>
    where
        T: IntegerRadixCiphertext,
        S: OprfSeed,
        C: Container<Element = c64> + Sync,
    {
        self.bitonic_shuffle_impl(data, key_size, |chunks| {
            Ok(oprf_key
                .key
                .generate_oblivious_pseudo_random_bits_chunks(seed, chunks, &self.key))
        })
    }

    pub fn re_randomized_keys_bitonic_shuffle<T, S, C>(
        &self,
        oprf_key: &GenericOprfServerKey<C>,
        data: Vec<T>,
        key_size: BitonicShuffleKeySize,
        seed: S,
        re_randomization_key: &ReRandomizationKey,
        re_randomization_hash_algo: ReRandomizationHashAlgo,
    ) -> Result<Vec<T>, crate::Error>
    where
        T: IntegerRadixCiphertext,
        S: OprfSeed,
        C: Container<Element = c64> + Sync,
    {
        let (cpk, ksk) = re_randomization_key.get_cpk_and_optional_ksk();

        self.bitonic_shuffle_impl(data, key_size, |chunks| {
            oprf_key
                .key
                .generate_oblivious_pseudo_random_bits_chunks_and_re_randomize(
                    seed,
                    chunks,
                    &self.key,
                    &cpk.key,
                    ksk.as_ref().map(|k| &k.material),
                    re_randomization_hash_algo,
                )
        })
    }

    fn bitonic_shuffle_impl<T, F>(
        &self,
        data: Vec<T>,
        key_size: BitonicShuffleKeySize,
        prf_callback: F,
    ) -> Result<Vec<T>, crate::Error>
    where
        T: IntegerRadixCiphertext,
        F: FnOnce(
            &[u64], // chunks
        ) -> crate::Result<Vec<Vec<Ciphertext>>>,
    {
        let key_num_blocks = key_size.num_blocks_of_keys(data.len(), self.message_modulus()) as u64;

        if key_num_blocks == 0 {
            return Err(crate::Error::new(
                "key_num_blocks must be at least 1".to_string(),
            ));
        }

        if data.len() <= 1 {
            return Ok(data);
        }

        let key_num_bits = key_num_blocks * self.message_modulus().0.ilog2() as u64;

        let chunks = vec![key_num_bits; data.len()];
        let block_chunks = prf_callback(&chunks)?;

        let keys = block_chunks
            .into_iter()
            .map(RadixCiphertext::from)
            .collect::<Vec<_>>();

        self.bitonic_shuffle_with_keys(data, keys)
    }

    /// Shuffles `data` using a bitonic sorting network keyed by `keys`.
    ///
    /// # Errors
    ///
    /// Returns an error if `data` and `keys` have different lengths, or if
    /// elements within `data` (or within `keys`) have inconsistent block counts.
    pub fn bitonic_shuffle_with_keys<T>(
        &self,
        mut data: Vec<T>,
        mut keys: Vec<RadixCiphertext>,
    ) -> Result<Vec<T>, crate::Error>
    where
        T: IntegerRadixCiphertext,
    {
        if data.len() != keys.len() {
            return Err(crate::Error::new(format!(
                "data and keys must have the same length, got {} and {}",
                data.len(),
                keys.len()
            )));
        }

        if data.len() <= 1 {
            return Ok(data);
        }

        let data_num_blocks = data[0].blocks().len();
        if data[1..]
            .iter()
            .any(|d| d.blocks().len() != data_num_blocks)
        {
            return Err(crate::Error::new(
                "all data elements must have the same number of blocks".to_string(),
            ));
        }
        let key_num_blocks = keys[0].blocks.len();
        if keys[1..].iter().any(|k| k.blocks.len() != key_num_blocks) {
            return Err(crate::Error::new(
                "all keys must have the same number of blocks".to_string(),
            ));
        }

        rayon::join(
            || {
                data.par_iter_mut()
                    .for_each(|value| self.clean_inplace_for_default_op(value));
            },
            || {
                keys.par_iter_mut()
                    .for_each(|value| self.clean_inplace_for_default_op(value));
            },
        );

        let mut data = self.unchecked_bitonic_shuffle_with_keys(data, keys);

        data.par_iter_mut().for_each(|radix| {
            radix
                .blocks_mut()
                .par_iter_mut()
                .for_each(|block| self.key.message_extract_assign(block))
        });

        Ok(data)
    }

    /// Performs a bitonic shuffle without cleaning inputs or outputs.
    ///
    /// # Preconditions
    ///
    /// * `data` and `keys` must have the same length and consistent block counts.
    /// * Data blocks must have no carries and noise budget for `unchecked_flip_parallelized`.
    /// * Key blocks must have no carries and noise budget for `unchecked_lt/gt`.
    ///
    /// Output blocks have no carries but non-nominal noise level.
    pub fn unchecked_bitonic_shuffle_with_keys<T>(
        &self,
        mut data: Vec<T>,
        mut keys: Vec<RadixCiphertext>,
    ) -> Vec<T>
    where
        T: IntegerRadixCiphertext,
    {
        assert_eq!(
            data.len(),
            keys.len(),
            "data.len()={} != keys.len()={}",
            data.len(),
            keys.len()
        );
        let n = data.len();
        if n <= 1 {
            return data;
        }

        let padded_n = n.next_power_of_two();
        let network = bitonic_network(padded_n);

        let mut key_num_blocks = keys[0].blocks.len();
        let data_num_blocks = data[0].blocks().len();

        let pad = padded_n - n;
        if pad > 0 {
            // We need to pad with some trivial (key=MAX, data=0)
            // However it could be that a key is already=MAX, so to protect us from that case
            // we add an extra block to the keys
            key_num_blocks += 1;
            for key in &mut keys {
                self.extend_radix_with_trivial_zero_blocks_msb_assign(key, 1);
            }

            for _ in 0..pad {
                keys.push(self.create_trivial_max_radix(key_num_blocks));
                data.push(self.create_trivial_zero_radix(data_num_blocks));
            }
        }

        let mut stage_results = Vec::with_capacity(padded_n / 2);
        for stage in network {
            stage
                .into_par_iter()
                .map(|(i, j, ascending)| {
                    let cmp = if ascending {
                        self.unchecked_gt_parallelized(&keys[i], &keys[j])
                    } else {
                        self.unchecked_lt_parallelized(&keys[i], &keys[j])
                    };

                    // If we use unchecked_flip, both outputs will have noise_level = 2
                    // many of the operation that they are used in require to have max_noise_level
                    // >= 4 in order to accept these inputs. So if it's not the
                    // case, we have to use default flip which cleans the output
                    let ((new_ki, new_kj), (new_di, new_dj)) = rayon::join(
                        || {
                            if self.key.max_noise_level.get() < 4 {
                                self.flip_parallelized(&cmp, &keys[i], &keys[j])
                            } else {
                                self.unchecked_flip_parallelized(&cmp, &keys[i], &keys[j])
                            }
                        },
                        || {
                            if self.key.max_noise_level.get() < 4 {
                                self.flip_parallelized(&cmp, &data[i], &data[j])
                            } else {
                                self.unchecked_flip_parallelized(&cmp, &data[i], &data[j])
                            }
                        },
                    );

                    (i, j, new_ki, new_kj, new_di, new_dj)
                })
                .collect_into_vec(&mut stage_results);

            for (i, j, new_ki, new_kj, new_di, new_dj) in stage_results.drain(..) {
                keys[i] = new_ki;
                keys[j] = new_kj;
                data[i] = new_di;
                data[j] = new_dj;
            }
        }

        data.truncate(n);
        data
    }
}
