//! Bitonic sorting network generator.
//!
//! A bitonic sorting network for n=2^k elements has k*(k+1)/2 stages,
//! each with n/2 comparators. It sorts any input sequence.
use crate::core_crypto::prelude::Container;
use crate::integer::oprf::GenericOprfServerKey;
use crate::integer::{IntegerRadixCiphertext, RadixCiphertext, ServerKey};
use crate::shortint::MessageModulus;
use rayon::prelude::*;
use tfhe_csprng::seeders::Seeder;
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
    let mut stages = Vec::new();

    for phase in 0..log_n {
        for step in (0..=phase).rev() {
            let mut comparators = Vec::new();
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

/// Returns the next power of 2 >= n (or n itself if already a power of 2).
fn padded_size(n: usize) -> usize {
    n.next_power_of_two()
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
    NumBlocks(u32),
}

impl BitonicShuffleKeySize {
    pub fn try_collision_probability(proba: f64) -> Option<Self> {
        CollisionProbability::try_new(proba).map(Self::CollisionProbability)
    }

    pub fn collision_probability(proba: f64) -> Self {
        Self::CollisionProbability(CollisionProbability::new(proba))
    }

    pub fn num_blocks(num_blocks: u32) -> Self {
        Self::NumBlocks(num_blocks)
    }

    fn num_blocks_of_keys(&self, num_elements: usize, msg_mod: MessageModulus) -> u32 {
        match self {
            Self::CollisionProbability(CollisionProbability(proba)) => {
                let n_squared = (num_elements * num_elements) as f64;
                let bits = (n_squared / (2.0 * proba)).log2().ceil() as u32;
                bits.div_ceil(msg_mod.0.ilog2())
            }
            Self::NumBlocks(n) => *n,
        }
    }
}

impl ServerKey {
    /// Shuffles `data` into a uniformly random permutation using a bitonic sorting network
    /// with random sort keys.
    ///
    /// `key_size` controls the bit-width of the random sort keys used internally, either
    /// by specifying a target collision probability or by passing a raw block count.
    /// Larger keys reduce collision probability — and thus improve shuffle uniformity —
    /// at the cost of more computation per comparison/swap.
    ///
    /// # Errors
    ///
    /// Returns an error if the resolved key block count is 0.
    pub fn bitonic_shuffle<T, S, C>(
        &self,
        oprf_key: &GenericOprfServerKey<C>,
        data: Vec<T>,
        key_size: BitonicShuffleKeySize,
        seeder: &mut S,
    ) -> Result<Vec<T>, crate::Error>
    where
        T: IntegerRadixCiphertext,
        S: Seeder,
        C: Container<Element = c64> + Sync,
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

        let keys: Vec<_> = (0..data.len())
            .map(|_| {
                oprf_key.par_generate_oblivious_pseudo_random_unsigned_integer(
                    seeder.seed(),
                    key_num_blocks,
                    self,
                )
            })
            .collect();

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

        let padded_n = padded_size(n);
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
                    let ((new_ki, new_kj), (new_di, new_dj)) = rayon::join(
                        || self.unchecked_flip_parallelized(&cmp, &keys[i], &keys[j]),
                        || self.unchecked_flip_parallelized(&cmp, &data[i], &data[j]),
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
