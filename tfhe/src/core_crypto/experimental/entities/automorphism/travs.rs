use crate::core_crypto::experimental::entities::automorphism::Automorphism;
use crate::core_crypto::prelude::*;

use super::hom_aut_key::AutomKey;
use super::Diff;

/// Traversal automorphism keys: a sliding window of [`AutomKey`] values covering up to
/// `window_size` entries from the sequence `-base^0, base^1, -base^1, base^2, -base^2, …`
pub struct Travs {
    ak: Vec<AutomKey>,
}

impl Travs {
    #[allow(clippy::too_many_arguments)]
    pub fn new<Gen: ByteRandomGenerator>(
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        glwe_noise_distribution: DynamicDistribution<u64>,
        ciphertext_modulus: CiphertextModulus<u64>,
        window_size: u16,
        base: u64,
        encryption_generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self {
        let base = base as usize;

        let polynomial_size = glwe_secret_key.polynomial_size();

        let mut build_autom_key = |power, sign_change| {
            let power = if sign_change {
                2 * polynomial_size.0 - power
            } else {
                power
            };

            let automorphism = Automorphism::new(power, polynomial_size);

            AutomKey::new(
                glwe_secret_key,
                automorphism,
                decomp_base_log,
                decomp_level_count,
                glwe_noise_distribution,
                ciphertext_modulus,
                encryption_generator,
            )
        };

        let mut power = 1;

        let ak: Vec<_> = (0..)
            .flat_map(|_| {
                let positive = (power, false);

                let negative = (power, true);

                power = (power * base) % (2 * polynomial_size.0);

                [positive, negative].into_iter()
            })
            // skip the useless ks of the identity automorphism
            .skip(1)
            .take(window_size as usize)
            .map(|(power, sign_change)| build_autom_key(power, sign_change))
            .collect();

        Self { ak }
    }

    /// Returns the [`AutomKey`] for `diff`, or `None` if `diff` is outside the window
    /// Panics if diff is identity
    pub fn get(&self, diff: Diff) -> Option<&AutomKey> {
        let index = 2 * diff.power_diff + diff.sign_change as usize;

        if index == 0 {
            panic!("Tried to get a key for the trivial automorphism (identity)");
        } else {
            // -1 because we don't store the useless ks of the identity automorphism
            self.ak.get(index - 1)
        }
    }
    pub fn biggest_diff(&self) -> Diff {
        let index_last = self.ak.len() - 1;

        let index_last_including_trivial = index_last + 1;

        Diff {
            power_diff: index_last_including_trivial / 2,
            sign_change: !index_last_including_trivial.is_multiple_of(2),
        }
    }

    /// Applies the largest available automorphism step to `diff` and returns the corresponding
    /// [`AutomKey`].
    ///
    /// If `diff` is within the window, it is consumed entirely and the exact key is returned.
    /// Otherwise the largest key that does not overshoot the sign of `diff` is chosen, `diff` is
    /// reduced by that amount, and the caller should continue looping until `diff` is exhausted.
    pub fn best_diff_reduction(&self, diff: &Diff) -> (Diff, &AutomKey) {
        #[allow(clippy::option_if_let_else)]
        if let Some(autom_key) = self.get(*diff) {
            (*diff, autom_key)
        } else {
            let mut chosen_diff = self.biggest_diff();

            if !diff.sign_change {
                chosen_diff.sign_change = false;
            }

            (chosen_diff, self.get(chosen_diff).unwrap())
        }
    }
}
