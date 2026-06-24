use crate::core_crypto::experimental::algorithms::automorphism_based_decomposition::{
    BaseDecomposer, Decomposition,
};
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::{LweCiphertext, PolynomialSize, UnsignedInteger};

/// Standard PBS modulus switch: maps `input` from the native modulus to `[0, 2N)`.
pub fn pbs_modulus_switch<Scalar: UnsignedInteger>(
    input: Scalar,
    polynomial_size: PolynomialSize,
) -> Scalar {
    modulus_switch(input, polynomial_size.to_blind_rotation_input_modulus_log())
}

/// Modulus switch that rounds to the nearest odd value in `[1, 2N)`.
///
/// The automorphism base decomposition requires all mask values to be odd (they must lie in
/// `Z*_{2N}`). This function rounds `input` to the closest odd representative so that it can
/// be expressed as `±base^k`. The rounding introduces slightly more noise than the standard PBS
/// modulus switch; prefer the bit-combining path (`allow_combine = true`) when possible.
pub fn automorphism_modulus_switch<Scalar: UnsignedInteger>(
    input: Scalar,
    polynomial_size: PolynomialSize,
) -> Scalar {
    let log_modulus = polynomial_size.to_blind_rotation_input_modulus_log();

    let floor_into_even_value = input >> (Scalar::BITS - log_modulus.0 + 1);

    (floor_into_even_value << 1) + Scalar::ONE
}

/// One mask element after modulus-switching and base decomposition, ready for blind rotation.
#[derive(Clone, Copy, Debug)]
pub struct MaskElement {
    /// How this mask coefficient is expressed as `±base^k mod 2N`.
    pub decomposition: Decomposition,
    /// Index into the LWE secret key for this coefficient.
    pub sk_index: usize,
    /// When `true`, the [`super::trav_bsk::TravBsk`] key for `sk_index` was generated for
    /// `s_{sk_index} + s_{sk_index+1}` (bit combining to avoid even mask values).
    pub combine_with_next: bool,
}

/// A modulus-switched LWE ciphertext prepared for automorphism-based blind rotation.
///
/// The body is modulus-switched to `[0, 2N)` in the standard way. Each mask coefficient is
/// either:
/// - rounded to the nearest odd value (when `allow_combine = false`), or
/// - transformed via bit-combining so that all values become odd while preserving the inner product
///   `⟨s, a⟩ mod 2N` (when `allow_combine = true`).
///
/// Odd mask values are required because the automorphisms for even values are not invertible.
///
/// The masks are then sorted by `(base_exponent, negative)` to minimise sign-change transitions
/// during blind rotation, which avoids unnecessary automorphism applications.
pub struct MsedLweFromAutomorphism {
    pub body: u64,
    pub masks: Vec<MaskElement>,
}

impl MsedLweFromAutomorphism {
    /// Modulus-switches `lwe` and decomposes each mask coefficient into the multiplicative base.
    ///
    /// The body is switched to `[0, 2N)` with the standard PBS rounding. For the mask there are
    /// two strategies controlled by `allow_combine`:
    ///
    /// - `allow_combine = false`: each coefficient is rounded to the nearest odd value via
    ///   [`automorphism_modulus_switch`]. Simple but introduces slightly more noise.
    /// - `allow_combine = true`: coefficients are first switched normally, then
    ///   `combine_to_make_all_odd` rewrites even values as differences of adjacent odd values,
    ///   preserving `⟨s, a⟩` without the extra rounding noise.
    ///
    /// The resulting [`MaskElement`]s are sorted by `(base_exponent, negative)` to minimise
    /// sign-change transitions during blind rotation.
    pub fn new(
        lwe: &LweCiphertext<Vec<u64>>,
        polynomial_size: PolynomialSize,
        base: u64,
        allow_combine: bool,
    ) -> Self {
        let decomposer = BaseDecomposer::new(base, polynomial_size);

        let (lwe_mask, lwe_body) = lwe.get_mask_and_body();

        let body = pbs_modulus_switch(*lwe_body.data, polynomial_size);

        let masks: Vec<MaskElement> = if allow_combine {
            // Allow even masks in first rounding pass
            let masks: Vec<u64> = lwe_mask
                .as_ref()
                .iter()
                .map(|a| pbs_modulus_switch(*a, polynomial_size))
                .collect();

            let masks = combine_to_make_all_odd(&masks, 2 * polynomial_size.0 as u64);

            masks
                .into_iter()
                .enumerate()
                .map(
                    |(
                        sk_index,
                        MsedValue {
                            value,
                            combine_with_next,
                        },
                    )| MaskElement {
                        decomposition: decomposer.decompose_in_base(value),
                        sk_index,
                        combine_with_next,
                    },
                )
                .collect()
        } else {
            // Round to closest odd value
            // Worse in terms of noise
            lwe_mask
                .as_ref()
                .iter()
                .map(|a| automorphism_modulus_switch(*a, polynomial_size))
                .enumerate()
                .map(|(sk_index, value)| MaskElement {
                    decomposition: decomposer.decompose_in_base(value),
                    sk_index,
                    combine_with_next: false,
                })
                .collect()
        };

        Self {
            body,
            masks: sort_avoid_changing_sign_neighbors(masks),
        }
    }
}

/// Reorders `masks` to minimise sign-change transitions during blind rotation.
///
/// Items are first sorted by `(base_exponent, negative)`. Then, within each group sharing the
/// same `base_exponent`, the traversal order (positive-first or negative-first) is chosen so
/// that the last item of one group and the first item of the next group have the same sign
/// whenever possible, avoiding an extra automorphism application for a sign flip.
fn sort_avoid_changing_sign_neighbors(mut masks: Vec<MaskElement>) -> Vec<MaskElement> {
    masks.sort_unstable_by_key(
        |MaskElement {
             decomposition:
                 Decomposition {
                     base_exponent,
                     negative,
                 },

             sk_index: _,
             combine_with_next: _,
         }| (*base_exponent, *negative),
    );

    let mut masks2 = vec![];

    let mut start_index = 0;
    let mut previous_negative = false;

    while start_index < masks.len() {
        let mut index = start_index;
        let current_base_exponent = masks[index].decomposition.base_exponent;

        while index < masks.len()
            && masks[index].decomposition.base_exponent == current_base_exponent
        {
            index += 1;
        }

        let end_index = index;

        if previous_negative {
            // add all at current_base_exponent in reversed sorted order (negative then
            // positive)
            for item in masks[start_index..end_index].iter().rev() {
                masks2.push(*item);

                previous_negative = item.decomposition.negative
            }
        } else {
            // add all at current_base_exponent in sorted order (positive then negative)
            for item in masks[start_index..end_index].iter() {
                masks2.push(*item);

                previous_negative = item.decomposition.negative
            }
        }

        start_index = end_index;
    }
    masks2
}

/// Private helper produced by the modulus-switch step.
///
/// `value` is an odd residue in `[1, 2N)` ready for base decomposition.
/// `combine_with_next` is `true` when this value was derived by bit-combining: the corresponding
/// LWE secret key coefficient has been replaced by `s_i + s_{i+1}` in the [`TravBsk`] lookup.
struct MsedValue {
    value: u64,
    combine_with_next: bool,
}

/// Rewrites a list of modulus-switched mask values so that all entries are odd.
///
/// Even values cannot be decomposed in the multiplicative base (they are not in `Z*_{2N}`).
/// The trick is to rewrite the inner product `⟨s, a⟩` by absorbing even entries into their
/// neighbours. For example, if `m0` is odd and `m1`, `m2` are even:
///
/// ```text
/// s0·m0 + s1·m1 + s2·m2
/// = (s0+s1)·m0 + (s1+s2)·(m1-m0) + s2·(m2-m1+m0)
/// ```
///
/// All three new coefficients are odd. The flag `combine_with_next` on entry `i` signals that
/// `s_i` must be looked up as `s_i + s_{i+1}` in the [`TravBsk`] keys.
fn combine_to_make_all_odd(masks: &[u64], module: u64) -> Vec<MsedValue> {
    let first_odd_index = {
        let mut first_odd_index = 0;

        while masks[first_odd_index].is_multiple_of(2) {
            first_odd_index += 1;
        }

        first_odd_index
    };

    assert_eq!(masks[first_odd_index] % 2, 1);

    let mut first_odd = MsedValue {
        combine_with_next: false,
        value: masks[first_odd_index],
    };

    let masks_before_after_odd = &masks[first_odd_index + 1..masks.len()];

    let mut odd_masks_after_first_odd =
        build_odd_values(module, &mut first_odd, masks_before_after_odd);

    let last = odd_masks_after_first_odd.last_mut().unwrap();

    let masks_before_fist_odd = &masks[0..first_odd_index];

    let odd_masks_before_first_odd = build_odd_values(
        module,
        // We allow the first coefficient to be combined with the last
        last,
        masks_before_fist_odd,
    );

    let mut all_odd_masks = odd_masks_before_first_odd;

    all_odd_masks.push(first_odd);

    all_odd_masks.extend(odd_masks_after_first_odd);

    all_odd_masks
}

/// Converts a slice of modulus-switched mask values into odd values, given a starting
/// `previous_odd_mask`.
///
/// For each entry in `masks_subslice`:
/// - If it is already odd, it is appended as-is.
/// - If it is even, it cannot be base-decomposed directly. Instead, the previous odd entry (or
///   `previous_odd_mask` when the running list is empty) is flagged `combine_with_next = true`, and
///   the new entry is set to `(mask - previous.value) mod module`. This value is odd because `mask`
///   is even and `previous.value` is odd (even − odd = odd).
fn build_odd_values(
    module: u64,
    previous_odd_mask: &mut MsedValue,
    masks_subslice: &[u64],
) -> Vec<MsedValue> {
    let mut odd_masks: Vec<MsedValue> = vec![];

    for mask in masks_subslice {
        let new_odd_mask = if mask.is_multiple_of(2) {
            // if the mask is even, we must combine it with the previous one (which is already odd)
            // to make it odd
            let previous = odd_masks.last_mut().unwrap_or(previous_odd_mask);

            previous.combine_with_next = true;

            (module + mask - previous.value) % module
        } else {
            *mask
        };

        assert_eq!(new_odd_mask % 2, 1);

        odd_masks.push(MsedValue {
            value: new_odd_mask,
            combine_with_next: false,
        });
    }
    odd_masks
}
