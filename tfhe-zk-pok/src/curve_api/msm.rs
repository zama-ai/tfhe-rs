use ark_ec::short_weierstrass::Affine;
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, BigInteger, Field, Fp, PrimeField};
use rayon::prelude::*;

fn make_digits(a: &impl BigInteger, w: usize, num_bits: usize) -> impl Iterator<Item = i64> + '_ {
    let scalar = a.as_ref();
    let radix: u64 = 1 << w;
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    let num_bits = if num_bits == 0 {
        a.num_bits() as usize
    } else {
        num_bits
    };
    let digits_count = num_bits.div_ceil(w);

    (0..digits_count).map(move |i| {
        // Construct a buffer of bits of the scalar, starting at `bit_offset`.
        let bit_offset = i * w;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;
        // Read the bits from the scalar
        let bit_buf = if bit_idx < 64 - w || u64_idx == scalar.len() - 1 {
            // This window's bits are contained in a single u64,
            // or it's the last u64 anyway.
            scalar[u64_idx] >> bit_idx
        } else {
            // Combine the current u64's bits with the bits from the next u64
            (scalar[u64_idx] >> bit_idx) | (scalar[1 + u64_idx] << (64 - bit_idx))
        };

        // Read the actual coefficient value from the window
        let coef = carry + (bit_buf & window_mask); // coef = [0, 2^r)

        // Recenter coefficients from [0,2^w) to [-2^w/2, 2^w/2)
        carry = (coef + radix / 2) >> w;
        let mut digit = (coef as i64) - (carry << w) as i64;

        if i == digits_count - 1 {
            digit += (carry << w) as i64;
        }
        digit
    })
}

// Compute msm using windowed non-adjacent form
#[track_caller]
pub fn msm_wnaf_g1_446(
    bases: &[super::bls12_446::G1Affine],
    scalars: &[super::bls12_446::Zp],
) -> super::bls12_446::G1 {
    use super::bls12_446::*;
    let num_bits = 299usize;
    type BaseField = Fp<ark_ff::MontBackend<crate::curve_446::FqConfig, 7>, 7>;

    assert_eq!(bases.len(), scalars.len());

    let size = bases.len();
    let scalars = &*scalars
        .par_iter()
        .map(|x| x.inner.into_bigint())
        .collect::<Vec<_>>();

    let c = if size < 32 {
        3
    } else {
        // natural log approx
        (size.ilog2() as usize * 69 / 100) + 2
    };

    let digits_count = num_bits.div_ceil(c);
    let scalar_digits = scalars
        .into_par_iter()
        .flat_map_iter(|s| make_digits(s, c, num_bits))
        .collect::<Vec<_>>();

    let zero = G1Affine {
        inner: Affine::zero(),
    };

    let window_sums: Vec<_> = (0..digits_count)
        .into_par_iter()
        .map(|i| {
            let n = 1 << c;
            let mut indices = vec![vec![]; n];
            let mut d = vec![BaseField::ZERO; n + 1];
            let mut e = vec![BaseField::ZERO; n + 1];

            for (idx, digits) in scalar_digits.chunks(digits_count).enumerate() {
                use core::cmp::Ordering;
                // digits is the digits thing of the first scalar?
                let scalar = digits[i];
                match 0.cmp(&scalar) {
                    Ordering::Less => indices[(scalar - 1) as usize].push(idx),
                    Ordering::Greater => indices[(-scalar - 1) as usize].push(!idx),
                    Ordering::Equal => (),
                }
            }

            let mut buckets = vec![zero; 1 << c];

            loop {
                d[0] = BaseField::ONE;
                for (k, (bucket, idx)) in core::iter::zip(&mut buckets, &mut indices).enumerate() {
                    if let Some(idx) = idx.last().copied() {
                        let value = if idx >> (usize::BITS - 1) == 1 {
                            let mut val = bases[!idx];
                            val.inner.y = -val.inner.y;
                            val
                        } else {
                            bases[idx]
                        };

                        if !bucket.inner.infinity {
                            let a = value.inner.x - bucket.inner.x;
                            if a != BaseField::ZERO {
                                d[k + 1] = d[k] * a;
                            } else if value.inner.y == bucket.inner.y {
                                d[k + 1] = d[k] * value.inner.y.double();
                            } else {
                                d[k + 1] = d[k];
                            }
                            continue;
                        }
                    }
                    d[k + 1] = d[k];
                }
                e[n] = d[n].inverse().unwrap();

                for (k, (bucket, idx)) in core::iter::zip(&mut buckets, &mut indices)
                    .enumerate()
                    .rev()
                {
                    if let Some(idx) = idx.last().copied() {
                        let value = if idx >> (usize::BITS - 1) == 1 {
                            let mut val = bases[!idx];
                            val.inner.y = -val.inner.y;
                            val
                        } else {
                            bases[idx]
                        };

                        if !bucket.inner.infinity {
                            let a = value.inner.x - bucket.inner.x;
                            if a != BaseField::ZERO {
                                e[k] = e[k + 1] * a;
                            } else if value.inner.y == bucket.inner.y {
                                e[k] = e[k + 1] * value.inner.y.double();
                            } else {
                                e[k] = e[k + 1];
                            }
                            continue;
                        }
                    }
                    e[k] = e[k + 1];
                }

                let d = &d[..n];
                let e = &e[1..];

                let mut empty = true;
                for ((&d, &e), (bucket, idx)) in core::iter::zip(
                    core::iter::zip(d, e),
                    core::iter::zip(&mut buckets, &mut indices),
                ) {
                    empty &= idx.len() <= 1;
                    if let Some(idx) = idx.pop() {
                        let value = if idx >> (usize::BITS - 1) == 1 {
                            let mut val = bases[!idx];
                            val.inner.y = -val.inner.y;
                            val
                        } else {
                            bases[idx]
                        };

                        if !bucket.inner.infinity {
                            let x1 = bucket.inner.x;
                            let x2 = value.inner.x;
                            let y1 = bucket.inner.y;
                            let y2 = value.inner.y;

                            let eq_x = x1 == x2;

                            if eq_x && y1 != y2 {
                                bucket.inner.infinity = true;
                            } else {
                                let r = d * e;
                                let m = if eq_x {
                                    let x1 = x1.square();
                                    x1 + x1.double()
                                } else {
                                    y2 - y1
                                };
                                let m = m * r;

                                let x3 = m.square() - x1 - x2;
                                let y3 = m * (x1 - x3) - y1;
                                bucket.inner.x = x3;
                                bucket.inner.y = y3;
                            }
                        } else {
                            *bucket = value;
                        }
                    }
                }

                if empty {
                    break;
                }
            }

            let mut running_sum = G1::ZERO;
            let mut res = G1::ZERO;
            buckets.into_iter().rev().for_each(|b| {
                running_sum.inner += b.inner;
                res += running_sum;
            });
            res
        })
        .collect();

    // We store the sum for the lowest window.
    let lowest = *window_sums.first().unwrap();

    // We're traversing windows from high to low.
    lowest
        + window_sums[1..]
            .iter()
            .rev()
            .fold(G1::ZERO, |mut total, &sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total = total.double();
                }
                total
            })
}
