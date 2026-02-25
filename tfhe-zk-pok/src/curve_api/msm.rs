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

pub fn compute_window(
    i: usize,
    bases: &[super::bls12_446::G1Affine],
    scalar_digits: &[i64],
    digits_count: usize,
) -> super::bls12_446::G1 {
    use super::bls12_446::*;

    type BaseField = Fp<ark_ff::MontBackend<crate::curve_446::FqConfig, 7>, 7>;

    let zero = G1Affine {
        inner: Affine::zero(),
    };
    let size = bases.len();

    let c = if size < 32 {
        3
    } else {
        // natural log approx
        (size.ilog2() as usize * 69 / 100) + 2
    };

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
                    let x1: BaseField = bucket.inner.x;
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
}

// Compute msm using windowed non-adjacent form
#[track_caller]
pub fn msm_wnaf_g1_446(
    bases: &[super::bls12_446::G1Affine],
    scalars: &[super::bls12_446::Zp],
) -> super::bls12_446::G1 {
    use super::bls12_446::*;
    let num_bits = 299usize;

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

    let window_sums: Vec<_> = (0..digits_count)
        .into_par_iter()
        .map(|i| compute_window(i, bases, &scalar_digits, digits_count))
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

#[cfg(target_family = "wasm")]
pub mod cross_origin {
    use crate::curve_api::bls12_446::{G2Affine, G2 as G2Projective};
    use crate::serialization::{
        SerializableAffine, SerializableFp, SerializableFp2, SerializableG1Affine,
        SerializableG2Affine,
    };
    use serde::{Deserialize, Serialize};
    use wasm_par_mq::{par_fn, register_fn, IntoParallelIterator, ParallelIterator};

    #[derive(Serialize, Deserialize)]
    pub struct SerializableProjective<F> {
        x: F,
        y: F,
        z: F,
    }

    pub type SerializableG1Projective = SerializableProjective<SerializableFp>;
    pub type SerializableG2Projective = SerializableProjective<SerializableFp2>;

    impl From<G1Projective> for SerializableG1Projective {
        fn from(value: G1Projective) -> Self {
            Self {
                x: value.inner.x.into(),
                y: value.inner.y.into(),
                z: value.inner.z.into(),
            }
        }
    }

    impl TryFrom<SerializableG1Projective> for G1Projective {
        type Error = crate::serialization::InvalidFpError;

        fn try_from(value: SerializableG1Projective) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: ark_ec::short_weierstrass::Projective {
                    x: value.x.try_into()?,
                    y: value.y.try_into()?,
                    z: value.z.try_into()?,
                },
            })
        }
    }

    impl From<G2Projective> for SerializableG2Projective {
        fn from(value: G2Projective) -> Self {
            Self {
                x: value.inner.x.into(),
                y: value.inner.y.into(),
                z: value.inner.z.into(),
            }
        }
    }

    impl TryFrom<SerializableG2Projective> for G2Projective {
        type Error = crate::serialization::InvalidFpError;

        fn try_from(value: SerializableG2Projective) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: ark_ec::short_weierstrass::Projective {
                    x: value.x.try_into()?,
                    y: value.y.try_into()?,
                    z: value.z.try_into()?,
                },
            })
        }
    }

    use crate::curve_api::bls12_446::{G1Affine, Zp, G1 as G1Projective};

    use super::msm_wnaf_g1_446;

    /// Input for parallel MSM: a chunk of bases and scalars
    /// Each worker computes a partial MSM on its subset, then results are summed.
    #[derive(Serialize, Deserialize)]
    pub struct G1MsmChunkInput {
        pub chunk_id: usize,
        pub bases: Vec<SerializableG1Affine>,
        pub scalars: Vec<SerializableFp>,
    }

    fn g1_msm_chunk_worker(input: G1MsmChunkInput) -> SerializableG1Projective {
        let bases: Vec<G1Affine> = input
            .bases
            .into_iter()
            .map(|b| b.try_into().unwrap())
            .collect();
        let scalars: Vec<Zp> = input
            .scalars
            .into_iter()
            .map(|s| s.try_into().unwrap())
            .collect();

        let result = msm_wnaf_g1_446(&bases, &scalars);
        result.into()
    }
    register_fn!(
        g1_msm_chunk_worker,
        G1MsmChunkInput,
        SerializableG1Projective
    );

    /// Input for parallel MSM: a chunk of bases and scalars
    /// Each worker computes a partial MSM on its subset, then results are summed.
    #[derive(Serialize, Deserialize)]
    pub struct G2MsmChunkInput {
        pub chunk_id: usize,
        pub bases: Vec<SerializableG2Affine>,
        pub scalars: Vec<SerializableFp>,
    }

    fn g2_msm_chunk_worker(input: G2MsmChunkInput) -> SerializableG2Projective {
        let bases: Vec<G2Affine> = input
            .bases
            .into_iter()
            .map(|b| b.try_into().unwrap())
            .collect();
        let scalars: Vec<Zp> = input
            .scalars
            .into_iter()
            .map(|s| s.try_into().unwrap())
            .collect();

        let result = G2Affine::multi_mul_scalar(&bases, &scalars);
        result.into()
    }
    register_fn!(
        g2_msm_chunk_worker,
        G2MsmChunkInput,
        SerializableG2Projective
    );

    pub fn msm_wnaf_g1_446_cross_origin(bases: &[G1Affine], scalars: &[Zp]) -> G1Projective {
        assert_eq!(bases.len(), scalars.len());

        let num_workers = wasm_par_mq::num_workers().max(1);
        let chunk_size = bases.len().div_ceil(num_workers as usize);

        let inputs: Vec<G1MsmChunkInput> = bases
            .chunks(chunk_size)
            .zip(scalars.chunks(chunk_size))
            .enumerate()
            .map(|(chunk_id, (bases, scalars))| G1MsmChunkInput {
                chunk_id,
                bases: bases.iter().map(|b| SerializableAffine::from(*b)).collect(),
                scalars: scalars.iter().map(|s| SerializableFp::from(*s)).collect(),
            })
            .collect();

        let chunk_results: Vec<SerializableG1Projective> = inputs
            .into_par_iter()
            .map(par_fn!(g1_msm_chunk_worker))
            .collect_vec_sync();

        chunk_results
            .into_iter()
            .try_fold(G1Projective::ZERO, |acc, r| {
                Ok::<_, crate::serialization::InvalidFpError>(acc + G1Projective::try_from(r)?)
            })
            .expect("worker returned invalid projective point")
    }

    pub fn msm_g2_cross_origin(bases: &[G2Affine], scalars: &[Zp]) -> G2Projective {
        assert_eq!(bases.len(), scalars.len());

        let num_workers = wasm_par_mq::num_workers().max(1);
        let chunk_size = bases.len().div_ceil(num_workers as usize);

        let inputs: Vec<G2MsmChunkInput> = bases
            .chunks(chunk_size)
            .zip(scalars.chunks(chunk_size))
            .enumerate()
            .map(|(chunk_id, (bases, scalars))| G2MsmChunkInput {
                chunk_id,
                bases: bases.iter().map(|b| SerializableAffine::from(*b)).collect(),
                scalars: scalars.iter().map(|s| SerializableFp::from(*s)).collect(),
            })
            .collect();

        let chunk_results: Vec<SerializableG2Projective> = inputs
            .into_par_iter()
            .map(par_fn!(g2_msm_chunk_worker))
            .collect_vec_sync();

        chunk_results
            .into_iter()
            .try_fold(G2Projective::ZERO, |acc, r| {
                Ok::<_, crate::serialization::InvalidFpError>(acc + G2Projective::try_from(r)?)
            })
            .expect("worker returned invalid projective point")
    }
}
