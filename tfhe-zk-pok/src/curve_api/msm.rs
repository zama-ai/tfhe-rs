use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
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

trait MsmAffine: Copy + Send + Sync {
    type Config: SWCurveConfig;
    fn to_ark_affine(&self) -> &Affine<Self::Config>;
}

impl MsmAffine for super::bls12_446::G1Affine {
    type Config = crate::curve_446::g1::Config;
    #[inline]
    fn to_ark_affine(&self) -> &Affine<Self::Config> {
        &self.inner
    }
}

impl MsmAffine for super::bls12_446::G2Affine {
    type Config = crate::curve_446::g2::Config;
    #[inline]
    fn to_ark_affine(&self) -> &Affine<Self::Config> {
        &self.inner
    }
}

#[track_caller]
fn compute_window<Aff: MsmAffine>(
    i: usize,
    bases: &[Aff],
    scalar_digits: &[i64],
    digits_count: usize,
) -> Projective<Aff::Config> {
    type BaseField<Aff> = <<Aff as MsmAffine>::Config as ark_ec::CurveConfig>::BaseField;

    let zero = Affine::<Aff::Config>::zero();

    let size = bases.len();

    let c = if size < 32 {
        3
    } else {
        // natural log approx
        (size.ilog2() as usize * 69 / 100) + 2
    };

    let n = 1 << c;
    let mut indices = vec![vec![]; n];
    let mut d = vec![BaseField::<Aff>::ZERO; n + 1];
    let mut e = vec![BaseField::<Aff>::ZERO; n + 1];

    for (idx, digits) in scalar_digits.chunks(digits_count).enumerate() {
        use core::cmp::Ordering;
        let scalar = digits[i];
        match 0.cmp(&scalar) {
            Ordering::Less => indices[(scalar - 1) as usize].push(idx),
            Ordering::Greater => indices[(-scalar - 1) as usize].push(!idx),
            Ordering::Equal => (),
        }
    }

    let get_base = |idx: usize| -> Affine<Aff::Config> {
        if idx >> (usize::BITS - 1) == 1 {
            let base = bases[!idx].to_ark_affine();
            Affine::<Aff::Config> {
                x: base.x,
                y: -base.y,
                infinity: base.infinity,
            }
        } else {
            *bases[idx].to_ark_affine()
        }
    };

    let mut buckets = vec![zero; 1 << c];

    loop {
        d[0] = BaseField::<Aff>::ONE;
        for (k, (bucket, idx)) in core::iter::zip(&mut buckets, &mut indices).enumerate() {
            if let Some(&idx) = idx.last() {
                let value = get_base(idx);

                if !bucket.infinity {
                    let a = value.x - bucket.x;
                    if a != BaseField::<Aff>::ZERO {
                        d[k + 1] = d[k] * a;
                    } else if value.y == bucket.y {
                        d[k + 1] = d[k] * value.y.double();
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
            if let Some(&idx) = idx.last() {
                let value = get_base(idx);

                if !bucket.infinity {
                    let a = value.x - bucket.x;
                    if a != BaseField::<Aff>::ZERO {
                        e[k] = e[k + 1] * a;
                    } else if value.y == bucket.y {
                        e[k] = e[k + 1] * value.y.double();
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
                let value = get_base(idx);

                if !bucket.infinity {
                    let x1 = bucket.x;
                    let x2 = value.x;
                    let y1 = bucket.y;
                    let y2 = value.y;

                    let eq_x = x1 == x2;

                    if eq_x && y1 != y2 {
                        bucket.infinity = true;
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
                        bucket.x = x3;
                        bucket.y = y3;
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

    let mut running_sum = Projective::<Aff::Config>::ZERO;
    let mut res = Projective::<Aff::Config>::ZERO;
    buckets.into_iter().rev().for_each(|b| {
        running_sum += b;
        res += running_sum;
    });
    res
}

fn msm_wnaf<A: MsmAffine>(bases: &[A], scalars: &[super::bls12_446::Zp]) -> Projective<A::Config> {
    // size of the scalars, the modulus used for FrConfig in curve446::mod.rs is 299 bits
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
        (size.ilog2() as usize * 69 / 100) + 2
    };

    let digits_count = num_bits.div_ceil(c);
    let scalar_digits = scalars
        .into_par_iter()
        .flat_map_iter(|s| make_digits(s, c, num_bits))
        .collect::<Vec<_>>();

    let window_sums: Vec<_> = (0..digits_count)
        .into_par_iter()
        .map(|i| compute_window::<A>(i, bases, &scalar_digits, digits_count))
        .collect();

    let lowest = *window_sums.first().unwrap();

    lowest
        + window_sums[1..]
            .iter()
            .rev()
            .fold(Projective::<A::Config>::ZERO, |mut total, &sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total.double_in_place();
                }
                total
            })
}

#[track_caller]
pub fn msm_wnaf_g1_446(
    bases: &[super::bls12_446::G1Affine],
    scalars: &[super::bls12_446::Zp],
) -> super::bls12_446::G1 {
    super::bls12_446::G1 {
        inner: msm_wnaf(bases, scalars),
    }
}

#[track_caller]
pub fn msm_wnaf_g2_446(
    bases: &[super::bls12_446::G2Affine],
    scalars: &[super::bls12_446::Zp],
) -> super::bls12_446::G2 {
    super::bls12_446::G2 {
        inner: msm_wnaf(bases, scalars),
    }
}

#[cfg(all(target_family = "wasm", feature = "cross-origin"))]
pub mod cross_origin {
    use crate::serialization::{
        SerializableAffine, SerializableFp, SerializableG1Affine, SerializableG1Projective,
        SerializableG2Affine, SerializableG2Projective,
    };
    use serde::{Deserialize, Serialize};
    use wasm_par_mq::{par_fn, register_fn, IntoParallelIterator, ParallelIterator};

    use super::{msm_wnaf_g1_446, msm_wnaf_g2_446};
    use crate::curve_api::bls12_446::{G1Affine, G2Affine, Zp, G1, G2};

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
        result.inner.into()
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

        let result = msm_wnaf_g2_446(&bases, &scalars);
        result.inner.into()
    }
    register_fn!(
        g2_msm_chunk_worker,
        G2MsmChunkInput,
        SerializableG2Projective
    );

    pub fn msm_wnaf_g1_446_cross_origin(bases: &[G1Affine], scalars: &[Zp]) -> G1 {
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
            .try_fold(G1::ZERO, |acc, r| {
                Ok::<_, crate::serialization::InvalidFpError>(
                    acc + G1 {
                        inner: r.try_into()?,
                    },
                )
            })
            .expect("worker returned invalid projective point")
    }

    pub fn msm_wnaf_g2_446_cross_origin(bases: &[G2Affine], scalars: &[Zp]) -> G2 {
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
            .try_fold(G2::ZERO, |acc, r| {
                Ok::<_, crate::serialization::InvalidFpError>(
                    acc + G2 {
                        inner: r.try_into()?,
                    },
                )
            })
            .expect("worker returned invalid projective point")
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::CurveGroup;
    use rand::rngs::StdRng;
    use rand::{thread_rng, Rng, SeedableRng};

    use super::*;
    use crate::curve_api::bls12_446::{G1Affine, G2Affine, Zp, G1, G2};

    const MSM_SIZES: [usize; 7] = [1, 2, 7, 32, 64, 256, 1024];
    const TEST_COUNT: usize = 10;

    fn random_g1_affine_points(rng: &mut dyn rand::RngCore, n: usize) -> Vec<G1Affine> {
        (0..n)
            .map(|_| G1Affine {
                inner: G1::GENERATOR.mul_scalar(Zp::rand(rng)).inner.into_affine(),
            })
            .collect()
    }

    fn random_g2_affine_points(rng: &mut dyn rand::RngCore, n: usize) -> Vec<G2Affine> {
        (0..n)
            .map(|_| G2Affine {
                inner: G2::GENERATOR.mul_scalar(Zp::rand(rng)).inner.into_affine(),
            })
            .collect()
    }

    fn random_scalars(rng: &mut dyn rand::RngCore, n: usize) -> Vec<Zp> {
        (0..n).map(|_| Zp::rand(rng)).collect()
    }

    #[test]
    fn test_wnaf_msm_g1_matches_arkworks() {
        let seed = thread_rng().gen();
        println!("test_wnaf_msm_g1_matches_arkworks seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        for _ in 0..TEST_COUNT {
            for n in MSM_SIZES {
                let bases = random_g1_affine_points(rng, n);
                let scalars = random_scalars(rng, n);

                let wnaf_result = msm_wnaf_g1_446(&bases, &scalars);
                let ark_result = G1Affine::multi_mul_scalar(&bases, &scalars);

                assert_eq!(wnaf_result, ark_result, "G1 MSM mismatch for n={n}");
            }
        }
    }

    #[test]
    fn test_wnaf_msm_g2_matches_arkworks() {
        let seed = thread_rng().gen();
        println!("test_wnaf_msm_g2_matches_arkworks seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        for _ in 0..TEST_COUNT {
            for n in MSM_SIZES {
                let bases = random_g2_affine_points(rng, n);
                let scalars = random_scalars(rng, n);

                let wnaf_result = msm_wnaf_g2_446(&bases, &scalars);
                let ark_result = G2Affine::multi_mul_scalar(&bases, &scalars);

                assert_eq!(wnaf_result, ark_result, "G2 MSM mismatch for n={n}");
            }
        }
    }
}
