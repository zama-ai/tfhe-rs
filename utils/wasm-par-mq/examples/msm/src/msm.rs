use web_time::Instant;

use ark_ec::short_weierstrass::Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, Fp, PrimeField};
use serde::{Deserialize, Serialize};
use wasm_par_mq::{IntoParallelIterator, ParallelIterator, par_fn, register_fn};

use crate::curve_446::g1::G1Projective;
use crate::{SerializableFp, SerializableG1Affine};

use super::curve_446;

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
    bases: &[curve_446::g1::G1Affine],
    scalar_digits: &[i64],
    digits_count: usize,
) -> G1Projective {
    type BaseField = Fp<ark_ff::MontBackend<crate::curve_446::FqConfig, 7>, 7>;

    let zero = Affine::zero();
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
                    val.y = -val.y;
                    val
                } else {
                    bases[idx]
                };

                if !bucket.infinity {
                    let a = value.x - bucket.x;
                    if a != BaseField::ZERO {
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
            if let Some(idx) = idx.last().copied() {
                let value = if idx >> (usize::BITS - 1) == 1 {
                    let mut val = bases[!idx];
                    val.y = -val.y;
                    val
                } else {
                    bases[idx]
                };

                if !bucket.infinity {
                    let a = value.x - bucket.x;
                    if a != BaseField::ZERO {
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
                let value = if idx >> (usize::BITS - 1) == 1 {
                    let mut val = bases[!idx];
                    val.y = -val.y;
                    val
                } else {
                    bases[idx]
                };

                if !bucket.infinity {
                    let x1: BaseField = bucket.x;
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

    let mut running_sum = G1Projective::ZERO;
    let mut res = G1Projective::ZERO;
    buckets.into_iter().rev().for_each(|b| {
        running_sum += b;
        res += running_sum;
    });
    res
}

// Compute msm using windowed non-adjacent form
#[track_caller]
pub fn msm_wnaf_g1_446(
    bases: &[curve_446::g1::G1Affine],
    scalars: &[curve_446::Fr],
) -> G1Projective {
    let num_bits = 299usize;

    assert_eq!(bases.len(), scalars.len());

    let size = bases.len();
    let scalars = &*scalars.iter().map(|x| x.into_bigint()).collect::<Vec<_>>();

    let c = if size < 32 {
        3
    } else {
        // natural log approx
        (size.ilog2() as usize * 69 / 100) + 2
    };

    let digits_count = num_bits.div_ceil(c);
    let scalar_digits = scalars
        .iter()
        .flat_map(|s| make_digits(s, c, num_bits))
        .collect::<Vec<_>>();

    let window_sums: Vec<_> = (0..digits_count)
        .map(|i| compute_window(i, bases, &scalar_digits, digits_count))
        .collect();

    // We store the sum for the lowest window.
    let lowest = *window_sums.first().unwrap();

    // We're traversing windows from high to low.
    lowest
        + window_sums[1..]
            .iter()
            .rev()
            .fold(G1Projective::ZERO, |mut total, &sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total = total.double();
                }
                total
            })
}

/// Input for parallel MSM: a chunk of bases and scalars
/// Each worker computes a partial MSM on its subset, then results are summed.
/// This approach scales better because each worker only gets 1/N of the data.
#[derive(Serialize, Deserialize, Clone)]
pub struct MsmChunkInput {
    pub chunk_id: usize,
    pub bases: Vec<SerializableG1Affine>,
    pub scalars: Vec<SerializableFp>,
}

/// Worker function that computes MSM on a chunk of bases/scalars
pub fn msm_chunk_worker(input: MsmChunkInput) -> SerializableG1Affine {
    let start = Instant::now();
    let bases: Vec<curve_446::g1::G1Affine> = input.bases.into_iter().map(|b| b.into()).collect();
    let scalars: Vec<curve_446::Fr> = input.scalars.into_iter().map(|s| s.into()).collect();

    let result = msm_wnaf_g1_446(&bases, &scalars);
    let res = SerializableG1Affine::uncompressed(result.into_affine());
    web_sys::console::log_1(
        &format!("msm_chunk #{}: {:#?}", input.chunk_id, start.elapsed()).into(),
    );
    res
}
register_fn!(msm_chunk_worker, MsmChunkInput, SerializableG1Affine);

/// Parallel version of msm_wnaf_g1_446 that distributes base/scalar chunks across workers.
/// Each worker computes a partial MSM, then results are summed.
pub async fn msm_wnaf_g1_446_parallel(
    bases: Vec<SerializableG1Affine>,
    scalars: Vec<SerializableFp>,
) -> G1Projective {
    assert_eq!(bases.len(), scalars.len());

    // Get number of workers to determine chunking
    let num_workers = wasm_par_mq::num_workers().max(1);
    let chunk_size = bases.len().div_ceil(num_workers as usize);

    // Zip bases and scalars, then split into chunks for each worker
    let start = Instant::now();
    let inputs: Vec<MsmChunkInput> = bases
        .chunks(chunk_size)
        .zip(scalars.chunks(chunk_size))
        .enumerate()
        .map(|(chunk_id, (bases, scalars))| MsmChunkInput {
            bases: bases.to_vec(),
            scalars: scalars.to_vec(),
            chunk_id,
        })
        .collect();
    web_sys::console::log_1(&format!("prepoc: {:#?}", start.elapsed()).into());

    // Execute chunks in parallel across workers
    let chunk_results: Vec<SerializableG1Affine> = inputs
        .into_par_iter()
        .map(par_fn!(msm_chunk_worker))
        .collect_vec()
        .await;
    web_sys::console::log_1(&format!("msm_chunk: {:#?}", start.elapsed()).into());

    // Sum partial results from each worker
    let res = chunk_results
        .into_iter()
        .map(|r| {
            let affine: curve_446::g1::G1Affine = r.into();
            G1Projective::from(affine)
        })
        .fold(G1Projective::ZERO, |acc, p| acc + p);

    web_sys::console::log_1(&format!("sum: {:#?}", start.elapsed()).into());
    res
}

/// Input for sync parallel MSM execution (public for use in lib.rs)
#[derive(Serialize, Deserialize, Clone)]
pub struct MsmSyncInput {
    pub bases: Vec<SerializableG1Affine>,
    pub scalars: Vec<SerializableFp>,
}

/// Sync version of the parallel MSM that uses collect_vec_sync()
/// This runs inside the SyncExecutor worker
pub fn msm_wnaf_g1_446_parallel_sync(input: MsmSyncInput) -> SerializableG1Affine {
    let bases = input.bases;
    let scalars = input.scalars;

    // Get number of workers to determine chunking
    let num_workers = wasm_par_mq::num_workers().max(1);
    let chunk_size = bases.len().div_ceil(num_workers as usize);

    // Zip bases and scalars, then split into chunks for each worker
    let start = Instant::now();
    let inputs: Vec<MsmChunkInput> = bases
        .chunks(chunk_size)
        .zip(scalars.chunks(chunk_size))
        .enumerate()
        .map(|(chunk_id, (bases, scalars))| MsmChunkInput {
            bases: bases.to_vec(),
            scalars: scalars.to_vec(),
            chunk_id,
        })
        .collect();
    web_sys::console::log_1(&format!("[sync] preproc: {:#?}", start.elapsed()).into());

    // Execute chunks in parallel using sync blocking API
    let chunk_results: Vec<SerializableG1Affine> = inputs
        .into_par_iter()
        .map(par_fn!(msm_chunk_worker))
        .collect_vec_sync();
    web_sys::console::log_1(&format!("[sync] msm_chunk: {:#?}", start.elapsed()).into());

    // Sum partial results from each worker
    let res = chunk_results
        .into_iter()
        .map(|r| {
            let affine: curve_446::g1::G1Affine = r.into();
            G1Projective::from(affine)
        })
        .fold(G1Projective::ZERO, |acc, p| acc + p);

    web_sys::console::log_1(&format!("[sync] sum: {:#?}", start.elapsed()).into());
    SerializableG1Affine::uncompressed(res.into_affine())
}
register_fn!(
    msm_wnaf_g1_446_parallel_sync,
    MsmSyncInput,
    SerializableG1Affine
);
