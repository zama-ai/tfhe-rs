use crate::backward_compatibility::GroupElementsVersions;

use crate::curve_api::{Compressible, Curve, CurveGroupOps, FieldOps, PairingGroupOps};
use crate::serialization::{
    InvalidSerializedGroupElementsError, SerializableG1Affine, SerializableG2Affine,
    SerializableGroupElements,
};
use core::ops::{Index, IndexMut};
use rand::{Rng, RngCore};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::fmt::Display;
use std::sync::{Arc, OnceLock};
use tfhe_versionable::Versionize;

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[repr(transparent)]
pub(crate) struct OneBased<T: ?Sized>(pub(crate) T);

/// The proving scheme is available in 2 versions, one that puts more load on the prover and one
/// that puts more load on the verifier
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ComputeLoad {
    Proof = 0,
    Verify = 1,
}

impl Display for ComputeLoad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComputeLoad::Proof => write!(f, "compute_load_proof"),
            ComputeLoad::Verify => write!(f, "compute_load_verify"),
        }
    }
}

impl<T: ?Sized> OneBased<T> {
    pub fn new(inner: T) -> Self
    where
        T: Sized,
    {
        Self(inner)
    }

    #[cfg(feature = "experimental")]
    pub fn new_ref(inner: &T) -> &Self {
        unsafe { &*(inner as *const T as *const Self) }
    }
}

impl<T: ?Sized + Index<usize>> Index<usize> for OneBased<T> {
    type Output = T::Output;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index - 1]
    }
}

impl<T: ?Sized + IndexMut<usize>> IndexMut<usize> for OneBased<T> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index - 1]
    }
}

pub type Affine<Zp, Group> = <Group as CurveGroupOps<Zp>>::Affine;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(
    deserialize = "G: Curve, G::G1: serde::Deserialize<'de>, G::G2: serde::Deserialize<'de>",
    serialize = "G: Curve, G::G1: serde::Serialize, G::G2: serde::Serialize"
))]
#[versionize(GroupElementsVersions)]
pub(crate) struct GroupElements<G: Curve> {
    pub(crate) g_list: OneBased<Vec<Affine<G::Zp, G::G1>>>,
    pub(crate) g_hat_list: OneBased<Vec<Affine<G::Zp, G::G2>>>,
    pub(crate) message_len: usize,
}

impl<G: Curve> GroupElements<G> {
    pub fn new(message_len: usize, alpha: G::Zp) -> Self {
        let (g_list, g_hat_list) = rayon::join(
            || {
                let mut g_list = Vec::with_capacity(2 * message_len);

                let mut g_cur = G::G1::GENERATOR.mul_scalar(alpha);

                for i in 0..2 * message_len {
                    if i == message_len {
                        g_list.push(G::G1::ZERO.normalize());
                    } else {
                        g_list.push(g_cur.normalize());
                    }
                    g_cur = g_cur.mul_scalar(alpha);
                }

                g_list
            },
            || {
                let mut g_hat_list = Vec::with_capacity(message_len);
                let mut g_hat_cur = G::G2::GENERATOR.mul_scalar(alpha);
                for _ in 0..message_len {
                    g_hat_list.push(g_hat_cur.normalize());
                    g_hat_cur = g_hat_cur.mul_scalar(alpha);
                }
                g_hat_list
            },
        );

        Self::from_vec(g_list, g_hat_list)
    }

    pub fn from_vec(
        g_list: Vec<Affine<G::Zp, G::G1>>,
        g_hat_list: Vec<Affine<G::Zp, G::G2>>,
    ) -> Self {
        let message_len = g_hat_list.len();

        Self {
            g_list: OneBased::new(g_list),
            g_hat_list: OneBased::new(g_hat_list),
            message_len,
        }
    }

    /// Check if the elements are valid for their respective groups
    pub fn is_valid(&self, n: usize) -> bool {
        if self.g_list.0.len() != n * 2
            || self.g_hat_list.0.len() != n
            || G::G1::projective(self.g_list[n + 1]) != G::G1::ZERO
        {
            return false;
        }

        let (g_list_valid, g_hat_list_valid) = rayon::join(
            || self.g_list.0.par_iter().all(G::G1::validate_affine),
            || self.g_hat_list.0.par_iter().all(G::G2::validate_affine),
        );

        g_list_valid && g_hat_list_valid
    }
}

/// Allows to compute proof with bad inputs for tests
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum ProofSanityCheckMode {
    Panic,
    #[cfg(test)]
    Ignore,
}

/// Check the preconditions of the pke proof before computing it. Panic if one of the conditions
/// does not hold.
#[allow(clippy::too_many_arguments)]
pub(crate) fn assert_pke_proof_preconditions(
    a: &[i64],
    b: &[i64],
    c1: &[i64],
    e1: &[i64],
    c2: &[i64],
    e2: &[i64],
    d: usize,
    k_max: usize,
    big_d: usize,
    big_d_max: usize,
) {
    assert!(k_max <= d);
    assert_eq!(a.len(), d);
    assert_eq!(b.len(), d);
    assert_eq!(c1.len(), d);
    assert_eq!(e1.len(), d);

    assert_eq!(c2.len(), e2.len());
    assert!(c2.len() <= k_max);

    assert!(big_d <= big_d_max);
}

/// q (modulus) is encoded on 64b, with 0 meaning 2^64. This converts the encoded q to its effective
/// value for modular operations.
pub(crate) fn decode_q(q: u64) -> u128 {
    if q == 0 {
        1u128 << 64
    } else {
        q as u128
    }
}

/// Compute r1 according to eq (11):
///
/// rot(a) * phi(bar(r)) - q phi(r1) + phi(e1) = phi(c1)
/// implies
/// phi(r1) = (rot(a) * phi(bar(r)) + phi(e1) - phi(c1)) / q
/// (phi is the function that maps a polynomial to its coeffs vector)
pub(crate) fn compute_r1(
    e1: &[i64],
    c1: &[i64],
    a: &[i64],
    r: &[i64],
    d: usize,
    decoded_q: u128,
) -> Box<[i64]> {
    let mut r1 = e1
        .iter()
        .zip(c1.iter())
        .map(|(&e1, &c1)| e1 as i128 - c1 as i128)
        .collect::<Box<[_]>>();

    for i in 0..d {
        for j in 0..d {
            if i + j < d {
                r1[i + j] += a[i] as i128 * r[d - j - 1] as i128;
            } else {
                r1[i + j - d] -= a[i] as i128 * r[d - j - 1] as i128;
            }
        }
    }

    {
        for r1 in &mut *r1 {
            *r1 /= decoded_q as i128;
        }
    }

    r1.into_vec().into_iter().map(|r1| r1 as i64).collect()
}

/// Compute r2 according to eq (11):
///
/// phi_[d - i](b).T * phi(bar(r)) + delta * m_i - q r2_i + e2_i = c2_i
/// implies
/// r2_i = (phi_[d - i](b).T * phi(bar(r)) + delta * m_i + e2_i - c2_i) / q
/// (phi is the function that maps a polynomial to its coeffs vector)
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_r2(
    e2: &[i64],
    c2: &[i64],
    m: &[i64],
    b: &[i64],
    r: &[i64],
    d: usize,
    delta: u64,
    decoded_q: u128,
) -> Box<[i64]> {
    let mut r2 = m
        .iter()
        .zip(e2)
        .zip(c2)
        .map(|((&m, &e2), &c2)| delta as i128 * m as i128 + e2 as i128 - c2 as i128)
        .collect::<Box<[_]>>();

    {
        for (i, r2) in r2.iter_mut().enumerate() {
            let mut dot = 0i128;
            for j in 0..d {
                let b = if i + j < d {
                    b[d - j - i - 1] as i128
                } else {
                    -(b[2 * d - j - i - 1] as i128)
                };

                dot += r[d - j - 1] as i128 * b;
            }

            *r2 += dot;
            *r2 /= decoded_q as i128;
        }
    }

    r2.into_vec().into_iter().map(|r2| r2 as i64).collect()
}

impl<G: Curve> Compressible for GroupElements<G>
where
    GroupElements<G>:
        TryFrom<SerializableGroupElements, Error = InvalidSerializedGroupElementsError>,
    <G::G1 as CurveGroupOps<G::Zp>>::Affine: Compressible<Compressed = SerializableG1Affine>,
    <G::G2 as CurveGroupOps<G::Zp>>::Affine: Compressible<Compressed = SerializableG2Affine>,
{
    type Compressed = SerializableGroupElements;

    type UncompressError = InvalidSerializedGroupElementsError;

    fn compress(&self) -> Self::Compressed {
        let mut g_list = Vec::new();
        let mut g_hat_list = Vec::new();
        for idx in 0..self.message_len {
            g_list.push(self.g_list[(idx * 2) + 1].compress());
            g_list.push(self.g_list[(idx * 2) + 2].compress());
            g_hat_list.push(self.g_hat_list[idx + 1].compress())
        }

        SerializableGroupElements { g_list, g_hat_list }
    }

    fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
        Self::try_from(compressed)
    }
}

/// Len of the "domain separator" fields used with the sha3 XoF PRNG
pub const HASH_DS_LEN_BYTES: usize = 8;

pub const LEGACY_HASH_DS_LEN_BYTES: usize = 256;

/// A unique id that is used to tie the hash functions to a specific CRS
#[derive(Debug, Clone, Copy)]
// This is an option for backward compatibility reasons
pub(crate) struct Sid(pub(crate) Option<u128>);

impl Sid {
    fn new(rng: &mut dyn RngCore) -> Self {
        Self(Some(rng.gen()))
    }

    pub(crate) fn to_le_bytes(self) -> SidBytes {
        self.0
            .map(|val| SidBytes(Some(val.to_le_bytes())))
            .unwrap_or_default()
    }
}

#[derive(Default)]
pub(crate) struct SidBytes(Option<[u8; 16]>);

impl SidBytes {
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0.as_ref().map(|val| val.as_slice()).unwrap_or(&[])
    }
}

// The verifier is meant to be executed on a large server with a high number of core. However, some
// arkworks operations do not scale well in that case, and we actually see decreased performance
// for pke_v2 with a higher thread count. This is supposed to be a temporary fix.
//
// See this issue for more information: https://github.com/arkworks-rs/algebra/issues/976

/// Number of threads used to run the verification.
///
/// This value has been determined empirically by running the `pke_v2_verify` benchmark on an aws
/// hpc7 96xlarge. Values between 30/50 seem to give good result but 32 is on the lower side (more
/// throughput), is a power of 2 and a divisor of 192 (number of CPU cores of the hpc7).
const VERIF_MAX_THREADS_COUNT: usize = 32;

/// Holds a ThreadPool and the number of verification tasks running on it, using the Arc
type VerificationPool = Arc<OnceLock<Option<ThreadPool>>>;

/// The list of pools used for verification
static VERIF_POOLS: OnceLock<Vec<VerificationPool>> = OnceLock::new();

/// Initialize the list of pools, based on the number of available CPU cores
fn get_or_init_pools() -> &'static Vec<VerificationPool> {
    VERIF_POOLS.get_or_init(|| {
        let total_cores = rayon::current_num_threads();

        // If the number of available cores is smaller than the pool size, default to one pool.
        let pools_count = total_cores.div_ceil(VERIF_MAX_THREADS_COUNT).max(1);

        (0..pools_count)
            .map(|_| Arc::new(OnceLock::new()))
            .collect()
    })
}

/// Run the target function in dedicated rayon threadpool with a limited number of threads.
///
/// When multiple calls of this function are made in parallel, each of them is executed in a
/// dedicated pool, if there is enough free cores on the CPU.
pub(crate) fn run_in_pool<OP, R>(f: OP) -> R
where
    OP: FnOnce() -> R + Send,
    R: Send,
{
    let pools = get_or_init_pools();

    // Select the least loaded pool
    let mut min_load = usize::MAX;
    let mut pool_index = 0;

    for (i, pool) in pools.iter().enumerate() {
        let load = Arc::strong_count(pool);

        if load < min_load {
            min_load = load;
            pool_index = i;

            if load == 0 {
                break;
            }
        }
    }
    let selected_pool = pools[pool_index].clone();

    if let Some(pool) = selected_pool
        .get_or_init(|| {
            ThreadPoolBuilder::new()
                .num_threads(VERIF_MAX_THREADS_COUNT)
                .build()
                .ok()
        })
        .as_ref()
    {
        pool.install(f)
    } else {
        // If the pool creation failed (ex wasm), we run it in the main threadpool
        // Since this is just an optimization, it is not worth panicking over
        f()
    }
}

#[cfg(feature = "experimental")]
pub mod binary;
#[cfg(feature = "experimental")]
pub mod index;
#[cfg(feature = "experimental")]
pub mod range;
#[cfg(feature = "experimental")]
pub mod rlwe;

pub mod pke;
pub mod pke_v2;

#[cfg(test)]
pub(crate) mod test {
    #![allow(non_snake_case)]
    use std::fmt::Display;
    use std::num::Wrapping;
    use std::ops::Sub;

    use ark_ec::{short_weierstrass, CurveConfig};
    use ark_ff::UniformRand;
    use bincode::ErrorKind;
    use rand::rngs::StdRng;
    use rand::Rng;
    use serde::{Deserialize, Serialize};

    use crate::curve_api::Compressible;
    use crate::proofs::decode_q;

    // One of our usecases uses 320 bits of additional metadata
    pub(crate) const METADATA_LEN: usize = (320 / u8::BITS) as usize;

    pub(crate) enum Compress {
        Yes,
        No,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(super) enum InputSizeVariation {
        Oversized,
        Undersized,
        Nominal,
    }

    pub(crate) fn serialize_then_deserialize<
        Params: Compressible + Serialize + for<'de> Deserialize<'de>,
    >(
        public_params: &Params,
        compress: Compress,
    ) -> bincode::Result<Params>
    where
        <Params as Compressible>::Compressed: Serialize + for<'de> Deserialize<'de>,
        <Params as Compressible>::UncompressError: Display,
    {
        match compress {
            Compress::Yes => Params::uncompress(bincode::deserialize(&bincode::serialize(
                &public_params.compress(),
            )?)?)
            .map_err(|e| Box::new(ErrorKind::Custom(format!("Failed to uncompress: {e}")))),
            Compress::No => bincode::deserialize(&bincode::serialize(&public_params)?),
        }
    }

    pub(super) fn polymul_rev(a: &[i64], b: &[i64]) -> Vec<i64> {
        assert_eq!(a.len(), b.len());
        let d = a.len();
        let mut c = vec![0i64; d];

        for i in 0..d {
            for j in 0..d {
                if i + j < d {
                    c[i + j] = c[i + j].wrapping_add(a[i].wrapping_mul(b[d - j - 1]));
                } else {
                    c[i + j - d] = c[i + j - d].wrapping_sub(a[i].wrapping_mul(b[d - j - 1]));
                }
            }
        }

        c
    }

    /// Wrapper that panics on overflow even in release mode
    pub(super) struct Strict<Num>(pub Num);

    impl Sub for Strict<u128> {
        type Output = Strict<u128>;

        fn sub(self, rhs: Self) -> Self::Output {
            Strict(self.0.checked_sub(rhs.0).unwrap())
        }
    }

    /// Parameters needed for a PKE zk proof test
    #[derive(Copy, Clone)]
    pub(crate) struct PkeTestParameters {
        pub(crate) d: usize,
        pub(crate) k: usize,
        pub(crate) B: u64,
        pub(crate) q: u64,
        pub(crate) t: u64,
        pub(crate) msbs_zero_padding_bit_count: u64,
    }

    /// An encrypted PKE ciphertext
    pub(crate) struct PkeTestCiphertext {
        pub(crate) c1: Vec<i64>,
        pub(crate) c2: Vec<i64>,
    }

    /// A randomly generated testcase of pke encryption
    #[derive(Clone)]
    pub(crate) struct PkeTestcase {
        pub(crate) a: Vec<i64>,
        pub(crate) e1: Vec<i64>,
        pub(crate) e2: Vec<i64>,
        pub(crate) r: Vec<i64>,
        pub(crate) m: Vec<i64>,
        pub(crate) b: Vec<i64>,
        pub(crate) metadata: [u8; METADATA_LEN],
        pub(crate) s: Vec<i64>,
    }

    impl PkeTestcase {
        pub(crate) fn gen(rng: &mut StdRng, params: PkeTestParameters) -> Self {
            let PkeTestParameters {
                d,
                k,
                B,
                q: _q,
                t,
                msbs_zero_padding_bit_count,
            } = params;

            let effective_cleartext_t = t >> msbs_zero_padding_bit_count;

            let a = (0..d).map(|_| rng.gen::<i64>()).collect::<Vec<_>>();

            let s = (0..d)
                .map(|_| (rng.gen::<u64>() % 2) as i64)
                .collect::<Vec<_>>();

            let e = (0..d)
                .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
                .collect::<Vec<_>>();
            let e1 = (0..d)
                .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
                .collect::<Vec<_>>();
            let e2 = (0..k)
                .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
                .collect::<Vec<_>>();

            let r = (0..d)
                .map(|_| (rng.gen::<u64>() % 2) as i64)
                .collect::<Vec<_>>();
            let m = (0..k)
                .map(|_| (rng.gen::<u64>() % effective_cleartext_t) as i64)
                .collect::<Vec<_>>();
            let b = polymul_rev(&a, &s)
                .into_iter()
                .zip(e.iter())
                .map(|(x, e)| x.wrapping_add(*e))
                .collect::<Vec<_>>();

            let mut metadata = [0u8; METADATA_LEN];
            metadata.fill_with(|| rng.gen::<u8>());

            Self {
                a,
                e1,
                e2,
                r,
                m,
                b,
                metadata,
                s,
            }
        }

        pub(crate) fn sk_encrypt_zero(
            &self,
            params: PkeTestParameters,
            rng: &mut StdRng,
        ) -> Vec<i64> {
            let PkeTestParameters {
                d,
                k: _,
                B,
                q: _,
                t: _,
                msbs_zero_padding_bit_count: _msbs_zero_padding_bit_count,
            } = params;

            let e = (rng.gen::<u64>() % (2 * B)) as i64 - B as i64;

            let mut a = (0..d).map(|_| rng.gen::<i64>()).collect::<Vec<_>>();

            let b = a
                .iter()
                .zip(&self.s)
                .map(|(ai, si)| Wrapping(ai * si))
                .sum::<Wrapping<i64>>()
                .0
                + e;

            a.push(b);
            a
        }

        /// Decrypt a ciphertext list
        pub(crate) fn decrypt(
            &self,
            ct: &PkeTestCiphertext,
            params: PkeTestParameters,
        ) -> Vec<i64> {
            let PkeTestParameters {
                d,
                k,
                B: _B,
                q,
                t,
                msbs_zero_padding_bit_count: _msbs_zero_padding_bit_count,
            } = params;

            // Check decryption
            let mut m_decrypted = vec![0i64; k];
            for (i, decrypted) in m_decrypted.iter_mut().enumerate() {
                let mut dot = 0i128;
                for j in 0..d {
                    let c = if i + j < d {
                        ct.c1[d - j - i - 1]
                    } else {
                        ct.c1[2 * d - j - i - 1].wrapping_neg()
                    };

                    dot += self.s[d - j - 1] as i128 * c as i128;
                }

                let decoded_q = decode_q(q) as i128;
                let val = ((ct.c2[i] as i128).wrapping_sub(dot)) * t as i128;
                let div = val.div_euclid(decoded_q);
                let rem = val.rem_euclid(decoded_q);
                let result = div as i64 + (rem > (decoded_q / 2)) as i64;
                let result = result.rem_euclid(params.t as i64);
                *decrypted = result;
            }

            m_decrypted
        }

        /// Encrypt using compact pke, the encryption is validated by doing a decryption
        pub(crate) fn encrypt(&self, params: PkeTestParameters) -> PkeTestCiphertext {
            let ct = self.encrypt_unchecked(params);

            // Check decryption
            let m_decrypted = self.decrypt(&ct, params);

            assert_eq!(self.m, m_decrypted);

            ct
        }

        /// Encrypt using compact pke, without checking that the decryption is correct
        pub(crate) fn encrypt_unchecked(&self, params: PkeTestParameters) -> PkeTestCiphertext {
            let PkeTestParameters {
                d,
                k,
                B: _B,
                q,
                t,
                msbs_zero_padding_bit_count: _msbs_zero_padding_bit_count,
            } = params;

            let delta = {
                let q = decode_q(q) as i128;
                // delta takes the encoding with the padding bit
                (q / t as i128) as u64
            };

            let c1 = polymul_rev(&self.a, &self.r)
                .into_iter()
                .zip(self.e1.iter())
                .map(|(x, e1)| x.wrapping_add(*e1))
                .collect::<Vec<_>>();

            let mut c2 = vec![0i64; k];

            for (i, c2) in c2.iter_mut().enumerate() {
                let mut dot = 0i64;
                for j in 0..d {
                    let b = if i + j < d {
                        self.b[d - j - i - 1]
                    } else {
                        self.b[2 * d - j - i - 1].wrapping_neg()
                    };

                    dot = dot.wrapping_add(self.r[d - j - 1].wrapping_mul(b));
                }

                *c2 = dot
                    .wrapping_add(self.e2[i])
                    .wrapping_add((delta * self.m[i] as u64) as i64);
            }

            PkeTestCiphertext { c1, c2 }
        }
    }

    /// Expected result of the verification for a test
    #[derive(Copy, Clone, Debug, PartialEq)]
    pub(super) enum VerificationResult {
        Accept,
        Reject,
    }

    /// Return a point with coordinates (x, y) that is randomly chosen and not on the curve
    pub(super) fn point_not_on_curve<Config: short_weierstrass::SWCurveConfig>(
        rng: &mut StdRng,
    ) -> short_weierstrass::Affine<Config> {
        loop {
            let fake_x = <Config as CurveConfig>::BaseField::rand(rng);
            let fake_y = <Config as CurveConfig>::BaseField::rand(rng);

            let point = short_weierstrass::Affine::new_unchecked(fake_x, fake_y);

            if !point.is_on_curve() {
                return point;
            }
        }
    }

    /// Return a random point on the curve
    pub(super) fn point_on_curve<Config: short_weierstrass::SWCurveConfig>(
        rng: &mut StdRng,
    ) -> short_weierstrass::Affine<Config> {
        loop {
            let x = <Config as CurveConfig>::BaseField::rand(rng);
            let is_positive = bool::rand(rng);
            if let Some(point) =
                short_weierstrass::Affine::get_point_from_x_unchecked(x, is_positive)
            {
                return point;
            }
        }
    }

    /// Return a random point that is on the curve but not in the correct subgroup
    pub(super) fn point_on_curve_wrong_subgroup<Config: short_weierstrass::SWCurveConfig>(
        rng: &mut StdRng,
    ) -> short_weierstrass::Affine<Config> {
        loop {
            let point = point_on_curve(rng);
            if !Config::is_in_correct_subgroup_assuming_on_curve(&point) {
                return point;
            }
        }
    }
}
