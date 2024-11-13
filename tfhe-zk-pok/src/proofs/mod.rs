use crate::backward_compatibility::GroupElementsVersions;

use crate::curve_api::{Compressible, Curve, CurveGroupOps, FieldOps, PairingGroupOps};
use crate::serialization::{
    InvalidSerializedGroupElementsError, SerializableG1Affine, SerializableG2Affine,
    SerializableGroupElements,
};
use core::ops::{Index, IndexMut};
use rand::{Rng, RngCore};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::fmt::Display;
use tfhe_versionable::Versionize;

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[repr(transparent)]
pub(crate) struct OneBased<T: ?Sized>(T);

/// The proving scheme is available in 2 versions, one that puts more load on the prover and one
/// that puts more load on the verifier
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ComputeLoad {
    Proof,
    Verify,
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
    pub fn is_valid(&self) -> bool {
        let (g_list_valid, g_hat_list_valid) = rayon::join(
            || self.g_list.0.par_iter().all(G::G1::validate_affine),
            || self.g_hat_list.0.par_iter().all(G::G2::validate_affine),
        );

        g_list_valid && g_hat_list_valid
    }
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

pub const HASH_METADATA_LEN_BYTES: usize = 256;

pub mod binary;
pub mod index;
pub mod pke;
pub mod pke_v2;
pub mod range;
pub mod rlwe;

#[cfg(test)]
mod test {
    #![allow(non_snake_case)]
    use std::fmt::Display;

    use ark_ec::{short_weierstrass, CurveConfig};
    use ark_ff::UniformRand;
    use bincode::ErrorKind;
    use rand::rngs::StdRng;
    use rand::Rng;
    use serde::{Deserialize, Serialize};

    use crate::curve_api::Compressible;

    // One of our usecases uses 320 bits of additional metadata
    pub(super) const METADATA_LEN: usize = (320 / u8::BITS) as usize;

    pub(super) enum Compress {
        Yes,
        No,
    }

    pub(super) fn serialize_then_deserialize<
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
            .map_err(|e| Box::new(ErrorKind::Custom(format!("Failed to uncompress: {}", e)))),
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

    /// Parameters needed for a PKE zk proof test
    #[derive(Copy, Clone)]
    pub(super) struct PkeTestParameters {
        pub(super) d: usize,
        pub(super) k: usize,
        pub(super) B: u64,
        pub(super) q: u64,
        pub(super) t: u64,
        pub(super) msbs_zero_padding_bit_count: u64,
    }

    /// An encrypted PKE ciphertext
    pub struct PkeTestCiphertext {
        pub(super) c1: Vec<i64>,
        pub(super) c2: Vec<i64>,
    }

    /// A randomly generated testcase of pke encryption
    pub(super) struct PkeTestcase {
        pub(super) a: Vec<i64>,
        pub(super) e1: Vec<i64>,
        pub(super) e2: Vec<i64>,
        pub(super) r: Vec<i64>,
        pub(super) m: Vec<i64>,
        pub(super) b: Vec<i64>,
        pub(super) metadata: [u8; METADATA_LEN],
        s: Vec<i64>,
    }

    impl PkeTestcase {
        pub(super) fn gen(rng: &mut StdRng, params: PkeTestParameters) -> Self {
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

        /// Encrypt using compact pke
        pub(super) fn encrypt(&self, params: PkeTestParameters) -> PkeTestCiphertext {
            let PkeTestParameters {
                d,
                k,
                B: _B,
                q,
                t,
                msbs_zero_padding_bit_count: _msbs_zero_padding_bit_count,
            } = params;

            let delta = {
                let q = if q == 0 { 1i128 << 64 } else { q as i128 };
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

            // Check decryption
            let mut m_roundtrip = vec![0i64; k];
            for i in 0..k {
                let mut dot = 0i128;
                for j in 0..d {
                    let c = if i + j < d {
                        c1[d - j - i - 1]
                    } else {
                        c1[2 * d - j - i - 1].wrapping_neg()
                    };

                    dot += self.s[d - j - 1] as i128 * c as i128;
                }

                let q = if q == 0 { 1i128 << 64 } else { q as i128 };
                let val = ((c2[i] as i128).wrapping_sub(dot)) * t as i128;
                let div = val.div_euclid(q);
                let rem = val.rem_euclid(q);
                let result = div as i64 + (rem > (q / 2)) as i64;
                let result = result.rem_euclid(params.t as i64);
                m_roundtrip[i] = result;
            }

            assert_eq!(self.m, m_roundtrip);

            PkeTestCiphertext { c1, c2 }
        }
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
