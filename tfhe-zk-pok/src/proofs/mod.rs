use crate::backward_compatibility::GroupElementsVersions;
use crate::curve_api::{Compressible, Curve, CurveGroupOps, FieldOps, PairingGroupOps};
use crate::serialization::{
    InvalidSerializedGroupElementsError, SerializableG1Affine, SerializableG2Affine,
    SerializableGroupElements,
};
use core::ops::{Index, IndexMut};
use rand::{Rng, RngCore};
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

    #[derive(Copy, Clone)]
    pub(super) struct PkeTestParameters {
        pub(super) d: usize,
        pub(super) k: usize,
        pub(super) B: u64,
        pub(super) q: u64,
        pub(super) t: u64,
        pub(super) msbs_zero_padding_bit_count: u64,
    }

    pub(super) struct PkeTestProofInputs {
        pub(super) a: Vec<i64>,
        pub(super) e1: Vec<i64>,
        pub(super) e2: Vec<i64>,
        pub(super) r: Vec<i64>,
        pub(super) m: Vec<i64>,
        pub(super) b: Vec<i64>,
        pub(super) c1: Vec<i64>,
        pub(super) c2: Vec<i64>,
        pub(super) metadata: [u8; METADATA_LEN],
    }

    impl PkeTestProofInputs {
        pub(super) fn gen(rng: &mut StdRng, params: PkeTestParameters) -> Self {
            let PkeTestParameters {
                d,
                k,
                B,
                q,
                t,
                msbs_zero_padding_bit_count,
            } = params;

            let effective_cleartext_t = t >> msbs_zero_padding_bit_count;

            let delta = {
                let q = if q == 0 { 1i128 << 64 } else { q as i128 };
                // delta takes the encoding with the padding bit
                (q / t as i128) as u64
            };

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

            // Encrypt using compact pke
            let c1 = polymul_rev(&a, &r)
                .into_iter()
                .zip(e1.iter())
                .map(|(x, e1)| x.wrapping_add(*e1))
                .collect::<Vec<_>>();

            let mut c2 = vec![0i64; k];

            for i in 0..k {
                let mut dot = 0i64;
                for j in 0..d {
                    let b = if i + j < d {
                        b[d - j - i - 1]
                    } else {
                        b[2 * d - j - i - 1].wrapping_neg()
                    };

                    dot = dot.wrapping_add(r[d - j - 1].wrapping_mul(b));
                }

                c2[i] = dot
                    .wrapping_add(e2[i])
                    .wrapping_add((delta * m[i] as u64) as i64);
            }

            let mut metadata = [0u8; METADATA_LEN];
            metadata.fill_with(|| rng.gen::<u8>());

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

                    dot += s[d - j - 1] as i128 * c as i128;
                }

                let q = if q == 0 { 1i128 << 64 } else { q as i128 };
                let val = ((c2[i] as i128).wrapping_sub(dot)) * t as i128;
                let div = val.div_euclid(q);
                let rem = val.rem_euclid(q);
                let result = div as i64 + (rem > (q / 2)) as i64;
                let result = result.rem_euclid(effective_cleartext_t as i64);
                m_roundtrip[i] = result;
            }

            assert_eq!(m, m_roundtrip);

            Self {
                a,
                e1,
                e2,
                r,
                m,
                b,
                c1,
                c2,
                metadata,
            }
        }
    }
}
