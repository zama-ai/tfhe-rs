use crate::backward_compatibility::GroupElementsVersions;
use crate::curve_api::{Compressible, Curve, CurveGroupOps, FieldOps, PairingGroupOps};
use crate::serialization::{
    InvalidSerializedGroupElementsError, SerializableG1Affine, SerializableG2Affine,
    SerializableGroupElements,
};
use core::ops::{Index, IndexMut};
use rand::{Rng, RngCore};
use tfhe_versionable::{Unversionize, Versionize, VersionizeOwned};

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
pub(crate) struct OneBased<T: ?Sized>(T);

// TODO: these impl could be removed by adding support for `repr(transparent)` in tfhe-versionable
impl<T: Versionize> Versionize for OneBased<T> {
    type Versioned<'vers>
        = T::Versioned<'vers>
    where
        T: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.0.versionize()
    }
}

impl<T: VersionizeOwned> VersionizeOwned for OneBased<T> {
    type VersionedOwned = T::VersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        self.0.versionize_owned()
    }
}

impl<T: Unversionize> Unversionize for OneBased<T> {
    fn unversionize(
        versioned: Self::VersionedOwned,
    ) -> Result<Self, tfhe_versionable::UnversionizeError> {
        Ok(Self(T::unversionize(versioned)?))
    }
}

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
