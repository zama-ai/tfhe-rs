use crate::curve_api::{Curve, CurveGroupOps, FieldOps, PairingGroupOps};

use core::ops::{Index, IndexMut};
use rand::RngCore;

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
struct OneBased<T: ?Sized>(T);

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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct GroupElements<G: Curve> {
    g_list: OneBased<Vec<G::G1>>,
    g_hat_list: OneBased<Vec<G::G2>>,
    message_len: usize,
}

impl<G: Curve> GroupElements<G> {
    pub fn new(message_len: usize, alpha: G::Zp) -> Self {
        let mut g_list = Vec::new();
        let mut g_hat_list = Vec::new();

        let mut g_cur = G::G1::GENERATOR.mul_scalar(alpha);

        for i in 0..2 * message_len {
            if i == message_len {
                g_list.push(G::G1::ZERO);
            } else {
                g_list.push(g_cur);
            }
            g_cur = g_cur.mul_scalar(alpha);
        }

        let mut g_hat_cur = G::G2::GENERATOR.mul_scalar(alpha);
        for _ in 0..message_len {
            g_hat_list.push(g_hat_cur);
            g_hat_cur = (g_hat_cur).mul_scalar(alpha);
        }

        Self {
            g_list: OneBased::new(g_list),
            g_hat_list: OneBased::new(g_hat_list),
            message_len,
        }
    }

    pub fn from_vec(g_list: Vec<G::G1>, g_hat_list: Vec<G::G2>) -> Self {
        let message_len = g_hat_list.len();
        Self {
            g_list: OneBased::new(g_list),
            g_hat_list: OneBased::new(g_hat_list),
            message_len,
        }
    }
}

pub mod binary;
pub mod index;
pub mod pke;
pub mod range;
pub mod rlwe;
