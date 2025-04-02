//!
//! Define polynomial ordering
//! And associated function that enable to translate from one ordering to the others
//!
//! Ordering is useful in HW to expose common structure in the computation.
//!
//! NB: Retrieved from Zaxl-sw implementation. A lot of cleanup required
//! -> With the current implementation only the Reverse order is used. Maybe, we can remove the
//! other one

// Currently only Pcg is used, but we kept RRot in the codebase.
// Cleanup required later on
#![allow(dead_code)]

use serde::Serialize;

use crate::core_crypto::prelude::UnsignedInteger;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PolyOrder {
    /// Natural order
    Natural,

    /// Reverse order
    /// poly[ {d_n, d_{n-1}, ..., d_0} ] -> poly[ { d_0, ..., d_{n-1}, d_n } ]
    ///      msd                   lsd           msd                    lsd
    Reverse,

    /// RightRotate order
    /// TODO describe this order
    RightRotate,

    /// PseudoReverse order
    /// Reverse LSB order and keep MSB as is
    PseudoReverse(usize),
}

/// Easily translate from one order to the other with generic radix basis
///
/// NB: Use dedicated structure instead of function to hide the requirement of intermediate buffer
/// for radix decomposition
#[derive(Debug, Clone)]
pub struct RadixBasis {
    radix_lg: usize,
    digits_nb: usize,
    conv_bfr: Vec<usize>,
}

impl RadixBasis {
    pub fn new(radix: usize, digits_nb: usize) -> Self {
        let radix_lg = radix.ilog(2) as usize;
        Self {
            radix_lg,
            digits_nb,
            conv_bfr: vec![0; digits_nb],
        }
    }

    pub fn radix_lg(&self) -> usize {
        self.radix_lg
    }
    pub fn digits_nb(&self) -> usize {
        self.digits_nb
    }

    /// Compute a value in binary basis from a vector of digit expressed in Radix basis
    /// digits[0] -> Least significant digit
    fn from_radix_basis(&self) -> usize {
        self.conv_bfr
            .iter()
            .enumerate()
            .map(|(i, d)| d << (i * self.radix_lg))
            .fold(0, |acc, v| acc + v)
    }

    /// Decompose a value expressed in binary basis in slice of radix digit
    /// digits[0] -> Least significant digit
    fn into_radix_basis(&mut self, val: usize) {
        let mask = (1 << self.radix_lg) - 1;

        for (i, d) in self.conv_bfr.iter_mut().enumerate() {
            *d = (val >> (i * self.radix_lg)) & mask;
        }
    }

    /// Convert an index expressed in Natural Order into 'rrot' Order
    /// NB: Rotation direction is expressed in vector direction (i.e counter intuitive for digit
    /// based shifting)
    pub fn idx_rrot(&mut self, nat_val: usize) -> usize {
        // Pseudo reverse is like left rotation of one digit-shift
        self.into_radix_basis(nat_val);
        self.conv_bfr.rotate_left(1);
        self.from_radix_basis()
    }

    /// Convert an index expressed in 'rrot' Order into Natural Order
    /// NB: Rotation direction is expressed in vector direction (i.e counter intuitive for digit
    /// based shifting)
    pub fn idx_rrot_inv(&mut self, pdrev_val: usize) -> usize {
        // Pseudo reverse is like left rotation of one digit-shift
        self.into_radix_basis(pdrev_val);
        self.conv_bfr.rotate_right(1);
        self.from_radix_basis()
    }

    /// Convert an index expressed in Natural Order into 'pdrev' Order
    /// Generalized pseudo reverse is:
    /// * Nat_order from 0..rank
    /// * Rev_order from rank..digits
    pub fn idx_pdrev(&mut self, digits: usize, rank: usize, nat_val: usize) -> usize {
        self.into_radix_basis(nat_val);
        self.conv_bfr[rank..digits].reverse();
        self.from_radix_basis()
    }

    /// Convert an index expressed in 'pdrev' Order into Natural Order
    #[inline]
    pub fn idx_pdrev_inv(&mut self, digits: usize, rank: usize, pdrev_val: usize) -> usize {
        self.idx_pdrev(digits, rank, pdrev_val)
    }

    pub fn idx_rev(&mut self, nat_val: usize) -> usize {
        self.into_radix_basis(nat_val);
        self.conv_bfr.reverse();
        self.from_radix_basis()
    }

    #[inline]
    pub fn idx_rev_inv(&mut self, pdrev_val: usize) -> usize {
        self.idx_rev(pdrev_val)
    }

    // TODO Must be moved directly in Network definition or merged with get_bu_idx
    /// Convert an bu output index in next stage input index for pcg network
    pub fn ntw_pcg_nxt(&mut self, cur_stg: usize, idx: usize) -> usize {
        // Transfer function from Natural index to Bu id
        let pdrev_idx = self.idx_pdrev(self.conv_bfr.len(), cur_stg + 1, idx);
        self.into_radix_basis(pdrev_idx);
        self.conv_bfr.rotate_right(1);
        // Transfer function from BU id to iteration index
        // NB: +2 here -> Only apply reverse on BU id not BU id + input index
        self.conv_bfr[cur_stg + 2..].reverse();
        self.from_radix_basis()
    }

    // TODO Must be moved directly in Network definition or merged with get_bu_idx
    /// Convert an bu output index in next stage input index for rrot network
    /// NB: Rotation direction is expressed in vector direction (i.e counter intuitive for digit
    /// based shifting)
    pub fn ntw_rrot_nxt(&mut self, idx: usize) -> usize {
        // Next stage of rrot is like left rotation of one digit-shift
        self.into_radix_basis(idx);
        self.conv_bfr.rotate_right(1);
        self.from_radix_basis()
    }
}

/// Utility function to get src idx for a given order
pub fn idx_in_order(idx: usize, into: PolyOrder, rb_conv: &mut RadixBasis) -> usize {
    match into {
        PolyOrder::Natural => idx,
        PolyOrder::Reverse => rb_conv.idx_rev(idx),
        PolyOrder::RightRotate => rb_conv.idx_rrot(idx),
        PolyOrder::PseudoReverse(rank) => rb_conv.idx_pdrev(rb_conv.digits_nb(), rank, idx),
    }
}

/// Utility function to shuffle a polynomial in a given order
pub fn poly_order<Scalar, F>(
    dst: &mut [Scalar],
    src: &[Scalar],
    into: PolyOrder,
    rb_conv: &mut RadixBasis,
    f: F,
) where
    Scalar: UnsignedInteger,
    F: Fn(Scalar) -> Scalar,
{
    assert_eq!(src.len(), dst.len(), "Poly src/ dst length mismtach");
    assert_eq!(
        src.len(),
        ((1 << rb_conv.radix_lg()) as usize).pow(rb_conv.digits_nb() as u32),
        "Poly length mismtach with RadixBasis configuration"
    );

    for (idx, v) in dst.iter_mut().enumerate() {
        let src_idx = idx_in_order(idx, into, rb_conv);
        *v = f(src[src_idx]);
    }
}

/// Kind of shuffling network used between stages
#[derive(Debug, Clone, Copy, Serialize)]
pub enum NetworkKind {
    /// Right Rotation
    RRot,
    /// Pcg -> Pseudo Reverse order
    Pcg,
}

#[derive(Debug, Clone)]
pub struct Network {
    kind: NetworkKind,
    stg_nb: usize,
    rb_conv: RadixBasis,
}

impl Network {
    /// Create network instance from NttParameters
    pub fn new(kind: NetworkKind, radix: usize, stg_nb: usize) -> Self {
        Self {
            kind,
            stg_nb,
            rb_conv: RadixBasis::new(radix, stg_nb),
        }
    }

    /// get ntw input idx from given poly_order and idx
    pub fn in_idx_from(&mut self, ord_orig: PolyOrder, idx: usize) -> usize {
        match ord_orig {
            PolyOrder::Natural => match self.kind {
                NetworkKind::RRot => self.rb_conv.idx_rrot(idx),
                NetworkKind::Pcg => self.rb_conv.idx_rev(idx),
            },
            PolyOrder::Reverse => match self.kind {
                NetworkKind::RRot => {
                    let idx_rrot = self.rb_conv.idx_rrot(idx);
                    let idx_rev = self.rb_conv.idx_rev_inv(idx_rrot);
                    idx_rev
                }
                NetworkKind::Pcg => idx,
            },
            _ => panic!("PolyOrder not supported as input"),
        }
    }

    /// get ntw output idx toward given poly_order and idx
    pub fn out_idx_to(&mut self, ord_trgt: PolyOrder, idx: usize) -> usize {
        // Output of the last stages are in reverse order
        match ord_trgt {
            PolyOrder::Natural => self.rb_conv.idx_rev_inv(idx),
            PolyOrder::Reverse => idx,
            _ => panic!("PolyOrder not supported as output"),
        }
    }

    /// Convert bu output idx `out_idx` into next stage input idx
    pub fn next_stg_idx(&mut self, cur_stg: usize, out_idx: usize) -> usize {
        match self.kind {
            NetworkKind::RRot => self.rb_conv.ntw_rrot_nxt(out_idx),
            NetworkKind::Pcg => self.rb_conv.ntw_pcg_nxt(cur_stg, out_idx),
        }
    }

    /// For a given position idx (in 0..N-1), at processing step delta_idx,
    /// find the corresponding position idx (consider the input of the node)
    pub fn get_pos_id(&mut self, delta_idx: usize, pos_idx: usize) -> usize {
        match self.kind {
            NetworkKind::Pcg => {
                let node_idx = pos_idx / (1 << self.rb_conv.radix_lg());
                let rmn_idx = pos_idx % (1 << self.rb_conv.radix_lg());
                let pdrev_idx = self.rb_conv.idx_pdrev(self.stg_nb - 1, delta_idx, node_idx);
                pdrev_idx * (1 << self.rb_conv.radix_lg()) + rmn_idx
            }
            _ => unimplemented!("get_pos_id not implemented for {:?}", self.kind),
        }
    }

    /// For a given position idx (in 0..N-1), at processing step delta_idx,
    /// find the corresponding node idx.
    pub fn get_node_id(&mut self, delta_idx: usize, node_idx: usize) -> usize {
        match self.kind {
            NetworkKind::Pcg => self.rb_conv.idx_pdrev(self.stg_nb - 1, delta_idx, node_idx),
            NetworkKind::RRot => node_idx,
        }
    }
}
