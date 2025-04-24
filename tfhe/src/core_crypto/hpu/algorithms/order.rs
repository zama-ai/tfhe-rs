//!
//! Define polynomial ordering
//! And associated function that enable to translate from one ordering to the others
//!
//! Ordering is useful in HW to expose common structure in the computation.
//! Both Ntt architecture used reverse order as input
//! However, Wmm use an intermediate Network required by the BSK shuffling.

use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, UnsignedInteger};

#[derive(Debug, Clone)]
pub struct RadixBasis {
    radix_lg: DecompositionBaseLog,
    digits_nb: DecompositionLevelCount,
}

impl RadixBasis {
    pub fn new(radix: usize, digits_nb: usize) -> Self {
        let radix_lg = radix.ilog2() as usize;
        Self {
            radix_lg: DecompositionBaseLog(radix_lg),
            digits_nb: DecompositionLevelCount(digits_nb),
        }
    }

    pub fn radix_lg(&self) -> DecompositionBaseLog {
        self.radix_lg
    }
    pub fn digits_nb(&self) -> DecompositionLevelCount {
        self.digits_nb
    }

    /// Convert an index expressed in Natural Order into 'pdrev' Order
    /// Generalized pseudo reverse is:
    /// * Nat_order from 0..rank
    /// * Rev_order from rank..digits
    pub fn idx_pdrev(&self, digits: usize, rank: usize, nat_val: usize) -> usize {
        let mask = (1 << ((digits - rank) * self.radix_lg.0)) - 1;
        let to_be_reversed = (nat_val >> (rank * self.radix_lg.0)) & mask;
        let reversed = Self::new(1 << self.radix_lg.0, digits - rank).idx_rev(to_be_reversed);

        let to_be_zeroed = nat_val & (mask << (rank * self.radix_lg.0));
        let mut result = nat_val & !to_be_zeroed;
        result |= reversed << (rank * self.radix_lg.0);

        result
    }

    /// Convert an index expressed in 'pdrev' Order into Natural Order
    #[inline]
    pub fn idx_pdrev_inv(&self, digits: usize, rank: usize, pdrev_val: usize) -> usize {
        self.idx_pdrev(digits, rank, pdrev_val)
    }

    /// Convert an index expressed in Natural Order into `reverse` Order
    pub fn idx_rev(&self, mut nat_val: usize) -> usize {
        let mask = (1 << self.radix_lg.0) - 1;
        let mut result = 0;
        for i in (0..self.digits_nb.0).rev() {
            result |= (nat_val & mask) << (i * self.radix_lg.0);
            nat_val >>= self.radix_lg.0;
        }

        result
    }

    /// Convert an index expressed in 'reverse' Order into Natural Order
    #[inline]
    pub fn idx_rev_inv(&mut self, pdrev_val: usize) -> usize {
        self.idx_rev(pdrev_val)
    }
}

/// Utility function to shuffle a polynomial in a reverse order
pub fn poly_order<Scalar, F>(dst: &mut [Scalar], src: &[Scalar], rb_conv: &RadixBasis, f: F)
where
    Scalar: UnsignedInteger,
    F: Fn(Scalar) -> Scalar,
{
    assert_eq!(src.len(), dst.len(), "Poly src/ dst length mismtach");
    assert_eq!(
        src.len(),
        ((1 << rb_conv.radix_lg().0) as usize).pow(rb_conv.digits_nb().0 as u32),
        "Poly length mismtach with RadixBasis configuration"
    );

    for (idx, v) in dst.iter_mut().enumerate() {
        let src_idx = rb_conv.idx_rev(idx);
        *v = f(src[src_idx]);
    }
}

#[derive(Debug, Clone)]
pub struct PcgNetwork {
    stage_nb: usize,
    rb_conv: RadixBasis,
}

impl PcgNetwork {
    /// Create network instance from NttParameters
    pub fn new(radix: usize, stg_nb: usize) -> Self {
        Self {
            stage_nb: stg_nb,
            rb_conv: RadixBasis::new(radix, stg_nb),
        }
    }

    /// For a given position idx (in 0..N-1), at processing step delta_idx,
    /// find the corresponding position idx (consider the input of the node)
    pub fn get_pos_id(&mut self, delta_idx: usize, pos_idx: usize) -> usize {
        let node_idx = pos_idx / (1 << self.rb_conv.radix_lg().0);
        let rmn_idx = pos_idx % (1 << self.rb_conv.radix_lg().0);
        let pdrev_idx = self
            .rb_conv
            .idx_pdrev(self.stage_nb - 1, delta_idx, node_idx);
        pdrev_idx * (1 << self.rb_conv.radix_lg().0) + rmn_idx
    }
}
