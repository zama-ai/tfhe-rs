use super::ServerKey;

use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::server_key::comparator::Comparator;
use crate::shortint::PBSOrderMarker;

impl ServerKey {
    pub fn unchecked_eq_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_eq_parallelized(lhs, rhs)
    }

    pub fn unchecked_gt_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_gt_parallelized(lhs, rhs)
    }

    pub fn unchecked_ge_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_ge_parallelized(lhs, rhs)
    }

    pub fn unchecked_lt_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_lt_parallelized(lhs, rhs)
    }

    pub fn unchecked_le_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_le_parallelized(lhs, rhs)
    }

    pub fn unchecked_max_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_max_parallelized(lhs, rhs)
    }

    pub fn unchecked_min_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_min_parallelized(lhs, rhs)
    }

    pub fn smart_eq_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_eq_parallelized(lhs, rhs)
    }

    pub fn smart_gt_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_gt_parallelized(lhs, rhs)
    }

    pub fn smart_ge_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_ge_parallelized(lhs, rhs)
    }

    pub fn smart_lt_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_lt_parallelized(lhs, rhs)
    }

    pub fn smart_le_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_le_parallelized(lhs, rhs)
    }

    pub fn smart_max_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_max_parallelized(lhs, rhs)
    }

    pub fn smart_min_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_min_parallelized(lhs, rhs)
    }
}
