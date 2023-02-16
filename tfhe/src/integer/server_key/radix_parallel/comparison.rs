use super::ServerKey;

use crate::integer::server_key::comparator::Comparator;
use crate::integer::RadixCiphertext;

impl ServerKey {
    pub fn unchecked_eq_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).unchecked_eq_parallelized(lhs, rhs)
    }

    pub fn unchecked_gt_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).unchecked_gt_parallelized(lhs, rhs)
    }

    pub fn unchecked_ge_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).unchecked_ge_parallelized(lhs, rhs)
    }

    pub fn unchecked_lt_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).unchecked_lt_parallelized(lhs, rhs)
    }

    pub fn unchecked_le_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).unchecked_le_parallelized(lhs, rhs)
    }

    pub fn unchecked_max_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).unchecked_max_parallelized(lhs, rhs)
    }

    pub fn unchecked_min_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).unchecked_min_parallelized(lhs, rhs)
    }

    pub fn smart_eq_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).smart_eq_parallelized(lhs, rhs)
    }

    pub fn smart_gt_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).smart_gt_parallelized(lhs, rhs)
    }

    pub fn smart_ge_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).smart_ge_parallelized(lhs, rhs)
    }

    pub fn smart_lt_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).smart_lt_parallelized(lhs, rhs)
    }

    pub fn smart_le_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).smart_le_parallelized(lhs, rhs)
    }

    pub fn smart_max_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).smart_max_parallelized(lhs, rhs)
    }

    pub fn smart_min_parallelized(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).smart_min_parallelized(lhs, rhs)
    }
}
