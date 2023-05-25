use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;
use crate::shortint::PBSOrderMarker;

use super::shift::BarrelShifterOperation;

impl ServerKey {
    //======================================================================
    //                Rotate Right
    //======================================================================

    pub fn unchecked_rotate_right_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &RadixCiphertext<PBSOrder>,
        n: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        let mut result = ct.clone();
        self.unchecked_rotate_right_assign_parallelized(&mut result, n);
        result
    }

    pub fn unchecked_rotate_right_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        n: &RadixCiphertext<PBSOrder>,
    ) {
        self.barrel_shifter(ct, n, BarrelShifterOperation::RightRotate);
    }

    pub fn smart_rotate_right_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        n: &mut RadixCiphertext<PBSOrder>,
    ) {
        rayon::join(
            || {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(ct);
                }
            },
            || {
                if !n.block_carries_are_empty() {
                    self.full_propagate_parallelized(n);
                }
            },
        );
        self.unchecked_rotate_right_assign_parallelized(ct, n);
    }

    pub fn smart_rotate_right_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        rotate: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        rayon::join(
            || {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(ct);
                }
            },
            || {
                if !rotate.block_carries_are_empty() {
                    self.full_propagate_parallelized(rotate);
                }
            },
        );
        self.unchecked_rotate_right_parallelized(ct, rotate)
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the right by a specified amount,
    /// `n`, wrapping the truncated bits to the beginning of the resulting integer.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let ct = cks.encrypt(msg as u64);
    /// let n_ct = cks.encrypt(n as u64);
    ///
    /// let ct_res = sks.rotate_right_parallelized(&ct, &n_ct);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg.rotate_right(n as u32) as u64, dec);
    /// ```
    pub fn rotate_right_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        rotate: &RadixCiphertext<PBSOrder>,
    ) {
        let mut tmp_rhs: RadixCiphertext<PBSOrder>;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            rotate.block_carries_are_empty(),
        ) {
            (true, true) => (ct, rotate),
            (true, false) => {
                tmp_rhs = rotate.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ct);
                (ct, rotate)
            }
            (false, false) => {
                tmp_rhs = rotate.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ct),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ct, &tmp_rhs)
            }
        };

        self.unchecked_rotate_right_assign_parallelized(lhs, rhs)
    }

    pub fn rotate_right_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &RadixCiphertext<PBSOrder>,
        rotate: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        let mut ct_res = ct.clone();
        self.rotate_right_assign_parallelized(&mut ct_res, rotate);
        ct_res
    }

    //======================================================================
    //                Rotate Left
    //======================================================================

    pub fn unchecked_rotate_left_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct_left: &RadixCiphertext<PBSOrder>,
        n: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        let mut result = ct_left.clone();
        self.unchecked_rotate_left_assign_parallelized(&mut result, n);
        result
    }

    pub fn unchecked_rotate_left_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        n: &RadixCiphertext<PBSOrder>,
    ) {
        self.barrel_shifter(ct, n, BarrelShifterOperation::LeftRotate);
    }

    pub fn smart_rotate_left_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        n: &mut RadixCiphertext<PBSOrder>,
    ) {
        rayon::join(
            || {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(ct);
                }
            },
            || {
                if !n.block_carries_are_empty() {
                    self.full_propagate_parallelized(n);
                }
            },
        );
        self.unchecked_rotate_left_assign_parallelized(ct, n);
    }

    pub fn smart_rotate_left_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        rotate: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        rayon::join(
            || {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(ct);
                }
            },
            || {
                if !rotate.block_carries_are_empty() {
                    self.full_propagate_parallelized(rotate);
                }
            },
        );
        self.unchecked_rotate_left_parallelized(ct, rotate)
    }

    pub fn rotate_left_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        rotate: &RadixCiphertext<PBSOrder>,
    ) {
        let mut tmp_rhs: RadixCiphertext<PBSOrder>;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            rotate.block_carries_are_empty(),
        ) {
            (true, true) => (ct, rotate),
            (true, false) => {
                tmp_rhs = rotate.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ct);
                (ct, rotate)
            }
            (false, false) => {
                tmp_rhs = rotate.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ct),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ct, &tmp_rhs)
            }
        };

        self.unchecked_rotate_left_assign_parallelized(lhs, rhs)
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the left by a specified amount,
    /// `n`, wrapping the truncated bits to the end of the resulting integer.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let ct = cks.encrypt(msg as u64);
    /// let n_ct = cks.encrypt(n as u64);
    ///
    /// let ct_res = sks.rotate_left_parallelized(&ct, &n_ct);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg.rotate_left(n as u32) as u64, dec);
    /// ```
    pub fn rotate_left_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &RadixCiphertext<PBSOrder>,
        rotate: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        let mut ct_res = ct.clone();
        self.rotate_left_assign_parallelized(&mut ct_res, rotate);
        ct_res
    }
}
