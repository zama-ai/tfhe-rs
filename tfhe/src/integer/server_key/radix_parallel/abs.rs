use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::ServerKey;

impl ServerKey {
    pub fn unchecked_abs_parallelized<T>(&self, ct: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if T::IS_SIGNED {
            // This 'bit-hack' is slightly faster than doing an if_then_else
            // http://graphics.stanford.edu/~seander/bithacks.html#IntegerAbs
            let num_bits_in_ciphertext =
                self.key.message_modulus.0.ilog2() * ct.blocks().len() as u32;
            let mask = self.unchecked_scalar_right_shift_arithmetic_parallelized(
                ct,
                num_bits_in_ciphertext - 1,
            );
            let mut abs = self.add_parallelized(ct, &mask);
            self.bitxor_assign_parallelized(&mut abs, &mask);
            abs
        } else {
            ct.clone()
        }
    }

    pub fn smart_abs_parallelized<T>(&self, ct: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }
        self.unchecked_abs_parallelized(ct)
    }

    pub fn abs_parallelized<T>(&self, ct: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if ct.block_carries_are_empty() {
            self.unchecked_abs_parallelized(ct)
        } else {
            let mut cloned = ct.clone();
            self.full_propagate_parallelized(&mut cloned);
            self.unchecked_abs_parallelized(&cloned)
        }
    }
}
