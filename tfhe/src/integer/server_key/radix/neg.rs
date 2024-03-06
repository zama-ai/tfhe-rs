use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::CheckError;
use crate::integer::ServerKey;
use crate::shortint::ciphertext::{Degree, MaxDegree};
#[cfg(any(test, feature = "gpu"))]
use crate::shortint::MessageModulus;

/// Iterator that returns the new degree of blocks
/// after negation was done.
///
/// It takes as input an iterator that returns the degree of the blocks
/// before negation as well as their message modulus.
#[cfg(any(test, feature = "gpu"))]
pub(crate) struct NegatedDegreeIter<I> {
    iter: I,
    z_b: usize,
}

#[cfg(any(test, feature = "gpu"))]
impl<I> NegatedDegreeIter<I>
where
    I: Iterator<Item = (Degree, MessageModulus)>,
{
    pub(crate) fn new(iter: I) -> Self {
        Self { iter, z_b: 0 }
    }
}

#[cfg(any(test, feature = "gpu"))]
impl<I> Iterator for NegatedDegreeIter<I>
where
    I: Iterator<Item = (Degree, MessageModulus)>,
{
    type Item = Degree;

    fn next(&mut self) -> Option<Self::Item> {
        let (mut current_degree, msg_mod) = self.iter.next()?;
        current_degree += Degree::new(self.z_b);

        // Ensure z is always >= 1 (which would not be the case if degree == 0)
        // some algorithms (e.g. overflowing_sub) require this even for trivial zeros
        let mut z = current_degree.get().div_ceil(msg_mod.0).max(1) as u64;
        z *= msg_mod.0 as u64;

        let new_degree = Degree::new(z as usize - self.z_b);
        self.z_b = z as usize / msg_mod.0;

        Some(new_degree)
    }
}

impl ServerKey {
    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// This function computes the opposite of a message without checking if it exceeds the
    /// capacity of the ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// // Encrypt two messages:
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let modulus = 1 << 8;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 159u64;
    ///
    /// // Encrypt a message
    /// let mut ctxt = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// sks.unchecked_neg_assign(&mut ctxt);
    ///
    /// // Decrypt
    /// let dec: u64 = cks.decrypt(&ctxt);
    /// assert_eq!(modulus - msg, dec);
    /// ```
    pub fn unchecked_neg<T>(&self, ctxt: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = ctxt.clone();

        self.unchecked_neg_assign(&mut result);

        result
    }

    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// This function computes the opposite of a message without checking if it exceeds the
    /// capacity of the ciphertext.
    ///
    /// The result is assigned to the input ciphertext.
    pub fn unchecked_neg_assign<T>(&self, ctxt: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        //z is used to make sure the negation doesn't fill the padding bit
        let mut z;
        let mut z_b = 0;

        for block in ctxt.blocks_mut() {
            if z_b != 0 {
                self.key.unchecked_scalar_add_assign(block, z_b);
            }
            z = self.key.unchecked_neg_assign_with_correcting_term(block);
            block.degree = Degree::new(z as usize - z_b as usize);

            z_b = (z / self.key.message_modulus.0 as u64) as u8;
        }
    }

    /// Verifies if ct can be negated.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 2u64;
    ///
    /// // Encrypt a message
    /// let ctxt = cks.encrypt(msg);
    ///
    /// // Check if we can perform a negation
    /// sks.is_neg_possible(&ctxt).unwrap();
    /// ```
    pub fn is_neg_possible<T>(&self, ctxt: &T) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        let mut preceding_block_carry = Degree::new(0);
        let mut preceding_scaled_z = 0;
        for block in ctxt.blocks().iter() {
            let msg_mod = block.message_modulus.0;
            let max_degree =
                MaxDegree::from_msg_carry_modulus(block.message_modulus, block.carry_modulus);

            // z = ceil( degree / 2^p ) x 2^p
            let mut z = block.degree.get().div_ceil(msg_mod);
            z = z.wrapping_mul(msg_mod);
            // In the actual operation, preceding_scaled_z is added to the ciphertext
            // before doing lwe_ciphertext_opposite:
            // i.e the code does -(ciphertext + preceding_scaled_z) + z
            // here we do -ciphertext -preceding_scaled_z + z
            // which is easier to express degree
            let block_degree_after_negation = Degree::new(z - preceding_scaled_z);

            // We want to be able to add together the negated block and the carry
            // from preceding negated block to make sure carry propagation would be correct.

            max_degree.validate(block_degree_after_negation + preceding_block_carry)?;

            preceding_block_carry = Degree::new(block_degree_after_negation.get() / msg_mod);
            preceding_scaled_z = z / msg_mod;
        }
        Ok(())
    }

    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// This function computes the opposite of a message without checking if it exceeds the
    /// capacity of the ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 1u64;
    ///
    /// // Encrypt a message
    /// let ctxt = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation:
    /// let ct_res = sks.checked_neg(&ctxt);
    ///
    /// match ct_res {
    ///     Err(x) => panic!("{:?}", x),
    ///     Ok(y) => {
    ///         let clear: u64 = cks.decrypt(&y);
    ///         assert_eq!(255, clear);
    ///     }
    /// }
    /// ```
    pub fn checked_neg<T>(&self, ctxt: &T) -> Result<T, CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        //If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        self.is_neg_possible(ctxt)?;
        let mut result = ctxt.clone();
        self.unchecked_neg_assign(&mut result);
        Ok(result)
    }

    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// This function computes the opposite of a message without checking if it exceeds the
    /// capacity of the ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let modulus = 1 << 8;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 1;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation:
    /// sks.checked_neg_assign(&mut ct);
    ///
    /// let clear_res: u64 = cks.decrypt(&ct);
    /// assert_eq!(clear_res, (modulus - msg));
    /// ```
    pub fn checked_neg_assign<T>(&self, ctxt: &mut T) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        //If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        self.is_neg_possible(ctxt)?;
        self.unchecked_neg_assign(ctxt);
        Ok(())
    }

    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 1u64;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// let ct_res = sks.smart_neg(&mut ctxt);
    ///
    /// // Decrypt
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(255, dec);
    /// ```
    pub fn smart_neg<T>(&self, ctxt: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if self.is_neg_possible(ctxt).is_err() {
            self.full_propagate(ctxt);
        }
        self.is_neg_possible(ctxt).unwrap();
        self.unchecked_neg(ctxt)
    }

    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// The result is assigned to the input ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 1u64;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// sks.smart_neg_assign(&mut ctxt);
    ///
    /// // Decrypt
    /// let dec: u64 = cks.decrypt(&ctxt);
    /// assert_eq!(255, dec);
    /// ```
    pub fn smart_neg_assign<T>(&self, ctxt: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        if self.is_neg_possible(ctxt).is_err() {
            self.full_propagate(ctxt);
        }
        self.is_neg_possible(ctxt).unwrap();
        self.unchecked_neg_assign(ctxt);
    }
}
