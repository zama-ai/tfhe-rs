use super::ServerKey;

use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::server_key::comparator::Comparator;
use crate::shortint::PBSOrderMarker;

impl ServerKey {
    /// Compares for equality 2 ciphertexts
    ///
    /// Returns a ciphertext containing 1 if lhs == rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_eq(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 == msg2));
    /// ```
    pub fn unchecked_eq<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_eq(lhs, rhs)
    }

    /// Compares if lhs is strictly greater than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs > rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_gt(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 > msg2));
    /// ```
    pub fn unchecked_gt<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_gt(lhs, rhs)
    }

    /// Compares if lhs is greater or equal than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs >= rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 97u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_ge(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 >= msg2));
    /// ```
    pub fn unchecked_ge<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_ge(lhs, rhs)
    }

    /// Compares if lhs is strictly lower than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs < rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 237u64;
    /// let msg2 = 23u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_lt(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 < msg2));
    /// ```
    pub fn unchecked_lt<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_lt(lhs, rhs)
    }

    /// Compares if lhs is lower or equal than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs < rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 237u64;
    /// let msg2 = 23u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_le(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 < msg2));
    /// ```
    pub fn unchecked_le<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_le(lhs, rhs)
    }

    /// Computes the max of two encrypted values
    ///
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 237u64;
    /// let msg2 = 23u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_max(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, std::cmp::max(msg1, msg2));
    /// ```
    pub fn unchecked_max<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_max(lhs, rhs)
    }

    /// Computes the min of two encrypted values
    ///
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 237u64;
    /// let msg2 = 23u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_min(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, std::cmp::min(msg1, msg2));
    /// ```
    pub fn unchecked_min<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &RadixCiphertext<PBSOrder>,
        rhs: &RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).unchecked_min(lhs, rhs)
    }

    /// Compares for equality 2 ciphertexts
    ///
    /// Returns a ciphertext containing 1 if lhs == rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_eq(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 == msg2));
    /// ```
    pub fn smart_eq<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_eq(lhs, rhs)
    }

    /// Compares if lhs is strictly greater than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs == rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_gt(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 > msg2));
    /// ```
    pub fn smart_gt<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_gt(lhs, rhs)
    }

    /// Compares if lhs is greater or equal than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs >= rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_gt(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 >= msg2));
    /// ```
    pub fn smart_ge<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_ge(lhs, rhs)
    }

    /// Compares if lhs is strictly lower than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs < rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_lt(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 < msg2));
    /// ```
    pub fn smart_lt<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_lt(lhs, rhs)
    }

    /// Compares if lhs is lower or equal than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs <= rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_le(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 <= msg2));
    /// ```
    pub fn smart_le<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_le(lhs, rhs)
    }

    /// Computes the max of two encrypted values
    ///
    /// Returns a ciphertext containing 1 if lhs < rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_max(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, std::cmp::max(msg1, msg2));
    /// ```
    pub fn smart_max<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_max(lhs, rhs)
    }

    /// Computes the min of two encrypted values
    ///
    /// Returns a ciphertext containing 1 if lhs < rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_min(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, std::cmp::min(msg1, msg2));
    /// ```
    pub fn smart_min<PBSOrder: PBSOrderMarker>(
        &self,
        lhs: &mut RadixCiphertext<PBSOrder>,
        rhs: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        Comparator::new(self).smart_min(lhs, rhs)
    }
}
