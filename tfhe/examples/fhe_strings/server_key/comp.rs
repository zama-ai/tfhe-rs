use crate::ciphertext::{FheString, GenericPattern};
use crate::server_key::{FheStringIsEmpty, ServerKey};
use tfhe::integer::BooleanBlock;

impl ServerKey {
    fn eq_length_checks(&self, lhs: &FheString, rhs: &FheString) -> Option<BooleanBlock> {
        let lhs_len = lhs.chars().len();
        let rhs_len = rhs.chars().len();

        // If lhs is empty, rhs must also be empty in order to be equal (the case where lhs is
        // empty with > 1 padding zeros is handled next)
        if lhs_len == 0 || (lhs.is_padded() && lhs_len == 1) {
            return match self.is_empty(rhs) {
                FheStringIsEmpty::Padding(enc_val) => Some(enc_val),
                FheStringIsEmpty::NoPadding(val) => {
                    Some(self.key.create_trivial_boolean_block(val))
                }
            };
        }

        // If rhs is empty, lhs must also be empty in order to be equal (only case remaining is if
        // lhs padding zeros > 1)
        if rhs_len == 0 || (rhs.is_padded() && rhs_len == 1) {
            return match self.is_empty(lhs) {
                FheStringIsEmpty::Padding(enc_val) => Some(enc_val),
                _ => Some(self.key.create_trivial_boolean_block(false)),
            };
        }

        // Two strings without padding that have different lengths cannot be equal
        if (!lhs.is_padded() && !rhs.is_padded()) && (lhs.chars().len() != rhs.chars().len()) {
            return Some(self.key.create_trivial_boolean_block(false));
        }

        // A string without padding cannot be equal to a string with padding that has the same or
        // lower length
        if (!lhs.is_padded() && rhs.is_padded()) && (rhs.chars().len() <= lhs.chars().len())
            || (!rhs.is_padded() && lhs.is_padded()) && (lhs.chars().len() <= rhs.chars().len())
        {
            return Some(self.key.create_trivial_boolean_block(false));
        }

        None
    }

    /// Returns `true` if an encrypted string and a pattern (either encrypted or clear) are equal.
    ///
    /// Returns `false` if they are not equal.
    ///
    /// The pattern for comparison (`rhs`) can be specified as either `GenericPattern::Clear` for a
    /// clear string or `GenericPattern::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::ciphertext::{FheString, GenericPattern};
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let (s1, s2) = ("hello", "hello");
    ///
    /// let enc_s1 = FheString::new(&ck, &s1, None);
    /// let enc_s2 = GenericPattern::Enc(FheString::new(&ck, &s2, None));
    ///
    /// let result = sk.eq(&enc_s1, &enc_s2);
    /// let are_equal = ck.key().decrypt_bool(&result);
    ///
    /// assert!(are_equal);
    /// ```
    pub fn eq(&self, lhs: &FheString, rhs: &GenericPattern) -> BooleanBlock {
        let early_return = match rhs {
            GenericPattern::Clear(rhs) => {
                self.eq_length_checks(lhs, &FheString::trivial(self, rhs.str()))
            }
            GenericPattern::Enc(rhs) => self.eq_length_checks(lhs, rhs),
        };

        if let Some(val) = early_return {
            return val;
        }

        let mut lhs_uint = lhs.to_uint(self);
        match rhs {
            GenericPattern::Clear(rhs) => {
                let rhs_clear_uint = self.pad_cipher_and_cleartext_lsb(&mut lhs_uint, rhs.str());

                self.key.scalar_eq_parallelized(&lhs_uint, rhs_clear_uint)
            }
            GenericPattern::Enc(rhs) => {
                let mut rhs_uint = rhs.to_uint(self);

                self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);

                self.key.eq_parallelized(&lhs_uint, &rhs_uint)
            }
        }
    }

    /// Returns `true` if an encrypted string and a pattern (either encrypted or clear) are not
    /// equal.
    ///
    /// Returns `false` if they are equal.
    ///
    /// The pattern for comparison (`rhs`) can be specified as either `GenericPattern::Clear` for a
    /// clear string or `GenericPattern::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::ciphertext::{FheString, GenericPattern};
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let (s1, s2) = ("hello", "world");
    ///
    /// let enc_s1 = FheString::new(&ck, &s1, None);
    /// let enc_s2 = GenericPattern::Enc(FheString::new(&ck, &s2, None));
    ///
    /// let result = sk.ne(&enc_s1, &enc_s2);
    /// let are_not_equal = ck.key().decrypt_bool(&result);
    ///
    /// assert!(are_not_equal);
    /// ```
    pub fn ne(&self, lhs: &FheString, rhs: &GenericPattern) -> BooleanBlock {
        let eq = self.eq(lhs, rhs);

        self.key.boolean_bitnot(&eq)
    }

    /// Returns `true` if the first encrypted string is less than the second encrypted string.
    ///
    /// Returns `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::ciphertext::FheString;
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let (s1, s2) = ("apple", "banana");
    ///
    /// let enc_s1 = FheString::new(&ck, &s1, None);
    /// let enc_s2 = FheString::new(&ck, &s2, None);
    ///
    /// let result = sk.lt(&enc_s1, &enc_s2);
    /// let is_lt = ck.key().decrypt_bool(&result);
    ///
    /// assert!(is_lt); // "apple" is less than "banana"
    /// ```
    pub fn lt(&self, lhs: &FheString, rhs: &FheString) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);

        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);

        self.key.lt_parallelized(&lhs_uint, &rhs_uint)
    }

    /// Returns `true` if the first encrypted string is greater than the second encrypted string.
    ///
    /// Returns `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::ciphertext::FheString;
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let (s1, s2) = ("banana", "apple");
    ///
    /// let enc_s1 = FheString::new(&ck, &s1, None);
    /// let enc_s2 = FheString::new(&ck, &s2, None);
    ///
    /// let result = sk.gt(&enc_s1, &enc_s2);
    /// let is_gt = ck.key().decrypt_bool(&result);
    ///
    /// assert!(is_gt); // "banana" is greater than "apple"
    /// ```
    pub fn gt(&self, lhs: &FheString, rhs: &FheString) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);

        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);

        self.key.gt_parallelized(&lhs_uint, &rhs_uint)
    }

    /// Returns `true` if the first encrypted string is less than or equal to the second encrypted
    /// string.
    ///
    /// Returns `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::ciphertext::FheString;
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let (s1, s2) = ("apple", "banana");
    ///
    /// let enc_s1 = FheString::new(&ck, &s1, None);
    /// let enc_s2 = FheString::new(&ck, &s2, None);
    ///
    /// let result = sk.le(&enc_s1, &enc_s2);
    /// let is_le = ck.key().decrypt_bool(&result);
    ///
    /// assert!(is_le); // "apple" is less than or equal to "banana"
    /// ```
    pub fn le(&self, lhs: &FheString, rhs: &FheString) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);

        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);

        self.key.le_parallelized(&lhs_uint, &rhs_uint)
    }

    /// Returns `true` if the first encrypted string is greater than or equal to the second
    /// encrypted string.
    ///
    /// Returns `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::ciphertext::FheString;
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let (s1, s2) = ("banana", "apple");
    ///
    /// let enc_s1 = FheString::new(&ck, &s1, None);
    /// let enc_s2 = FheString::new(&ck, &s2, None);
    ///
    /// let result = sk.ge(&enc_s1, &enc_s2);
    /// let is_ge = ck.key().decrypt_bool(&result);
    ///
    /// assert!(is_ge); // "banana" is greater than or equal to "apple"
    /// ```
    pub fn ge(&self, lhs: &FheString, rhs: &FheString) -> BooleanBlock {
        let mut lhs_uint = lhs.to_uint(self);
        let mut rhs_uint = rhs.to_uint(self);

        self.pad_ciphertexts_lsb(&mut lhs_uint, &mut rhs_uint);

        self.key.ge_parallelized(&lhs_uint, &rhs_uint)
    }
}
