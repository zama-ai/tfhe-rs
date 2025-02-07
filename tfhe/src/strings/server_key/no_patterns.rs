use crate::integer::ServerKey as IntegerServerKey;
use crate::strings::ciphertext::{FheString, UIntArg};
use crate::strings::server_key::{FheStringIsEmpty, FheStringLen, ServerKey};
use rayon::prelude::*;
use std::borrow::Borrow;

impl<T: Borrow<IntegerServerKey> + Sync> ServerKey<T> {
    /// Returns the length of an encrypted string as an `FheStringLen` enum.
    ///
    /// If the encrypted string has no padding, the length is the clear length of the char vector.
    /// If there is padding, the length is calculated homomorphically and returned as an
    /// encrypted `RadixCiphertext`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::FheString;
    /// use tfhe::strings::server_key::FheStringLen;
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let s = "hello";
    /// let number_of_nulls = 3;
    ///
    /// let enc_s_no_padding = FheString::new(&ck, s, None);
    /// let enc_s_with_padding = FheString::new(&ck, s, Some(number_of_nulls));
    ///
    /// let result_no_padding = sk.len(&enc_s_no_padding);
    /// let result_with_padding = sk.len(&enc_s_with_padding);
    ///
    /// match result_no_padding {
    ///     FheStringLen::NoPadding(length) => assert_eq!(length, 5),
    ///     FheStringLen::Padding(_) => panic!("Unexpected padding"),
    /// }
    ///
    /// match result_with_padding {
    ///     FheStringLen::NoPadding(_) => panic!("Unexpected no padding"),
    ///     FheStringLen::Padding(ciphertext) => {
    ///         // Homomorphically computed length, requires decryption for actual length
    ///         let length = ck.inner().decrypt_radix::<u32>(&ciphertext);
    ///         assert_eq!(length, 5)
    ///     }
    /// }
    /// ```
    pub fn len(&self, str: &FheString) -> FheStringLen {
        let sk = self.inner();

        if str.is_padded() {
            let non_zero_chars: Vec<_> = str
                .chars()
                .par_iter()
                .map(|char| {
                    let bool = sk.scalar_ne_parallelized(char.ciphertext(), 0u8);
                    bool.into_radix(16, sk)
                })
                .collect();

            // If we add the number of non-zero elements we get the actual length, without padding
            let len = sk
                .sum_ciphertexts_parallelized(non_zero_chars.iter())
                .expect("There's at least one padding character");

            FheStringLen::Padding(len)
        } else {
            FheStringLen::NoPadding(str.len())
        }
    }

    /// Returns whether an encrypted string is empty or not as an `FheStringIsEmpty` enum.
    ///
    /// If the encrypted string has no padding, the result is a clear boolean.
    /// If there is padding, the result is calculated homomorphically and returned as an
    /// encrypted `RadixCiphertext`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::FheString;
    /// use tfhe::strings::server_key::FheStringIsEmpty;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let s = "";
    /// let number_of_nulls = 2;
    ///
    /// let enc_s_no_padding = FheString::new(&ck, s, None);
    /// let enc_s_with_padding = FheString::new(&ck, s, Some(number_of_nulls));
    ///
    /// let result_no_padding = sk.is_empty(&enc_s_no_padding);
    /// let result_with_padding = sk.is_empty(&enc_s_with_padding);
    ///
    /// match result_no_padding {
    ///     FheStringIsEmpty::NoPadding(is_empty) => assert!(is_empty),
    ///     FheStringIsEmpty::Padding(_) => panic!("Unexpected padding"),
    /// }
    ///
    /// match result_with_padding {
    ///     FheStringIsEmpty::NoPadding(_) => panic!("Unexpected no padding"),
    ///     FheStringIsEmpty::Padding(ciphertext) => {
    ///         // Homomorphically computed emptiness, requires decryption for actual value
    ///         let is_empty = ck.inner().decrypt_bool(&ciphertext);
    ///         assert!(is_empty)
    ///     }
    /// }
    /// ```
    pub fn is_empty(&self, str: &FheString) -> FheStringIsEmpty {
        let sk = self.inner();

        if str.is_padded() {
            if str.len() == 1 {
                return FheStringIsEmpty::Padding(sk.create_trivial_boolean_block(true));
            }

            let str_uint = str.to_uint();
            let result = sk.scalar_eq_parallelized(&str_uint, 0u8);

            FheStringIsEmpty::Padding(result)
        } else {
            FheStringIsEmpty::NoPadding(str.len() == 0)
        }
    }

    /// Returns a new encrypted string with all characters converted to uppercase.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::FheString;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let s = "Hello World";
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    ///
    /// let result = sk.to_uppercase(&enc_s);
    /// let uppercased = ck.decrypt_ascii(&result);
    ///
    /// assert_eq!(uppercased, "HELLO WORLD");
    /// ```
    pub fn to_uppercase(&self, str: &FheString) -> FheString {
        let sk = self.inner();

        let mut uppercase = str.clone();

        // Returns 1 if the corresponding character is lowercase, 0 otherwise
        let lowercase_chars: Vec<_> = str
            .chars()
            .par_iter()
            .map(|char| {
                let (ge_97, le_122) = rayon::join(
                    || sk.scalar_ge_parallelized(char.ciphertext(), 97u8),
                    || sk.scalar_le_parallelized(char.ciphertext(), 122u8),
                );

                sk.boolean_bitand(&ge_97, &le_122)
            })
            .collect();

        // Subtraction by 32 makes the character uppercase
        uppercase
            .chars_mut()
            .par_iter_mut()
            .zip(lowercase_chars.into_par_iter())
            .for_each(|(char, is_lowercase)| {
                let mut subtract = sk.create_trivial_radix(32, self.num_ascii_blocks());

                sk.mul_assign_parallelized(&mut subtract, &is_lowercase.into_radix(1, sk));

                sk.sub_assign_parallelized(char.ciphertext_mut(), &subtract);
            });

        uppercase
    }

    /// Returns a new encrypted string with all characters converted to lowercase.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::FheString;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let s = "Hello World";
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    ///
    /// let result = sk.to_lowercase(&enc_s);
    /// let lowercased = ck.decrypt_ascii(&result);
    ///
    /// assert_eq!(lowercased, "hello world");
    /// ```
    pub fn to_lowercase(&self, str: &FheString) -> FheString {
        let sk = self.inner();

        let mut lowercase = str.clone();

        // Returns 1 if the corresponding character is uppercase, 0 otherwise
        let uppercase_chars: Vec<_> = str
            .chars()
            .par_iter()
            .map(|char| {
                let (ge_65, le_90) = rayon::join(
                    || sk.scalar_ge_parallelized(char.ciphertext(), 65u8),
                    || sk.scalar_le_parallelized(char.ciphertext(), 90u8),
                );

                sk.boolean_bitand(&ge_65, &le_90)
            })
            .collect();

        // Addition by 32 makes the character lowercase
        lowercase
            .chars_mut()
            .par_iter_mut()
            .zip(uppercase_chars)
            .for_each(|(char, is_uppercase)| {
                let mut add = sk.create_trivial_radix(32, self.num_ascii_blocks());

                sk.mul_assign_parallelized(&mut add, &is_uppercase.into_radix(1, sk));

                sk.add_assign_parallelized(char.ciphertext_mut(), &add);
            });

        lowercase
    }

    /// Concatenates two encrypted strings and returns the result as a new encrypted string.
    ///
    /// This function is equivalent to using the `+` operator on standard strings.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::FheString;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let (lhs, rhs) = ("Hello, ", "world!");
    ///
    /// let enc_lhs = FheString::new(&ck, lhs, None);
    /// let enc_rhs = FheString::new(&ck, rhs, None);
    ///
    /// let result = sk.concat(&enc_lhs, &enc_rhs);
    /// let concatenated = ck.decrypt_ascii(&result);
    ///
    /// assert_eq!(concatenated, "Hello, world!");
    /// ```
    pub fn concat(&self, lhs: &FheString, rhs: &FheString) -> FheString {
        let sk = self.inner();

        let mut result = lhs.clone();

        match self.len(lhs) {
            // No homomorphic operation required if the lhs is not padded
            FheStringLen::NoPadding(_) => {
                result.chars_vec().extend_from_slice(rhs.chars());
                result.set_is_padded(rhs.is_padded());
            }

            // If lhs is padded we can shift it right such that all nulls move to the start, then
            // we append the rhs and shift it left again to move the nulls to the new end
            FheStringLen::Padding(len) => {
                let padded_len = sk.create_trivial_radix(lhs.len() as u32, 16);
                let number_of_nulls = sk.sub_parallelized(&padded_len, &len);

                result = self.right_shift_chars(&result, &number_of_nulls);

                result.chars_vec().extend_from_slice(rhs.chars());

                result = self.left_shift_chars(&result, &number_of_nulls);

                result.set_is_padded(true);
            }
        }

        result
    }

    /// Returns a new encrypted string which is the original encrypted string repeated `n` times.
    ///
    /// The number of repetitions `n` is specified by a `UIntArg`, which can be either `Clear` or
    /// `Enc`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::{FheString, UIntArg};
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let s = "hi";
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    ///
    /// // Using Clear count
    /// let clear_count = UIntArg::Clear(3);
    /// let result_clear = sk.repeat(&enc_s, &clear_count);
    /// let repeated_clear = ck.decrypt_ascii(&result_clear);
    ///
    /// assert_eq!(repeated_clear, "hihihi");
    ///
    /// // Using Encrypted count
    /// let max = 3; // Restricts the range of enc_n to 0..=max
    /// let enc_n = ck.encrypt_u16(3, Some(max));
    /// let enc_count = UIntArg::Enc(enc_n);
    /// let result_enc = sk.repeat(&enc_s, &enc_count);
    /// let repeated_enc = ck.decrypt_ascii(&result_enc);
    ///
    /// assert_eq!(repeated_enc, "hihihi");
    /// ```
    pub fn repeat(&self, str: &FheString, n: &UIntArg) -> FheString {
        let sk = self.inner();

        if matches!(n, UIntArg::Clear(0)) {
            return FheString::empty();
        }

        if str.is_empty() {
            return FheString::empty();
        }

        let mut result = str.clone();

        // Note that if n = 3, at most we have to append the str 2 times
        match n {
            UIntArg::Clear(clear_n) => {
                for _ in 0..*clear_n - 1 {
                    result = self.concat(&result, str);
                }
            }
            UIntArg::Enc(enc_n) => {
                let n_is_zero = sk.scalar_eq_parallelized(enc_n.cipher(), 0);
                result = self.conditional_string(&n_is_zero, &FheString::empty(), &result);

                for i in 0..enc_n.max().unwrap_or(u16::MAX).saturating_sub(1) {
                    let n_is_exceeded = sk.scalar_le_parallelized(enc_n.cipher(), i + 1);
                    let append = self.conditional_string(&n_is_exceeded, &FheString::empty(), str);

                    result = self.concat(&result, &append);
                }

                // If str was not padded and n == max we don't get nulls at the end. However if
                // n < max we do, and as these conditions are unknown we have to ensure result is
                // actually padded
                if !str.is_padded() {
                    result.append_null(self);
                }
            }
        }

        result
    }
}
