use super::ServerKey;
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::server_key::CheckError;
use crate::shortint::server_key::CheckError::CarryFull;
use crate::shortint::Ciphertext;

impl ServerKey {
    /// Multiply two ciphertexts together without checks.
    ///
    /// Return the "least significant bits" of the multiplication, i.e., the result modulus the
    /// message_modulus.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_1;
    ///
    /// // Generate the client key and the server key
    /// let (mut cks, mut sks) = gen_keys(PARAM_MESSAGE_1_CARRY_1);
    ///
    /// let clear_1 = 1;
    /// let clear_2 = 1;
    ///
    /// // Encrypt two messages
    /// let ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_mul_lsb(&ct_1, &ct_2);
    /// // 2*3 == 6 == 01_10 (base 2)
    /// // Only the message part is returned (lsb) so `ct_res` is:
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn unchecked_mul_lsb(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_mul_lsb(self, ct_left, ct_right).unwrap()
        })
    }

    /// Multiply two ciphertexts together without checks.
    ///
    /// Return the "least significant bits" of the multiplication, i.e., the result modulus the
    /// message_modulus.
    ///
    /// The result is _assigned_ in the first ciphertext
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::DEFAULT_PARAMETERS;
    ///
    /// // Generate the client key and the server key
    /// let (mut cks, mut sks) = gen_keys(DEFAULT_PARAMETERS);
    ///
    /// let clear_1 = 3;
    /// let clear_2 = 2;
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_mul_lsb_assign(&mut ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_1);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn unchecked_mul_lsb_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_mul_lsb_assign(self, ct_left, ct_right)
                .unwrap()
        })
    }

    /// Multiply two ciphertexts together without checks.
    ///
    /// Return the "most significant bits" of the multiplication, i.e., the part in the carry
    /// buffer.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::DEFAULT_PARAMETERS;
    ///
    /// // Generate the client key and the server key
    /// let (mut cks, mut sks) = gen_keys(DEFAULT_PARAMETERS);
    ///
    /// let clear_1 = 3;
    /// let clear_2 = 2;
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt(clear_1);
    /// let mut ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_mul_msb(&ct_1, &ct_2);
    /// // 2*3 == 6 == 01_10 (base 2)
    /// // however the ciphertext will contain only the carry buffer
    /// // as the message, the ct_res is actually:
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!((clear_1 * clear_2) / modulus, res);
    /// ```
    pub fn unchecked_mul_msb(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_mul_msb(self, ct_left, ct_right).unwrap()
        })
    }

    pub fn unchecked_mul_msb_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_mul_msb_assign(self, ct_left, ct_right)
                .unwrap()
        })
    }

    /// Verify if two ciphertexts can be multiplied together.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (mut cks, mut sks) = gen_keys(Parameters::default());
    ///
    /// let msg = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(msg);
    /// let ct_2 = cks.encrypt(msg);
    ///
    /// // Check if we can perform a multiplication
    /// let res = sks.is_mul_possible(&ct_1, &ct_2);
    ///
    /// assert_eq!(true, res);
    /// ```
    pub fn is_mul_possible(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> bool {
        self.is_functional_bivariate_pbs_possible(ct1, ct2)
    }

    /// Multiply two ciphertexts together with checks.
    ///
    /// Return the "least significant bits" of the multiplication, i.e., the result modulus the
    /// message_modulus.
    ///
    /// If the operation can be performed, a _new_ ciphertext with the result is returned.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (mut cks, mut sks) = gen_keys(Parameters::default());
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(2);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.checked_mul_lsb(&ct_1, &ct_2);
    ///
    /// assert!(ct_res.is_ok());
    ///
    /// let ct_res = ct_res.unwrap();
    /// let clear_res = cks.decrypt_message_and_carry(&ct_res);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(clear_res % modulus, 2);
    /// ```
    pub fn checked_mul_lsb(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        if self.is_mul_possible(ct_left, ct_right) {
            let ct_result = self.unchecked_mul_lsb(ct_left, ct_right);
            Ok(ct_result)
        } else {
            Err(CarryFull)
        }
    }

    /// Multiply two ciphertexts together with checks.
    ///
    /// Return the "least significant bits" of the multiplication, i.e., the result modulus the
    /// message_modulus.
    ///
    /// If the operation can be performed, the result is assigned to the first ciphertext given
    /// as a parameter.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (mut cks, mut sks) = gen_keys(Parameters::default());
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.encrypt(2);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.checked_mul_lsb_assign(&mut ct_1, &ct_2);
    ///
    /// assert!(ct_res.is_ok());
    ///
    /// let clear_res = cks.decrypt_message_and_carry(&ct_1);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(clear_res % modulus, 2);
    /// ```
    pub fn checked_mul_lsb_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<(), CheckError> {
        if self.is_mul_possible(ct_left, ct_right) {
            self.unchecked_mul_lsb_assign(ct_left, ct_right);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Multiply two ciphertexts together without checks.
    ///
    /// Return the "most significant bits" of the multiplication, i.e., the part in the carry
    /// buffer.
    ///
    /// If the operation can be performed, a _new_ ciphertext with the result is returned.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (mut cks, mut sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg_1 = 2;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(msg_1);
    /// let ct_2 = cks.encrypt(msg_2);
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.checked_mul_msb(&ct_1, &ct_2);
    /// assert!(ct_res.is_ok());
    ///
    /// // 2*2 == 4 == 01_00 (base 2)
    /// // however the ciphertext will contain only the carry buffer
    /// // as the message, the ct_res is actually:
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// let ct_res = ct_res.unwrap();
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(
    ///     clear_res,
    ///     (msg_1 * msg_2) / cks.parameters.message_modulus.0 as u64
    /// );
    /// ```
    pub fn checked_mul_msb(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        if self.is_mul_possible(ct_left, ct_right) {
            let ct_result = self.unchecked_mul_msb(ct_left, ct_right);
            Ok(ct_result)
        } else {
            Err(CarryFull)
        }
    }

    /// Multiply two ciphertexts together using one bit of carry only.
    ///
    /// The algorithm uses the (.)^2/4 trick.
    /// For more information: page 4, §Computing a multiplication in
    /// Chillotti, I., Joye, M., Ligier, D., Orfila, J. B., & Tap, S. (2020, December).
    /// CONCRETE: Concrete operates on ciphertexts rapidly by extending TfhE.
    /// In WAHC 2020–8th Workshop on Encrypted Computing & Applied Homomorphic Cryptography (Vol.
    /// 15).
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_1;
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (mut cks, mut sks) = gen_keys(PARAM_MESSAGE_1_CARRY_1);
    ///
    /// let clear_1 = 1;
    /// let clear_2 = 1;
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt(clear_1);
    /// let mut ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_mul_lsb_small_carry(&mut ct_1, &mut ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((clear_2 * clear_1), res);
    /// ```
    pub fn unchecked_mul_lsb_small_carry(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_mul_lsb_small_carry_modulus(self, ct_left, ct_right)
                .unwrap()
        })
    }

    pub fn unchecked_mul_lsb_small_carry_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_mul_lsb_small_carry_modulus_assign(self, ct_left, ct_right)
                .unwrap()
        })
    }

    pub fn unchecked_mul_msb_small_carry(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_mul_msb_small_carry_modulus(self, ct_left, ct_right)
                .unwrap()
        })
    }

    pub fn unchecked_mul_msb_small_carry_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_mul_msb_small_carry_modulus_assign(self, ct_left, ct_right)
                .unwrap()
        })
    }


    /// Verify if two ciphertexts can be multiplied together in the case where the carry
    /// modulus is smaller than the message modulus.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_1;
    ///
    /// // Generate the client key and the server key:
    /// let (mut cks, mut sks) = gen_keys(PARAM_MESSAGE_2_CARRY_1);
    ///
    /// let msg = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(msg);
    /// let ct_2 = cks.encrypt(msg);
    ///
    /// // Check if we can perform a multiplication
    /// let mut res = sks.is_mul_small_carry_possible(&ct_1, &ct_2);
    ///
    /// assert_eq!(true, res);
    ///
    /// //Encryption with a full carry buffer
    /// let large_msg = 7;
    /// let ct_3 = cks.unchecked_encrypt(large_msg);
    ///
    /// //  Check if we can perform a multiplication
    /// res = sks.is_mul_small_carry_possible(&ct_1, &ct_3);
    ///
    /// assert_eq!(false, res);
    /// ```
    pub fn is_mul_small_carry_possible(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> bool {
        // Check if an addition is possible
        let b1 = self.is_add_possible(ct_left, ct_right);
        let b2 = self.is_sub_possible(ct_left, ct_right);
        b1 & b2
    }

    /// Compute homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// The operation is done using a small carry buffer.
    ///
    /// If the operation can be performed, a _new_ ciphertext with the result of the
    /// multiplication is returned. Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (mut cks, mut sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg_1 = 2;
    /// let msg_2 = 3;
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.encrypt(msg_1);
    /// let mut ct_2 = cks.encrypt(msg_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.checked_mul_lsb_with_small_carry(&mut ct_1, &mut ct_2);
    ///
    /// assert!(ct_res.is_ok());
    ///
    /// let ct_res = ct_res.unwrap();
    /// let clear_res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(clear_res % modulus, (msg_1 * msg_2) % modulus);
    /// ```
    pub fn checked_mul_lsb_with_small_carry(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        if self.is_mul_small_carry_possible(ct_left, ct_right) {
            let mut ct_result = self.unchecked_mul_lsb_small_carry(ct_left, ct_right);
            ct_result.degree = Degree(ct_left.degree.0 * 2);
            Ok(ct_result)
        } else {
            Err(CarryFull)
        }
    }

    /// Multiply two ciphertexts.
    ///
    /// Return the "least significant bits" of the multiplication, i.e., the result modulus the
    /// message_modulus.
    ///
    /// The result is _assigned_ in the first ciphertext
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_1;
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_1);
    ///
    /// // Encrypt two messages:
    /// let msg1 = 5;
    /// let msg2 = 3;
    ///
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let mut ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.smart_mul_lsb_assign(&mut ct_1, &mut ct_2);
    ///
    /// let res = cks.decrypt(&ct_1);
    /// let modulus = sks.message_modulus.0 as u64;
    /// assert_eq!(res % modulus, (msg1 * msg2) % modulus);
    /// ```
    pub fn smart_mul_lsb_assign(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .smart_mul_lsb_assign(self, ct_left, ct_right)
                .unwrap()
        })
    }

    pub fn smart_mul_msb_assign(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .smart_mul_msb_assign(self, ct_left, ct_right)
                .unwrap()
        })
    }

    /// Multiply two ciphertexts together
    ///
    /// Return the "least significant bits" of the multiplication, i.e., the result modulus the
    /// message_modulus.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(Parameters::default());
    ///
    /// // Encrypt two messages:
    /// let msg1 = 12;
    /// let msg2 = 13;
    ///
    /// let mut ct_left = cks.unchecked_encrypt(msg1);
    /// // |      ct_left    |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 1  |   0 0   |
    /// let mut ct_right = cks.unchecked_encrypt(msg2);
    /// // |      ct_right   |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 1  |   0 1   |
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.smart_mul_lsb(&mut ct_left, &mut ct_right);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 0   |
    ///
    /// let res = cks.decrypt(&ct_res);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res, (msg1 * msg2) % modulus as u64);
    /// ```
    pub fn smart_mul_lsb(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_mul_lsb(self, ct_left, ct_right).unwrap()
        })
    }

    /// Multiply two ciphertexts together
    ///
    /// Return the "most significant bits" of the multiplication, i.e., the part in the carry
    /// buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(Parameters::default());
    ///
    /// // Encrypt two messages:
    /// let msg1 = 12;
    /// let msg2 = 12;
    ///
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let mut ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.smart_mul_msb(&mut ct_1, &mut ct_2);
    ///
    /// let res = cks.decrypt(&ct_res);
    /// let modulus = sks.carry_modulus.0;
    /// assert_eq!(res, (msg1 * msg2) % modulus as u64);
    /// ```
    pub fn smart_mul_msb(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_mul_msb(self, ct_left, ct_right).unwrap()
        })
    }
}
