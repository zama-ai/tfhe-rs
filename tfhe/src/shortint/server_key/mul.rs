use super::add::unchecked_add_assign;
use super::{CiphertextNoiseDegree, ServerKey};
use crate::shortint::ciphertext::Degree;
use crate::shortint::server_key::CheckError;
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
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn unchecked_mul_lsb(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut result = ct_left.clone();
        self.unchecked_mul_lsb_assign(&mut result, ct_right);
        result
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
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn unchecked_mul_lsb_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        if ct_left.degree.get() == 0 || ct_right.degree.get() == 0 {
            // One of the ciphertext is a trivial 0
            self.create_trivial_assign(ct_left, 0);
            return;
        }

        //Modulus of the msg in the msg bits
        let res_modulus = ct_left.message_modulus.0;
        self.unchecked_evaluate_bivariate_function_assign(ct_left, ct_right, |x, y| {
            (x * y) % res_modulus
        });
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
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 3;
    /// let clear_2 = 2;
    ///
    /// // Encrypt two messages
    /// let ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
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
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!((clear_1 * clear_2) / modulus, res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages
    /// let ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
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
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!((clear_1 * clear_2) / modulus, res);
    /// ```
    pub fn unchecked_mul_msb(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut result = ct_left.clone();
        self.unchecked_mul_msb_assign(&mut result, ct_right);

        result
    }

    pub fn unchecked_mul_msb_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        if ct_left.degree.get() == 0 || ct_right.degree.get() == 0 {
            // One of the ciphertext is a trivial 0
            self.create_trivial_assign(ct_left, 0);
            return;
        }

        // Modulus of the msg in the msg bits
        let res_modulus = self.message_modulus.0;
        self.unchecked_evaluate_bivariate_function_assign(ct_left, ct_right, |x, y| {
            (x * y) / res_modulus
        });
    }

    pub(crate) fn unchecked_mul_lsb_small_carry_modulus(
        &self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
    ) -> Ciphertext {
        // ct1 + ct2
        let mut ct_add = ct1.clone();

        unchecked_add_assign(&mut ct_add, ct2, self.max_noise_level);

        // ct1 - ct2
        let (mut ct_sub, z) = self.unchecked_sub_with_correcting_term(ct1, ct2);

        //Modulus of the msg in the msg bits
        let modulus = ct1.message_modulus.0;

        let acc_add = self.generate_lookup_table(|x| ((x.wrapping_mul(x)) / 4) % modulus);
        let acc_sub = self.generate_lookup_table(|x| {
            (((x.wrapping_sub(z)).wrapping_mul(x.wrapping_sub(z))) / 4) % modulus
        });

        self.apply_lookup_table_assign(&mut ct_add, &acc_add);
        self.apply_lookup_table_assign(&mut ct_sub, &acc_sub);

        //Last subtraction might fill one bit of carry
        self.unchecked_sub(&ct_add, &ct_sub)
    }

    pub(crate) fn unchecked_mul_lsb_small_carry_modulus_assign(
        &self,
        ct1: &mut Ciphertext,
        ct2: &Ciphertext,
    ) {
        *ct1 = self.unchecked_mul_lsb_small_carry_modulus(ct1, ct2);
    }

    /// Verify if two ciphertexts can be multiplied together.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(msg);
    /// let ct_2 = cks.encrypt(msg);
    ///
    /// // Check if we can perform a multiplication
    /// sks.is_mul_possible(ct_1.noise_degree(), ct_2.noise_degree())
    ///     .unwrap();
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(msg);
    /// let ct_2 = cks.encrypt(msg);
    ///
    /// // Check if we can perform a multiplication
    /// sks.is_mul_possible(ct_1.noise_degree(), ct_2.noise_degree())
    ///     .unwrap();
    /// ```
    pub fn is_mul_possible(
        &self,
        ct1: CiphertextNoiseDegree,
        ct2: CiphertextNoiseDegree,
    ) -> Result<(), CheckError> {
        self.is_functional_bivariate_pbs_possible(ct1, ct2, None)
    }

    /// Multiply two ciphertexts together with checks.
    ///
    /// Return the "least significant bits" of the multiplication, i.e., the result modulus the
    /// message_modulus.
    ///
    /// If the operation can be performed, a _new_ ciphertext with the result is returned.
    /// Otherwise a [CheckError] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(2);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.checked_mul_lsb(&ct_1, &ct_2).unwrap();
    ///
    /// let clear_res = cks.decrypt_message_and_carry(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(clear_res % modulus, 2);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(2);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.checked_mul_lsb(&ct_1, &ct_2).unwrap();
    ///
    /// let clear_res = cks.decrypt_message_and_carry(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(clear_res % modulus, 2);
    /// ```
    pub fn checked_mul_lsb(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        self.is_mul_possible(ct_left.noise_degree(), ct_right.noise_degree())?;
        let ct_result = self.unchecked_mul_lsb(ct_left, ct_right);
        Ok(ct_result)
    }

    /// Multiply two ciphertexts together with checks.
    ///
    /// Return the "least significant bits" of the multiplication, i.e., the result modulus the
    /// message_modulus.
    ///
    /// If the operation can be performed, the result is assigned to the first ciphertext given
    /// as a parameter.
    /// Otherwise a [CheckError] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.encrypt(2);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a multiplication:
    /// sks.checked_mul_lsb_assign(&mut ct_1, &ct_2).unwrap();
    ///
    /// let clear_res = cks.decrypt_message_and_carry(&ct_1);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(clear_res % modulus, 2);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.encrypt(2);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a multiplication:
    /// sks.checked_mul_lsb_assign(&mut ct_1, &ct_2).unwrap();
    ///
    /// let clear_res = cks.decrypt_message_and_carry(&ct_1);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(clear_res % modulus, 2);
    /// ```
    pub fn checked_mul_lsb_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<(), CheckError> {
        self.is_mul_possible(ct_left.noise_degree(), ct_right.noise_degree())?;
        self.unchecked_mul_lsb_assign(ct_left, ct_right);
        Ok(())
    }

    /// Multiply two ciphertexts together without checks.
    ///
    /// Return the "most significant bits" of the multiplication, i.e., the part in the carry
    /// buffer.
    ///
    /// If the operation can be performed, a _new_ ciphertext with the result is returned.
    /// Otherwise a [CheckError] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(msg_1);
    /// let ct_2 = cks.encrypt(msg_2);
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.checked_mul_msb(&ct_1, &ct_2).unwrap();
    ///
    /// // 2*2 == 4 == 01_00 (base 2)
    /// // however the ciphertext will contain only the carry buffer
    /// // as the message, the ct_res is actually:
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(
    ///     clear_res,
    ///     (msg_1 * msg_2) / cks.parameters.message_modulus().0
    /// );
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(msg_1);
    /// let ct_2 = cks.encrypt(msg_2);
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.checked_mul_msb(&ct_1, &ct_2).unwrap();
    ///
    /// // 2*2 == 4 == 01_00 (base 2)
    /// // however the ciphertext will contain only the carry buffer
    /// // as the message, the ct_res is actually:
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(
    ///     clear_res,
    ///     (msg_1 * msg_2) / cks.parameters.message_modulus().0
    /// );
    /// ```
    pub fn checked_mul_msb(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        self.is_mul_possible(ct_left.noise_degree(), ct_right.noise_degree())?;
        let ct_result = self.unchecked_mul_msb(ct_left, ct_right);
        Ok(ct_result)
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
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 1;
    /// let clear_2 = 1;
    ///
    /// // Encrypt two messages
    /// let ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_mul_lsb_small_carry(&ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((clear_2 * clear_1), res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages
    /// let ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_mul_lsb_small_carry(&ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((clear_2 * clear_1), res);
    /// ```
    pub fn unchecked_mul_lsb_small_carry(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Ciphertext {
        self.unchecked_mul_lsb_small_carry_modulus(ct_left, ct_right)
    }

    pub fn unchecked_mul_lsb_small_carry_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) {
        self.unchecked_mul_lsb_small_carry_modulus_assign(ct_left, ct_right);
    }

    /// Verify if two ciphertexts can be multiplied together in the case where the carry
    /// modulus is smaller than the message modulus.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64);
    ///
    /// let msg = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(msg);
    /// let ct_2 = cks.encrypt(msg);
    ///
    /// // Check if we can perform a multiplication
    /// sks.is_mul_small_carry_possible(ct_1.noise_degree(), ct_2.noise_degree())
    ///     .unwrap();
    ///
    /// //Encryption with a full carry buffer
    /// let large_msg = 7;
    /// let ct_3 = cks.unchecked_encrypt(large_msg);
    ///
    /// //  Check if we can perform a multiplication
    /// let res = sks.is_mul_small_carry_possible(ct_1.noise_degree(), ct_3.noise_degree());
    ///
    /// assert!(res.is_err());
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(msg);
    /// let ct_2 = cks.encrypt(msg);
    ///
    /// // Check if we can perform a multiplication
    /// sks.is_mul_small_carry_possible(ct_1.noise_degree(), ct_2.noise_degree())
    ///     .unwrap();
    ///
    /// //Encryption with a full carry buffer
    /// let large_msg = 7;
    /// let ct_3 = cks.unchecked_encrypt(large_msg);
    ///
    /// //  Check if we can perform a multiplication
    /// let res = sks.is_mul_small_carry_possible(ct_1.noise_degree(), ct_3.noise_degree());
    ///
    /// assert!(res.is_err());
    /// ```
    pub fn is_mul_small_carry_possible(
        &self,
        ct_left: CiphertextNoiseDegree,
        ct_right: CiphertextNoiseDegree,
    ) -> Result<(), CheckError> {
        // Check if an addition is possible
        self.is_add_possible(ct_left, ct_right)?;
        self.is_sub_possible(ct_left, ct_right)?;
        Ok(())
    }

    /// Compute homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// The operation is done using a small carry buffer.
    ///
    /// If the operation can be performed, a _new_ ciphertext with the result of the
    /// multiplication is returned. Otherwise a [CheckError] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let msg_2 = 3;
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(msg_1);
    /// let ct_2 = cks.encrypt(msg_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.checked_mul_lsb_with_small_carry(&ct_1, &ct_2).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(clear_res % modulus, (msg_1 * msg_2) % modulus);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(msg_1);
    /// let ct_2 = cks.encrypt(msg_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.checked_mul_lsb_with_small_carry(&ct_1, &ct_2).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(clear_res % modulus, (msg_1 * msg_2) % modulus);
    /// ```
    pub fn checked_mul_lsb_with_small_carry(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        self.is_mul_small_carry_possible(ct_left.noise_degree(), ct_right.noise_degree())?;
        let mut ct_result = self.unchecked_mul_lsb_small_carry(ct_left, ct_right);
        ct_result.degree = Degree::new(ct_left.degree.get() * 2);
        Ok(ct_result)
    }

    /// Multiply two ciphertexts together
    ///
    /// Return the "least significant bits" of the multiplication, i.e., the result modulus the
    /// message_modulus.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg1 = 12;
    /// let msg2 = 13;
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.unchecked_encrypt(msg1);
    /// // |      ct_left    |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 1  |   0 0   |
    /// let ct_right = cks.unchecked_encrypt(msg2);
    /// // |      ct_right   |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 1  |   0 1   |
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.mul_lsb(&ct_left, &ct_right);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 0   |
    ///
    /// let res = cks.decrypt(&ct_res);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res, (msg1 * msg2) % modulus);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.unchecked_encrypt(msg1);
    /// // |      ct_left    |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 1  |   0 0   |
    /// let ct_right = cks.unchecked_encrypt(msg2);
    /// // |      ct_right   |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 1  |   0 1   |
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.mul_lsb(&ct_left, &ct_right);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 0   |
    ///
    /// let res = cks.decrypt(&ct_res);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res, (msg1 * msg2) % modulus);
    /// ```
    pub fn mul_lsb(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut ct_res = ct_left.clone();
        self.mul_lsb_assign(&mut ct_res, ct_right);
        ct_res
    }

    /// Multiply two ciphertexts together
    ///
    /// Return the "least significant bits" of the multiplication, i.e., the result modulus the
    /// message_modulus.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg1 = 12;
    /// let msg2 = 13;
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.unchecked_encrypt(msg1);
    /// // |      ct_left    |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 1  |   0 0   |
    /// let ct_right = cks.unchecked_encrypt(msg2);
    /// // |      ct_right   |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 1  |   0 1   |
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.mul(&ct_left, &ct_right);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 0   |
    ///
    /// let res = cks.decrypt(&ct_res);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res, (msg1 * msg2) % modulus);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.unchecked_encrypt(msg1);
    /// // |      ct_left    |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 1  |   0 0   |
    /// let ct_right = cks.unchecked_encrypt(msg2);
    /// // |      ct_right   |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 1  |   0 1   |
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.mul(&ct_left, &ct_right);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 0   |
    ///
    /// let res = cks.decrypt(&ct_res);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res, (msg1 * msg2) % modulus);
    /// ```
    pub fn mul(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        self.mul_lsb(ct_left, ct_right)
    }

    /// Multiply two ciphertexts.
    ///
    /// Return the "least significant bits" of the multiplication, i.e., the result modulus the
    /// message_modulus.
    ///
    /// The result is _assigned_ in the first ciphertext
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    ///  # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     V0_11_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    ///     V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64);
    ///
    /// let msg1 = 5;
    /// let msg2 = 3;
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.mul_lsb_assign(&mut ct_1, &ct_2);
    ///
    /// let res = cks.decrypt(&ct_1);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res % modulus, (msg1 * msg2) % modulus);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.mul_lsb_assign(&mut ct_1, &ct_2);
    ///
    /// let res = cks.decrypt(&ct_1);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res % modulus, (msg1 * msg2) % modulus);
    /// ```
    pub fn mul_lsb_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        let tmp_rhs: Ciphertext;

        if !ct_left.carry_is_empty() {
            self.message_extract_assign(ct_left);
        }

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.message_extract(ct_right);
            &tmp_rhs
        };

        if ct_left.message_modulus.0 > ct_left.carry_modulus.0 {
            self.unchecked_mul_lsb_small_carry_modulus_assign(ct_left, rhs);

            self.message_extract_assign(ct_left);
        } else {
            self.unchecked_mul_lsb_assign(ct_left, rhs);
        }
    }

    /// Multiply two ciphertexts.
    ///
    /// Return the "least significant bits" of the multiplication, i.e., the result modulus the
    /// message_modulus.
    ///
    /// The result is _assigned_ in the first ciphertext
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    ///  # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     V0_11_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    ///     V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64);
    ///
    /// let msg1 = 5;
    /// let msg2 = 3;
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.mul_assign(&mut ct_1, &ct_2);
    ///
    /// let res = cks.decrypt(&ct_1);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res % modulus, (msg1 * msg2) % modulus);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.mul_assign(&mut ct_1, &ct_2);
    ///
    /// let res = cks.decrypt(&ct_1);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res % modulus, (msg1 * msg2) % modulus);
    /// ```
    pub fn mul_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        self.mul_lsb_assign(ct_left, ct_right);
    }

    /// Multiply two ciphertexts together
    ///
    /// Return the "most significant bits" of the multiplication, i.e., the part in the carry
    /// buffer.
    ///
    /// The result is _assigned_ in the first ciphertext
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg1 = 12;
    /// let msg2 = 12;
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication:
    /// sks.mul_msb_assign(&mut ct_1, &ct_2);
    ///
    /// let res = cks.decrypt(&ct_1);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res, ((msg1 * msg2) / modulus) % modulus);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication:
    /// sks.mul_msb_assign(&mut ct_1, &ct_2);
    ///
    /// let res = cks.decrypt(&ct_1);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res, ((msg1 * msg2) / modulus) % modulus);
    /// ```
    pub fn mul_msb_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        let tmp_rhs: Ciphertext;

        if !ct_left.carry_is_empty() {
            self.message_extract_assign(ct_left);
        }

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.message_extract(ct_right);
            &tmp_rhs
        };

        self.unchecked_mul_msb_assign(ct_left, rhs);
    }

    /// Multiply two ciphertexts together
    ///
    /// Return the "most significant bits" of the multiplication, i.e., the part in the carry
    /// buffer.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg1 = 12;
    /// let msg2 = 12;
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.unchecked_encrypt(msg1);
    /// let ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.mul_msb(&ct_1, &ct_2);
    ///
    /// let res = cks.decrypt(&ct_res);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res, ((msg1 * msg2) / modulus) % modulus);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.unchecked_encrypt(msg1);
    /// let ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.mul_msb(&ct_1, &ct_2);
    ///
    /// let res = cks.decrypt(&ct_res);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res, ((msg1 * msg2) / modulus) % modulus);
    /// ```
    pub fn mul_msb(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut ct_res = ct_left.clone();
        self.mul_msb_assign(&mut ct_res, ct_right);
        ct_res
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
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     V0_11_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    ///     V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64);
    ///
    /// let msg1 = 5;
    /// let msg2 = 3;
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let mut ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.smart_mul_lsb_assign(&mut ct_1, &mut ct_2);
    ///
    /// let res = cks.decrypt(&ct_1);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res % modulus, (msg1 * msg2) % modulus);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let mut ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.smart_mul_lsb_assign(&mut ct_1, &mut ct_2);
    ///
    /// let res = cks.decrypt(&ct_1);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res % modulus, (msg1 * msg2) % modulus);
    /// ```
    pub fn smart_mul_lsb_assign(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        //Choice of the multiplication algorithm depending on the parameters
        if ct_left.message_modulus.0 > ct_left.carry_modulus.0 {
            //If the ciphertexts cannot be multiplied together without exceeding the capacity of a
            // ciphertext
            if self
                .is_mul_small_carry_possible(ct_left.noise_degree(), ct_right.noise_degree())
                .is_err()
            {
                self.message_extract_assign(ct_left);
                self.message_extract_assign(ct_right);
            }
            self.is_mul_small_carry_possible(ct_left.noise_degree(), ct_right.noise_degree())
                .unwrap();
            self.unchecked_mul_lsb_small_carry_modulus_assign(ct_left, ct_right);
        } else {
            let msg_modulus = ct_left.message_modulus.0;

            self.smart_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| {
                (lhs * rhs) % msg_modulus
            });
        }
    }

    /// Multiply two ciphertexts together
    ///
    /// Return the "most significant bits" of the multiplication, i.e., the part in the carry
    /// buffer.
    ///
    /// The result is _assigned_ in the first ciphertext
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg1 = 12;
    /// let msg2 = 12;
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let mut ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication:
    /// sks.smart_mul_msb_assign(&mut ct_1, &mut ct_2);
    ///
    /// let res = cks.decrypt(&ct_1);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res, ((msg1 * msg2) / modulus) % modulus);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let mut ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication:
    /// sks.smart_mul_msb_assign(&mut ct_1, &mut ct_2);
    ///
    /// let res = cks.decrypt(&ct_1);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res, ((msg1 * msg2) / modulus) % modulus);
    /// ```
    pub fn smart_mul_msb_assign(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        let msg_modulus = ct_left.message_modulus.0;

        self.smart_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| {
            (lhs * rhs) / msg_modulus
        });
    }

    /// Multiply two ciphertexts together
    ///
    /// Return the "least significant bits" of the multiplication, i.e., the result modulus the
    /// message_modulus.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg1 = 12;
    /// let msg2 = 13;
    ///
    /// // Encrypt two messages:
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
    /// assert_eq!(res, (msg1 * msg2) % modulus);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
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
    /// assert_eq!(res, (msg1 * msg2) % modulus);
    /// ```
    pub fn smart_mul_lsb(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        if ct_left.message_modulus.0 > ct_left.carry_modulus.0 {
            //If the ciphertexts cannot be multiplied together without exceeding the capacity of a
            // ciphertext
            if self
                .is_mul_small_carry_possible(ct_left.noise_degree(), ct_right.noise_degree())
                .is_err()
            {
                self.message_extract_assign(ct_left);
                self.message_extract_assign(ct_right);
            }

            self.is_mul_small_carry_possible(ct_left.noise_degree(), ct_right.noise_degree())
                .unwrap();

            self.unchecked_mul_lsb_small_carry_modulus(ct_left, ct_right)
        } else {
            let msg_modulus = ct_left.message_modulus.0;

            self.smart_evaluate_bivariate_function(ct_left, ct_right, |lhs, rhs| {
                (lhs * rhs) % msg_modulus
            })
        }
    }

    /// Multiply two ciphertexts together
    ///
    /// Return the "most significant bits" of the multiplication, i.e., the part in the carry
    /// buffer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg1 = 12;
    /// let msg2 = 12;
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let mut ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.smart_mul_msb(&mut ct_1, &mut ct_2);
    ///
    /// let res = cks.decrypt(&ct_res);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res, ((msg1 * msg2) / modulus) % modulus);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.unchecked_encrypt(msg1);
    /// let mut ct_2 = cks.unchecked_encrypt(msg2);
    ///
    /// // Compute homomorphically a multiplication:
    /// let ct_res = sks.smart_mul_msb(&mut ct_1, &mut ct_2);
    ///
    /// let res = cks.decrypt(&ct_res);
    /// let modulus = sks.message_modulus.0;
    /// assert_eq!(res, ((msg1 * msg2) / modulus) % modulus);
    /// ```
    pub fn smart_mul_msb(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        let msg_modulus = ct_left.message_modulus.0;
        self.smart_evaluate_bivariate_function(ct_left, ct_right, |lhs, rhs| {
            (lhs * rhs) / msg_modulus
        })
    }
}
