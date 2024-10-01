use super::CiphertextNoiseDegree;
use crate::shortint::ciphertext::Degree;
use crate::shortint::server_key::scalar_mul::unchecked_scalar_mul_assign;
use crate::shortint::server_key::CheckError;
use crate::shortint::{Ciphertext, ServerKey};

impl ServerKey {
    /// Compute homomorphically a right shift of the bits.
    ///
    /// This returns a new ciphertext.
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
    /// let msg = 2;
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Compute homomorphically a right shift
    /// let shift: u8 = 1;
    /// let ct_res = sks.scalar_right_shift(&ct, shift);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(msg >> shift, dec);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Compute homomorphically a right shift
    /// let shift: u8 = 1;
    /// let ct_res = sks.scalar_right_shift(&ct, shift);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn scalar_right_shift(&self, ct: &Ciphertext, shift: u8) -> Ciphertext {
        let mut ct_res = ct.clone();
        self.scalar_right_shift_assign(&mut ct_res, shift);
        ct_res
    }

    /// Compute homomorphically a right shift of the bits.
    ///
    /// This stores the result in `ct`.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 2;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Compute homomorphically a right shift
    /// let shift: u8 = 1;
    /// sks.scalar_right_shift_assign(&mut ct, shift);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg >> shift, dec);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Compute homomorphically a right shift
    /// let shift: u8 = 1;
    /// sks.scalar_right_shift_assign(&mut ct, shift);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn scalar_right_shift_assign(&self, ct: &mut Ciphertext, shift: u8) {
        let acc = self.generate_msg_lookup_table(|x| x >> shift, self.message_modulus);
        self.apply_lookup_table_assign(ct, &acc);
    }

    /// Compute homomorphically a right shift of the bits without checks.
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
    /// let msg = 2;
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Compute homomorphically a right shift
    /// let shift: u8 = 1;
    /// let ct_res = sks.unchecked_scalar_right_shift(&ct, shift);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(msg >> shift, dec);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Compute homomorphically a right shift
    /// let shift: u8 = 1;
    /// let ct_res = sks.unchecked_scalar_right_shift(&ct, shift);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn unchecked_scalar_right_shift(&self, ct: &Ciphertext, shift: u8) -> Ciphertext {
        let mut result = ct.clone();
        self.unchecked_scalar_right_shift_assign(&mut result, shift);
        result
    }

    /// Compute homomorphically a right shift of the bits without checks.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 2;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Compute homomorphically a right shift
    /// let shift: u8 = 1;
    /// sks.unchecked_scalar_right_shift_assign(&mut ct, shift);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg >> shift, dec);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Compute homomorphically a right shift
    /// let shift: u8 = 1;
    /// sks.unchecked_scalar_right_shift_assign(&mut ct, shift);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn unchecked_scalar_right_shift_assign(&self, ct: &mut Ciphertext, shift: u8) {
        let acc = self.generate_msg_lookup_table(|x| x >> shift, ct.message_modulus);
        self.apply_lookup_table_assign(ct, &acc);

        ct.degree = Degree::new(ct.degree.get() >> shift);
    }

    /// Compute homomorphically a left shift of the bits.
    ///
    /// This returns a new ciphertext.
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
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 1;
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// let shift: u8 = 1;
    /// let ct_res = sks.scalar_left_shift(&ct, shift);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Decrypt:
    /// let msg_only = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// assert_eq!((msg << shift) % modulus, msg_only);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// let shift: u8 = 1;
    /// let ct_res = sks.scalar_left_shift(&ct, shift);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Decrypt:
    /// let msg_only = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// assert_eq!((msg << shift) % modulus, msg_only);
    /// ```
    pub fn scalar_left_shift(&self, ct: &Ciphertext, shift: u8) -> Ciphertext {
        let mut ct_res = ct.clone();
        self.scalar_left_shift_assign(&mut ct_res, shift);
        ct_res
    }

    /// Compute homomorphically a left shift of the bits.
    ///
    /// This writes the result in `ct`.
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
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 1;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// let shift: u8 = 1;
    /// sks.scalar_left_shift_assign(&mut ct, shift);
    /// // |      ct         |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Decrypt:
    /// let msg_only = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// assert_eq!((msg << shift) % modulus, msg_only);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// let shift: u8 = 1;
    /// sks.scalar_left_shift_assign(&mut ct, shift);
    /// // |      ct         |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Decrypt:
    /// let msg_only = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// assert_eq!((msg << shift) % modulus, msg_only);
    /// ```
    pub fn scalar_left_shift_assign(&self, ct: &mut Ciphertext, shift: u8) {
        let modulus = self.message_modulus.0;
        let acc = self.generate_lookup_table(|x| (x << shift) % modulus);
        self.apply_lookup_table_assign(ct, &acc);
    }

    /// Compute homomorphically a left shift of the bits without checks.
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
    /// let msg = 2;
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Compute homomorphically a left shift
    /// let shift: u8 = 1;
    /// let ct_res = sks.unchecked_scalar_left_shift(&ct, shift);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 1  |   0 0   |
    ///
    /// // Decrypt:
    /// let msg_and_carry = cks.decrypt_message_and_carry(&ct_res);
    /// let msg_only = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// assert_eq!(msg << shift, msg_and_carry);
    /// assert_eq!((msg << shift) % modulus, msg_only);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Compute homomorphically a left shift
    /// let shift: u8 = 1;
    /// let ct_res = sks.unchecked_scalar_left_shift(&ct, shift);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 1  |   0 0   |
    ///
    /// // Decrypt:
    /// let msg_and_carry = cks.decrypt_message_and_carry(&ct_res);
    /// let msg_only = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// assert_eq!(msg << shift, msg_and_carry);
    /// assert_eq!((msg << shift) % modulus, msg_only);
    /// ```
    pub fn unchecked_scalar_left_shift(&self, ct: &Ciphertext, shift: u8) -> Ciphertext {
        let mut result = ct.clone();
        self.unchecked_scalar_left_shift_assign(&mut result, shift);
        result
    }
    /// Compute homomorphically a left shift of the bits without checks
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 2;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Compute homomorphically a left shift
    /// let shift: u8 = 1;
    /// sks.unchecked_scalar_left_shift_assign(&mut ct, shift);
    /// // |      ct     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 1  |   0 0   |
    ///
    /// // Decrypt:
    /// let msg_and_carry = cks.decrypt_message_and_carry(&ct);
    /// let msg_only = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// assert_eq!(msg << shift, msg_and_carry);
    /// assert_eq!((msg << shift) % modulus, msg_only);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Compute homomorphically a left shift
    /// let shift: u8 = 1;
    /// sks.unchecked_scalar_left_shift_assign(&mut ct, shift);
    /// // |      ct     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 1  |   0 0   |
    ///
    /// // Decrypt:
    /// let msg_and_carry = cks.decrypt_message_and_carry(&ct);
    /// let msg_only = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// assert_eq!(msg << shift, msg_and_carry);
    /// assert_eq!((msg << shift) % modulus, msg_only);
    /// ```
    pub fn unchecked_scalar_left_shift_assign(&self, ct: &mut Ciphertext, shift: u8) {
        let scalar = 1_u8 << shift;
        unchecked_scalar_mul_assign(ct, scalar, self.max_noise_level);
    }

    /// Checks if the left shift operation can be applied.
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
    /// let shift = 5;
    ///
    /// // Encrypt a message
    /// let ct1 = cks.encrypt(msg);
    ///
    /// // Check if we can perform an addition
    /// let res = sks.is_scalar_left_shift_possible(ct1.noise_degree(), shift);
    ///
    /// assert!(res.is_err());
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let ct1 = cks.encrypt(msg);
    ///
    /// // Check if we can perform an addition
    /// let res = sks.is_scalar_left_shift_possible(ct1.noise_degree(), shift);
    ///
    /// assert!(res.is_err());
    /// ```
    pub fn is_scalar_left_shift_possible(
        &self,
        ct1: CiphertextNoiseDegree,
        shift: u8,
    ) -> Result<(), CheckError> {
        let final_operation_count = ct1.degree.get() << shift as usize;

        self.max_degree
            .validate(Degree::new(final_operation_count))?;

        self.max_noise_level
            .validate(ct1.noise_level * (1 << shift))?;

        Ok(())
    }

    /// Compute homomorphically a left shift of the bits.
    ///
    /// If the operation can be performed, a new ciphertext with the result is returned.
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
    /// let msg = 2;
    ///
    /// // Encrypt a message
    /// let ct1 = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Shifting 3 times is not ok, as it exceeds the carry buffer
    /// let ct_res = sks.checked_scalar_left_shift(&ct1, 3);
    /// assert!(ct_res.is_err());
    ///
    /// // Shifting 2 times is ok
    /// let shift = 2;
    /// let ct_res = sks.checked_scalar_left_shift(&ct1, shift).unwrap();
    ///
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 0  |   0 0   |
    ///
    /// // Decrypt:
    /// let msg_and_carry = cks.decrypt_message_and_carry(&ct_res);
    /// let msg_only = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// assert_eq!(msg << shift, msg_and_carry);
    /// assert_eq!((msg << shift) % modulus, msg_only);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let ct1 = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Shifting 3 times is not ok, as it exceeds the carry buffer
    /// let ct_res = sks.checked_scalar_left_shift(&ct1, 3);
    /// assert!(ct_res.is_err());
    ///
    /// // Shifting 2 times is ok
    /// let shift = 2;
    /// let ct_res = sks.checked_scalar_left_shift(&ct1, shift).unwrap();
    ///
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 0  |   0 0   |
    ///
    /// // Decrypt:
    /// let msg_and_carry = cks.decrypt_message_and_carry(&ct_res);
    /// let msg_only = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// assert_eq!(msg << shift, msg_and_carry);
    /// assert_eq!((msg << shift) % modulus, msg_only);
    /// ```
    pub fn checked_scalar_left_shift(
        &self,
        ct: &Ciphertext,
        shift: u8,
    ) -> Result<Ciphertext, CheckError> {
        self.is_scalar_left_shift_possible(ct.noise_degree(), shift)?;
        let ct_result = self.unchecked_scalar_left_shift(ct, shift);
        Ok(ct_result)
    }

    pub fn checked_scalar_left_shift_assign(
        &self,
        ct: &mut Ciphertext,
        shift: u8,
    ) -> Result<(), CheckError> {
        self.is_scalar_left_shift_possible(ct.noise_degree(), shift)?;
        self.unchecked_scalar_left_shift_assign(ct, shift);
        Ok(())
    }

    /// Compute homomorphically a left shift of the bits
    ///
    /// This checks that the operation is possible. In the case where the carry buffers are
    /// full, then it is automatically cleared to allow the operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 2;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// let shift: u8 = 1;
    /// let ct_res = sks.smart_scalar_left_shift(&mut ct, shift);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 1  |   0 0   |
    ///
    /// // Decrypt:
    /// let msg_and_carry = cks.decrypt_message_and_carry(&ct_res);
    /// let msg_only = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// assert_eq!(msg << shift, msg_and_carry);
    /// assert_eq!((msg << shift) % modulus, msg_only);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// let shift: u8 = 1;
    /// let ct_res = sks.smart_scalar_left_shift(&mut ct, shift);
    /// // |      ct_res     |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 1  |   0 0   |
    ///
    /// // Decrypt:
    /// let msg_and_carry = cks.decrypt_message_and_carry(&ct_res);
    /// let msg_only = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    ///
    /// assert_eq!(msg << shift, msg_and_carry);
    /// assert_eq!((msg << shift) % modulus, msg_only);
    /// ```
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub fn smart_scalar_left_shift(&self, ct: &mut Ciphertext, shift: u8) -> Ciphertext {
        let mut result = ct.clone();
        self.smart_scalar_left_shift_assign(&mut result, shift);
        result
    }

    pub fn smart_scalar_left_shift_assign(&self, ct: &mut Ciphertext, shift: u8) {
        if self
            .is_scalar_left_shift_possible(ct.noise_degree(), shift)
            .is_ok()
        {
            self.unchecked_scalar_left_shift_assign(ct, shift);
        } else {
            let modulus = self.message_modulus.0;
            let acc = self.generate_msg_lookup_table(|x| x << shift, self.message_modulus);
            self.apply_lookup_table_assign(ct, &acc);
            ct.degree = ct.degree.after_left_shift(shift, modulus);
        }
    }
}
