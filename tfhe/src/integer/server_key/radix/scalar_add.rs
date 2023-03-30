use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::server_key::CheckError;
use crate::integer::server_key::CheckError::CarryFull;
use crate::integer::ServerKey;

use crate::shortint::PBSOrderMarker;
impl ServerKey {
    /// Computes homomorphically an addition between a scalar and a ciphertext.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
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
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.unchecked_scalar_add(&ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn unchecked_scalar_add<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) -> RadixCiphertext<PBSOrder> {
        let mut result = ct.clone();
        self.unchecked_scalar_add_assign(&mut result, scalar);
        result
    }

    /// Computes homomorphically an addition between a scalar and a ciphertext.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    pub fn unchecked_scalar_add_assign<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) {
        // Bits of message put to 1
        let mask = (self.key.message_modulus.0 - 1) as u64;

        let mut power = 1_u64;
        // Put each decomposition into a new ciphertext
        for ct_i in ct.blocks.iter_mut() {
            let mut decomp = scalar & (mask * power);
            decomp /= power;

            self.key.unchecked_scalar_add_assign(ct_i, decomp as u8);

            //modulus to the power i
            let Some(new_power) = power.checked_mul(self.key.message_modulus.0 as u64) else {break};
            power = new_power;
        }
    }

    /// Verifies if a scalar can be added to a ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 2u64;
    /// let scalar = 40;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Check if we can perform an addition
    /// let res = sks.is_scalar_add_possible(&ct1, scalar);
    ///
    /// assert_eq!(true, res);
    /// ```
    pub fn is_scalar_add_possible<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) -> bool {
        //Bits of message put to 1
        let mask = (self.key.message_modulus.0 - 1) as u64;

        let mut power = 1_u64;

        for ct_i in ct.blocks.iter() {
            let mut decomp = scalar & (mask * power);
            decomp /= power;

            if !self.key.is_scalar_add_possible(ct_i, decomp as u8) {
                return false;
            }

            //modulus to the power i
            let Some(new_power) = power.checked_mul(self.key.message_modulus.0 as u64) else {break};
            power = new_power;
        }
        true
    }

    /// Computes homomorphically an addition between a scalar and a ciphertext.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.checked_scalar_add(&mut ct, scalar)?;
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + scalar, dec);
    /// # Ok(())
    /// # }
    /// ```
    pub fn checked_scalar_add<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) -> Result<RadixCiphertext<PBSOrder>, CheckError> {
        if self.is_scalar_add_possible(ct, scalar) {
            Ok(self.unchecked_scalar_add(ct, scalar))
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically an addition between a scalar and a ciphertext.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned, and `ct_left` is not modified.
    pub fn checked_scalar_add_assign<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) -> Result<(), CheckError> {
        if self.is_scalar_add_possible(ct, scalar) {
            self.unchecked_scalar_add_assign(ct, scalar);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically the addition of ciphertext with a scalar.
    ///
    /// The result is returned in a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_scalar_add(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn smart_scalar_add<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) -> RadixCiphertext<PBSOrder> {
        if !self.is_scalar_add_possible(ct, scalar) {
            self.full_propagate(ct);
        }

        let mut ct = ct.clone();
        self.unchecked_scalar_add_assign(&mut ct, scalar);
        ct
    }

    /// Computes homomorphically the addition of ciphertext with a scalar.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
    ///
    /// let msg = 129;
    /// let scalar = 40;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// sks.smart_scalar_add_assign(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn smart_scalar_add_assign<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        scalar: u64,
    ) {
        if !self.is_scalar_add_possible(ct, scalar) {
            self.full_propagate(ct);
        }
        self.unchecked_scalar_add_assign(ct, scalar);
    }
}
