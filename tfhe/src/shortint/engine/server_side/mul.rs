use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{Ciphertext, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_mul_lsb(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct_left.clone();
        self.unchecked_mul_lsb_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_mul_lsb_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<()> {
        if ct_left.degree.0 == 0 || ct_right.degree.0 == 0 {
            // One of the ciphertext is a trivial 0
            self.create_trivial_assign(server_key, ct_left, 0)?;
            return Ok(());
        }

        //Modulus of the msg in the msg bits
        let res_modulus = ct_left.message_modulus.0 as u64;
        self.unchecked_evaluate_bivariate_function_assign(
            server_key,
            ct_left,
            ct_right,
            |x, y| (x * y) % res_modulus,
        )?;
        Ok(())
    }

    pub(crate) fn unchecked_mul_msb(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct_left.clone();
        self.unchecked_mul_msb_assign(server_key, &mut result, ct_right)?;

        Ok(result)
    }

    pub(crate) fn unchecked_mul_msb_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<()> {
        if ct_left.degree.0 == 0 || ct_right.degree.0 == 0 {
            // One of the ciphertext is a trivial 0
            self.create_trivial_assign(server_key, ct_left, 0)?;
            return Ok(());
        }

        // Modulus of the msg in the msg bits
        let res_modulus = server_key.message_modulus.0 as u64;
        self.unchecked_evaluate_bivariate_function_assign(
            server_key,
            ct_left,
            ct_right,
            |x, y| (x * y) / res_modulus,
        )?;
        Ok(())
    }

    pub(crate) fn unchecked_mul_lsb_small_carry_modulus(
        &mut self,
        server_key: &ServerKey,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        // ct1 + ct2
        let mut ct_add = self.unchecked_add(ct1, ct2)?;

        // ct1 - ct2
        let (mut ct_sub, z) = self.unchecked_sub_with_correcting_term(server_key, ct1, ct2)?;

        //Modulus of the msg in the msg bits
        let modulus = ct1.message_modulus.0 as u64;

        let acc_add =
            self.generate_lookup_table(server_key, |x| ((x.wrapping_mul(x)) / 4) % modulus)?;
        let acc_sub = self.generate_lookup_table(server_key, |x| {
            (((x.wrapping_sub(z)).wrapping_mul(x.wrapping_sub(z))) / 4) % modulus
        })?;

        self.apply_lookup_table_assign(server_key, &mut ct_add, &acc_add)?;
        self.apply_lookup_table_assign(server_key, &mut ct_sub, &acc_sub)?;

        //Last subtraction might fill one bit of carry
        self.unchecked_sub(server_key, &ct_add, &ct_sub)
    }

    pub(crate) fn unchecked_mul_lsb_small_carry_modulus_assign(
        &mut self,
        server_key: &ServerKey,
        ct1: &mut Ciphertext,
        ct2: &Ciphertext,
    ) -> EngineResult<()> {
        *ct1 = self.unchecked_mul_lsb_small_carry_modulus(server_key, ct1, ct2)?;
        Ok(())
    }

    pub(crate) fn smart_mul_lsb_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<()> {
        //Choice of the multiplication algorithm depending on the parameters
        if ct_left.message_modulus.0 > ct_left.carry_modulus.0 {
            //If the ciphertexts cannot be multiplied together without exceeding the capacity of a
            // ciphertext
            if !server_key.is_mul_small_carry_possible(ct_left, ct_right) {
                self.message_extract_assign(server_key, ct_left)?;
                self.message_extract_assign(server_key, ct_right)?;
            }
            assert!(server_key.is_mul_small_carry_possible(ct_left, ct_right));
            self.unchecked_mul_lsb_small_carry_modulus_assign(server_key, ct_left, ct_right)?;
        } else {
            //If the ciphertexts cannot be multiplied together without exceeding the capacity of a
            // ciphertext
            if !server_key.is_mul_possible(ct_left, ct_right) {
                if (server_key.message_modulus.0 - 1) * ct_right.degree.0
                    < (ct_right.carry_modulus.0 * ct_right.message_modulus.0 - 1)
                {
                    self.message_extract_assign(server_key, ct_left)?;
                } else if (server_key.message_modulus.0 - 1) + ct_left.degree.0
                    < (ct_right.carry_modulus.0 * ct_right.message_modulus.0 - 1)
                {
                    self.message_extract_assign(server_key, ct_right)?;
                } else {
                    self.message_extract_assign(server_key, ct_left)?;
                    self.message_extract_assign(server_key, ct_right)?;
                }
            }
            assert!(server_key.is_mul_possible(ct_left, ct_right));
            self.unchecked_mul_lsb_assign(server_key, ct_left, ct_right)?;
        }
        Ok(())
    }

    pub(crate) fn smart_mul_lsb(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<Ciphertext> {
        if ct_left.message_modulus.0 > ct_left.carry_modulus.0 {
            //If the ciphertexts cannot be multiplied together without exceeding the capacity of a
            // ciphertext
            if !server_key.is_mul_small_carry_possible(ct_left, ct_right) {
                self.message_extract_assign(server_key, ct_left)?;
                self.message_extract_assign(server_key, ct_right)?;
            }

            assert!(server_key.is_mul_small_carry_possible(ct_left, ct_right));

            self.unchecked_mul_lsb_small_carry_modulus(server_key, ct_left, ct_right)
        } else {
            //If the ciphertexts cannot be multiplied together without exceeding the capacity of a
            // ciphertext
            if !server_key.is_mul_possible(ct_left, ct_right) {
                if (server_key.message_modulus.0 - 1) * ct_right.degree.0
                    < (ct_right.carry_modulus.0 * ct_right.message_modulus.0 - 1)
                {
                    self.message_extract_assign(server_key, ct_left)?;
                } else if (server_key.message_modulus.0 - 1) + ct_left.degree.0
                    < (ct_right.carry_modulus.0 * ct_right.message_modulus.0 - 1)
                {
                    self.message_extract_assign(server_key, ct_right)?;
                } else {
                    self.message_extract_assign(server_key, ct_left)?;
                    self.message_extract_assign(server_key, ct_right)?;
                }
            }

            assert!(server_key.is_mul_possible(ct_left, ct_right));

            self.unchecked_mul_lsb(server_key, ct_left, ct_right)
        }
    }

    pub(crate) fn smart_mul_msb_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<()> {
        if !server_key.is_mul_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }

        assert!(server_key.is_mul_possible(ct_left, ct_right));

        self.unchecked_mul_msb_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    // by convention smart operations take mut refs to their inputs, even if they do not modify them
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn smart_mul_msb(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct_left.clone();
        self.smart_mul_msb_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }
}
