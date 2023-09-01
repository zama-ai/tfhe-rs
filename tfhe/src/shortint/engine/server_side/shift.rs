use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{Ciphertext, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_scalar_right_shift(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
        shift: u8,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct.clone();
        self.unchecked_scalar_right_shift_assign(server_key, &mut result, shift)?;
        Ok(result)
    }

    pub(crate) fn unchecked_scalar_right_shift_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        shift: u8,
    ) -> EngineResult<()> {
        let acc = self.generate_lookup_table(server_key, |x| x >> shift)?;
        self.apply_lookup_table_assign(server_key, ct, &acc)?;

        Ok(())
    }

    pub(crate) fn unchecked_scalar_left_shift(
        &mut self,
        ct: &Ciphertext,
        shift: u8,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct.clone();
        self.unchecked_scalar_left_shift_assign(&mut result, shift)?;
        Ok(result)
    }

    pub(crate) fn unchecked_scalar_left_shift_assign(
        &mut self,
        ct: &mut Ciphertext,
        shift: u8,
    ) -> EngineResult<()> {
        let scalar = 1_u8 << shift;
        self.unchecked_scalar_mul_assign(ct, scalar)?;
        Ok(())
    }

    pub(crate) fn smart_scalar_left_shift(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        shift: u8,
    ) -> EngineResult<Ciphertext> {
        if !server_key.is_scalar_left_shift_possible(ct, shift) {
            self.message_extract_assign(server_key, ct)?;
        }
        let mut result = ct.clone();
        self.smart_scalar_left_shift_assign(server_key, &mut result, shift)?;
        Ok(result)
    }

    pub(crate) fn smart_scalar_left_shift_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        shift: u8,
    ) -> EngineResult<()> {
        if server_key.is_scalar_left_shift_possible(ct, shift) {
            self.unchecked_scalar_left_shift_assign(ct, shift)?;
        } else {
            let modulus = server_key.message_modulus.0 as u64;
            let acc = self.generate_lookup_table(server_key, |x| (x << shift) % modulus)?;
            self.apply_lookup_table_assign(server_key, ct, &acc)?;
        }
        Ok(())
    }
}
