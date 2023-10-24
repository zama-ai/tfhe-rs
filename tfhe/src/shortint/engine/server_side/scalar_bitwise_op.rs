use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{Ciphertext, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_scalar_bitand(
        &mut self,
        server_key: &ServerKey,
        lhs: &Ciphertext,
        rhs: u8,
    ) -> EngineResult<Ciphertext> {
        let mut result = lhs.clone();
        self.unchecked_scalar_bitand_assign(server_key, &mut result, rhs)?;
        Ok(result)
    }

    pub(crate) fn unchecked_scalar_bitand_assign(
        &mut self,
        server_key: &ServerKey,
        lhs: &mut Ciphertext,
        rhs: u8,
    ) -> EngineResult<()> {
        let lut =
            self.generate_msg_lookup_table(server_key, |x| x & rhs as u64, lhs.message_modulus)?;
        self.apply_lookup_table_assign(server_key, lhs, &lut)?;
        Ok(())
    }

    // by convention smart operations take mut refs to their inputs, even if they do not modify them
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn smart_scalar_bitand(
        &mut self,
        server_key: &ServerKey,
        lhs: &mut Ciphertext,
        rhs: u8,
    ) -> EngineResult<Ciphertext> {
        let mut result = lhs.clone();
        self.smart_scalar_bitand_assign(server_key, &mut result, rhs)?;
        Ok(result)
    }

    pub(crate) fn smart_scalar_bitand_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: u8,
    ) -> EngineResult<()> {
        self.unchecked_scalar_bitand_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_scalar_bitxor(
        &mut self,
        server_key: &ServerKey,
        lhs: &Ciphertext,
        rhs: u8,
    ) -> EngineResult<Ciphertext> {
        let mut result = lhs.clone();
        self.unchecked_scalar_bitxor_assign(server_key, &mut result, rhs)?;
        Ok(result)
    }

    pub(crate) fn unchecked_scalar_bitxor_assign(
        &mut self,
        server_key: &ServerKey,
        lhs: &mut Ciphertext,
        rhs: u8,
    ) -> EngineResult<()> {
        let lut =
            self.generate_msg_lookup_table(server_key, |x| x ^ rhs as u64, lhs.message_modulus)?;
        self.apply_lookup_table_assign(server_key, lhs, &lut)?;
        Ok(())
    }

    // by convention smart operations take mut refs to their inputs, even if they do not modify them
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn smart_scalar_bitxor(
        &mut self,
        server_key: &ServerKey,
        lhs: &mut Ciphertext,
        rhs: u8,
    ) -> EngineResult<Ciphertext> {
        let mut result = lhs.clone();
        self.smart_scalar_bitxor_assign(server_key, &mut result, rhs)?;
        Ok(result)
    }

    pub(crate) fn smart_scalar_bitxor_assign(
        &mut self,
        server_key: &ServerKey,
        lhs: &mut Ciphertext,
        rhs: u8,
    ) -> EngineResult<()> {
        self.unchecked_scalar_bitxor_assign(server_key, lhs, rhs)?;
        Ok(())
    }

    pub(crate) fn unchecked_scalar_bitor(
        &mut self,
        server_key: &ServerKey,
        lhs: &Ciphertext,
        rhs: u8,
    ) -> EngineResult<Ciphertext> {
        let mut result = lhs.clone();
        self.unchecked_scalar_bitor_assign(server_key, &mut result, rhs)?;
        Ok(result)
    }

    pub(crate) fn unchecked_scalar_bitor_assign(
        &mut self,
        server_key: &ServerKey,
        lhs: &mut Ciphertext,
        rhs: u8,
    ) -> EngineResult<()> {
        let lut =
            self.generate_msg_lookup_table(server_key, |x| x | rhs as u64, lhs.message_modulus)?;
        self.apply_lookup_table_assign(server_key, lhs, &lut)?;
        Ok(())
    }

    // by convention smart operations take mut refs to their inputs, even if they do not modify them
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn smart_scalar_bitor(
        &mut self,
        server_key: &ServerKey,
        lhs: &mut Ciphertext,
        rhs: u8,
    ) -> EngineResult<Ciphertext> {
        let mut result = lhs.clone();
        self.smart_scalar_bitor_assign(server_key, &mut result, rhs)?;
        Ok(result)
    }

    pub(crate) fn smart_scalar_bitor_assign(
        &mut self,
        server_key: &ServerKey,
        lhs: &mut Ciphertext,
        rhs: u8,
    ) -> EngineResult<()> {
        self.unchecked_scalar_bitor_assign(server_key, lhs, rhs)?;
        Ok(())
    }
}
