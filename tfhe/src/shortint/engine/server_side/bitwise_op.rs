use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{Ciphertext, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_bitand(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct_left.clone();
        self.unchecked_bitand_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_bitand_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;
        self.unchecked_functional_bivariate_pbs_assign(server_key, ct_left, ct_right, |x| {
            ((x / modulus) & (x % modulus))
        })?;
        ct_left.degree = ct_left.degree.after_bitand(ct_right.degree);
        Ok(())
    }

    pub(crate) fn smart_bitand(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct_left.clone();
        self.smart_bitand_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_bitand_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_bitand_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_bitxor(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct_left.clone();
        self.unchecked_bitxor_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_bitxor_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;
        self.unchecked_functional_bivariate_pbs_assign(server_key, ct_left, ct_right, |x| {
            ((x / modulus) ^ (x % modulus))
        })?;
        ct_left.degree = ct_left.degree.after_bitxor(ct_right.degree);
        Ok(())
    }

    pub(crate) fn smart_bitxor(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct_left.clone();
        self.smart_bitxor_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_bitxor_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_bitxor_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_bitor(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct_left.clone();
        self.unchecked_bitor_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_bitor_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;
        self.unchecked_functional_bivariate_pbs_assign(server_key, ct_left, ct_right, |x| {
            ((x / modulus) | (x % modulus))
        })?;
        ct_left.degree = ct_left.degree.after_bitor(ct_right.degree);
        Ok(())
    }

    pub(crate) fn smart_bitor(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct_left.clone();
        self.smart_bitor_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_bitor_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_bitor_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }
}
