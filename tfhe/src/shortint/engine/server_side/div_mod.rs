use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{Ciphertext, ServerKey};

// Specific division function returning value_on_div_by_zero in case of a division by 0
pub(crate) fn safe_division(x: u64, y: u64, value_on_div_by_zero: u64) -> u64 {
    if y == 0 {
        value_on_div_by_zero
    } else {
        x / y
    }
}

impl ShortintEngine {
    pub(crate) fn unchecked_div(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct_left.clone();
        self.unchecked_div_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_div_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<()> {
        let value_on_div_by_zero = (ct_left.message_modulus.0 - 1) as u64;
        self.unchecked_evaluate_bivariate_function_assign(
            server_key,
            ct_left,
            ct_right,
            |x, y| safe_division(x, y, value_on_div_by_zero),
        )?;
        Ok(())
    }

    pub(crate) fn smart_div(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct_left.clone();
        self.smart_div_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_div_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            if ct_left.message_modulus.0 + ct_right.degree.0 <= server_key.max_degree.0 {
                self.message_extract_assign(server_key, ct_left)?;
            } else if ct_right.message_modulus.0 + (ct_left.degree.0 + 1) <= server_key.max_degree.0
            {
                self.message_extract_assign(server_key, ct_right)?;
            } else {
                self.message_extract_assign(server_key, ct_left)?;
                self.message_extract_assign(server_key, ct_right)?;
            }
        }
        self.unchecked_div_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    /// # Panics
    ///
    /// This function will panic if `scalar == 0`
    pub(crate) fn unchecked_scalar_div(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
        scalar: u8,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct.clone();
        self.unchecked_scalar_div_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    /// # Panics
    ///
    /// This function will panic if `scalar == 0`
    pub(crate) fn unchecked_scalar_div_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        scalar: u8,
    ) -> EngineResult<()> {
        assert_ne!(scalar, 0, "attempt to divide by zero");
        let lookup_table = self.generate_lookup_table(server_key, |x| x / (scalar as u64))?;
        self.apply_lookup_table_assign(server_key, ct, &lookup_table)?;
        ct.degree = Degree(ct.degree.0 / scalar as usize);
        Ok(())
    }

    pub(crate) fn unchecked_scalar_mod(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
        modulus: u8,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct.clone();
        self.unchecked_scalar_mod_assign(server_key, &mut result, modulus)?;
        Ok(result)
    }

    /// # Panics
    ///
    /// This function will panic if `modulus == 0`
    pub(crate) fn unchecked_scalar_mod_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        modulus: u8,
    ) -> EngineResult<()> {
        assert_ne!(modulus, 0);
        let acc = self.generate_lookup_table(server_key, |x| x % modulus as u64)?;
        self.apply_lookup_table_assign(server_key, ct, &acc)?;
        ct.degree = Degree(modulus as usize - 1);
        Ok(())
    }
}
