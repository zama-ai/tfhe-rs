use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{CiphertextBase, PBSOrderMarker, ServerKey};

// Specific division function returning 0 in case of a division by 0
pub(crate) fn safe_division(x: u64, y: u64) -> u64 {
    if y == 0 {
        0
    } else {
        x / y
    }
}

impl ShortintEngine {
    pub(crate) fn unchecked_div<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.unchecked_div_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_div_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        self.unchecked_evaluate_bivariate_function_assign(
            server_key,
            ct_left,
            ct_right,
            safe_division,
        )?;
        Ok(())
    }

    pub(crate) fn smart_div<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_div_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_div_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
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
    pub(crate) fn unchecked_scalar_div<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct.clone();
        self.unchecked_scalar_div_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    /// # Panics
    ///
    /// This function will panic if `scalar == 0`
    pub(crate) fn unchecked_scalar_div_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<()> {
        assert_ne!(scalar, 0);
        //generate the accumulator for the multiplication
        let acc = self.generate_accumulator(server_key, |x| x / (scalar as u64))?;
        self.apply_lookup_table_assign(server_key, ct, &acc)?;
        ct.degree = Degree(ct.degree.0 / scalar as usize);
        Ok(())
    }

    pub(crate) fn unchecked_scalar_mod<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &CiphertextBase<OpOrder>,
        modulus: u8,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct.clone();
        self.unchecked_scalar_mod_assign(server_key, &mut result, modulus)?;
        Ok(result)
    }

    /// # Panics
    ///
    /// This function will panic if `modulus == 0`
    pub(crate) fn unchecked_scalar_mod_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextBase<OpOrder>,
        modulus: u8,
    ) -> EngineResult<()> {
        assert_ne!(modulus, 0);
        let acc = self.generate_accumulator(server_key, |x| x % modulus as u64)?;
        self.apply_lookup_table_assign(server_key, ct, &acc)?;
        ct.degree = Degree(modulus as usize - 1);
        Ok(())
    }
}
