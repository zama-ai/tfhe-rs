use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{CiphertextBase, PBSOrderMarker, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_greater<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.unchecked_greater_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    fn unchecked_greater_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        self.unchecked_evaluate_bivariate_function_assign(
            server_key,
            ct_left,
            ct_right,
            |lhs, rhs| u64::from(lhs > rhs),
        )?;
        Ok(())
    }

    pub(crate) fn smart_greater<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_greater_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_greater_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }

        self.unchecked_greater_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_greater_or_equal<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.unchecked_greater_or_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    fn unchecked_greater_or_equal_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        self.unchecked_evaluate_bivariate_function_assign(
            server_key,
            ct_left,
            ct_right,
            |lhs, rhs| u64::from(lhs >= rhs),
        )?;
        Ok(())
    }

    pub(crate) fn smart_greater_or_equal<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_greater_or_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_greater_or_equal_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_greater_or_equal_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_less<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.unchecked_less_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    fn unchecked_less_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        self.unchecked_evaluate_bivariate_function_assign(
            server_key,
            ct_left,
            ct_right,
            |lhs, rhs| u64::from(lhs < rhs),
        )?;
        Ok(())
    }

    pub(crate) fn smart_less<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_less_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_less_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_less_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_less_or_equal<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.unchecked_less_or_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    fn unchecked_less_or_equal_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        self.unchecked_evaluate_bivariate_function_assign(
            server_key,
            ct_left,
            ct_right,
            |lhs, rhs| u64::from(lhs <= rhs),
        )?;
        Ok(())
    }

    pub(crate) fn smart_less_or_equal<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_less_or_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_less_or_equal_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_less_or_equal_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_equal<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.unchecked_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    fn unchecked_equal_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        self.unchecked_evaluate_bivariate_function_assign(
            server_key,
            ct_left,
            ct_right,
            |lhs, rhs| u64::from(lhs == rhs),
        )?;
        Ok(())
    }

    pub(crate) fn smart_equal<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_equal_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_equal_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn smart_scalar_equal<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_scalar_equal_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    fn smart_scalar_equal_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<()> {
        let modulus = ct_left.message_modulus.0 as u64;
        let acc =
            self.generate_accumulator(server_key, |x| (x % modulus == scalar as u64) as u64)?;
        self.apply_lookup_table_assign(server_key, ct_left, &acc)?;
        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn unchecked_not_equal<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.unchecked_not_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    fn unchecked_not_equal_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        self.unchecked_evaluate_bivariate_function_assign(
            server_key,
            ct_left,
            ct_right,
            |lhs, rhs| u64::from(lhs != rhs),
        )?;
        Ok(())
    }

    pub(crate) fn smart_not_equal<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_not_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_not_equal_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_not_equal_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn smart_scalar_not_equal<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_scalar_not_equal_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    fn smart_scalar_not_equal_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<()> {
        let modulus = ct_left.message_modulus.0 as u64;
        let acc =
            self.generate_accumulator(server_key, |x| (x % modulus != scalar as u64) as u64)?;
        self.apply_lookup_table_assign(server_key, ct_left, &acc)?;
        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_scalar_greater_or_equal<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_scalar_greater_or_equal_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    fn smart_scalar_greater_or_equal_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<()> {
        let acc = self.generate_accumulator(server_key, |x| (x >= scalar as u64) as u64)?;
        self.apply_lookup_table_assign(server_key, ct_left, &acc)?;
        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_scalar_less_or_equal<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_scalar_less_or_equal_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    fn smart_scalar_less_or_equal_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<()> {
        let acc = self.generate_accumulator(server_key, |x| (x <= scalar as u64) as u64)?;
        self.apply_lookup_table_assign(server_key, ct_left, &acc)?;
        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_scalar_greater<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_scalar_greater_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    fn smart_scalar_greater_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<()> {
        let acc = self.generate_accumulator(server_key, |x| (x > scalar as u64) as u64)?;
        self.apply_lookup_table_assign(server_key, ct_left, &acc)?;
        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_scalar_less<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_scalar_less_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    fn smart_scalar_less_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> EngineResult<()> {
        let acc = self.generate_accumulator(server_key, |x| (x < scalar as u64) as u64)?;
        self.apply_lookup_table_assign(server_key, ct_left, &acc)?;
        ct_left.degree.0 = 1;
        Ok(())
    }
}
