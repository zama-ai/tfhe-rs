use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{CiphertextBase, PBSOrderMarker, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_bitand<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.unchecked_bitand_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_bitand_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        self.unchecked_evaluate_bivariate_function_assign(
            server_key,
            ct_left,
            ct_right,
            |lhs, rhs| lhs & rhs,
        )?;
        ct_left.degree = ct_left.degree.after_bitand(ct_right.degree);
        Ok(())
    }

    pub(crate) fn smart_bitand<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_bitand_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_bitand_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_bitand_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_bitxor<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.unchecked_bitxor_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_bitxor_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        self.unchecked_evaluate_bivariate_function_assign(
            server_key,
            ct_left,
            ct_right,
            |lhs, rhs| lhs ^ rhs,
        )?;
        ct_left.degree = ct_left.degree.after_bitxor(ct_right.degree);
        Ok(())
    }

    pub(crate) fn smart_bitxor<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_bitxor_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_bitxor_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_bitxor_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_bitor<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.unchecked_bitor_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_bitor_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        self.unchecked_evaluate_bivariate_function_assign(
            server_key,
            ct_left,
            ct_right,
            |lhs, rhs| lhs | rhs,
        )?;
        ct_left.degree = ct_left.degree.after_bitor(ct_right.degree);
        Ok(())
    }

    pub(crate) fn smart_bitor<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct_left.clone();
        self.smart_bitor_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_bitor_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_bitor_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }
}
