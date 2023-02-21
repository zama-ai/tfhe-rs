use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{CiphertextBase, PBSOrderMarker, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_scalar_right_shift<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &CiphertextBase<OpOrder>,
        shift: u8,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct.clone();
        self.unchecked_scalar_right_shift_assign(server_key, &mut result, shift)?;
        Ok(result)
    }

    pub(crate) fn unchecked_scalar_right_shift_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextBase<OpOrder>,
        shift: u8,
    ) -> EngineResult<()> {
        let acc = self.generate_accumulator(server_key, |x| x >> shift)?;
        self.apply_lookup_table_assign(server_key, ct, &acc)?;

        ct.degree = Degree(ct.degree.0 >> shift);
        Ok(())
    }

    pub(crate) fn unchecked_scalar_left_shift<OpOrder: PBSOrderMarker>(
        &mut self,
        ct: &CiphertextBase<OpOrder>,
        shift: u8,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct.clone();
        self.unchecked_scalar_left_shift_assign(&mut result, shift)?;
        Ok(result)
    }

    pub(crate) fn unchecked_scalar_left_shift_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        ct: &mut CiphertextBase<OpOrder>,
        shift: u8,
    ) -> EngineResult<()> {
        let scalar = 1_u8 << shift;
        self.unchecked_scalar_mul_assign(ct, scalar)?;
        Ok(())
    }

    pub(crate) fn smart_scalar_left_shift<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextBase<OpOrder>,
        shift: u8,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct.clone();
        self.smart_scalar_left_shift_assign(server_key, &mut result, shift)?;
        Ok(result)
    }

    pub(crate) fn smart_scalar_left_shift_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextBase<OpOrder>,
        shift: u8,
    ) -> EngineResult<()> {
        if server_key.is_scalar_left_shift_possible(ct, shift) {
            self.unchecked_scalar_left_shift_assign(ct, shift)?;
        } else {
            let modulus = server_key.message_modulus.0 as u64;
            let acc = self.generate_accumulator(server_key, |x| (x << shift) % modulus)?;
            self.apply_lookup_table_assign(server_key, ct, &acc)?;
            ct.degree = ct.degree.after_left_shift(shift, modulus as usize);
        }
        Ok(())
    }
}
