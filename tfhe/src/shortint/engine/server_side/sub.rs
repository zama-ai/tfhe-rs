use crate::core_crypto::algorithms::*;
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{Ciphertext, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_sub(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct_left.clone();
        self.unchecked_sub_assign(server_key, &mut result, ct_right)?;

        Ok(result)
    }

    pub(crate) fn unchecked_sub_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<()> {
        self.unchecked_sub_assign_with_correcting_term(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_sub_with_correcting_term(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<(Ciphertext, u64)> {
        let mut result = ct_left.clone();
        let z =
            self.unchecked_sub_assign_with_correcting_term(server_key, &mut result, ct_right)?;

        Ok((result, z))
    }

    pub(crate) fn unchecked_sub_assign_with_correcting_term(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> EngineResult<u64> {
        let (neg_right, z) = self.unchecked_neg_with_correcting_term(server_key, ct_right)?;

        lwe_ciphertext_add_assign(&mut ct_left.ct, &neg_right.ct);

        ct_left.degree = Degree(ct_left.degree.0 + z as usize);

        Ok(z)
    }

    pub(crate) fn smart_sub(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<Ciphertext> {
        // If the ciphertext cannot be subtracted together without exceeding the degree max
        if !server_key.is_sub_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_right)?;
            self.message_extract_assign(server_key, ct_left)?;
        }
        self.unchecked_sub(server_key, ct_left, ct_right)
    }

    pub(crate) fn smart_sub_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<()> {
        // If the ciphertext cannot be subtracted together without exceeding the degree max
        if !server_key.is_sub_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_right)?;
            self.message_extract_assign(server_key, ct_left)?;
        }

        self.unchecked_sub_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn smart_sub_with_correcting_term(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> EngineResult<(Ciphertext, u64)> {
        //If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if !server_key.is_sub_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }

        self.unchecked_sub_with_correcting_term(server_key, ct_left, ct_right)
    }
}
