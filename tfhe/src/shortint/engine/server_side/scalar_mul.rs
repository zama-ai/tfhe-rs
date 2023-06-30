use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{Ciphertext, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_scalar_mul(
        &mut self,
        ct: &Ciphertext,
        scalar: u8,
    ) -> EngineResult<Ciphertext> {
        let mut ct_result = ct.clone();
        self.unchecked_scalar_mul_assign(&mut ct_result, scalar)?;

        Ok(ct_result)
    }

    pub(crate) fn unchecked_scalar_mul_assign(
        &mut self,
        ct: &mut Ciphertext,
        scalar: u8,
    ) -> EngineResult<()> {
        match scalar {
            0 => {
                trivially_encrypt_lwe_ciphertext(&mut ct.ct, Plaintext(0));
                ct.degree = Degree(0);
            }
            1 => {
                // Multiplication by one is the identidy
            }
            scalar => {
                let scalar = u64::from(scalar);
                let cleartext_scalar = Cleartext(scalar);
                lwe_ciphertext_cleartext_mul_assign(&mut ct.ct, cleartext_scalar);

                ct.degree = Degree(ct.degree.0 * scalar as usize);
            }
        }

        Ok(())
    }

    pub(crate) fn smart_scalar_mul(
        &mut self,
        server_key: &ServerKey,
        ctxt: &mut Ciphertext,
        scalar: u8,
    ) -> EngineResult<Ciphertext> {
        let mut ct_result = ctxt.clone();
        self.smart_scalar_mul_assign(server_key, &mut ct_result, scalar)?;

        Ok(ct_result)
    }

    pub(crate) fn smart_scalar_mul_assign(
        &mut self,
        server_key: &ServerKey,
        ctxt: &mut Ciphertext,
        scalar: u8,
    ) -> EngineResult<()> {
        let modulus = server_key.message_modulus.0 as u64;
        // Direct scalar computation is possible
        if server_key.is_scalar_mul_possible(ctxt, scalar) {
            self.unchecked_scalar_mul_assign(ctxt, scalar)?;
            ctxt.degree = Degree(ctxt.degree.0 * scalar as usize);
        }
        // If the ciphertext cannot be multiplied without exceeding the degree max
        else {
            let acc = self.generate_lookup_table(server_key, |x| (scalar as u64 * x) % modulus)?;
            self.apply_lookup_table_assign(server_key, ctxt, &acc)?;
            ctxt.degree = Degree(server_key.message_modulus.0 - 1);
        }
        Ok(())
    }
}
