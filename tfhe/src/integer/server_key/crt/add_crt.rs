use crate::integer::{CrtCiphertext, ServerKey};
use crate::shortint::CheckError;

impl ServerKey {
    pub fn is_crt_add_possible(
        &self,
        ct_left: &CrtCiphertext,
        ct_right: &CrtCiphertext,
    ) -> Result<(), CheckError> {
        for (ct_left_i, ct_right_i) in ct_left.blocks.iter().zip(ct_right.blocks.iter()) {
            self.key
                .is_add_possible(ct_left_i.noise_degree(), ct_right_i.noise_degree())?;
        }
        Ok(())
    }

    pub fn unchecked_crt_add_assign(&self, ct_left: &mut CrtCiphertext, ct_right: &CrtCiphertext) {
        for (ct_left_i, ct_right_i) in ct_left.blocks.iter_mut().zip(ct_right.blocks.iter()) {
            self.key.unchecked_add_assign(ct_left_i, ct_right_i);
        }
    }

    pub fn unchecked_crt_add(
        &self,
        ct_left: &CrtCiphertext,
        ct_right: &CrtCiphertext,
    ) -> CrtCiphertext {
        let mut ct_res = ct_left.clone();
        self.unchecked_crt_add_assign(&mut ct_res, ct_right);
        ct_res
    }
}
