use crate::integer::{CrtCiphertext, CrtServerKey};

impl CrtServerKey {
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
