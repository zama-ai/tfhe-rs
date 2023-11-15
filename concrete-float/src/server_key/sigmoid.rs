use crate::ciphertext::Ciphertext;
use crate::server_key::ServerKey;

impl ServerKey {
    pub fn sigmoid(&self, ct: &Ciphertext) -> Ciphertext {
        let msg_modulus = self.wopbs_key.param.message_modulus.0 as u64;
        let carry_modulus = self.wopbs_key.param.carry_modulus.0 as u64;
        let log_msg_modulus = f64::log2(msg_modulus as f64) as u64;
        let log_carry_modulus = f64::log2(carry_modulus as f64) as u64;
        let cst = ct.e_min + ct.ct_vec_mantissa.len() as i64 - 1;
        let cst = (cst.abs() as u64) >> (log_msg_modulus * (ct.ct_vec_exponent.len() - 1) as u64);

        let mut one = self.create_trivial_zero_from_ct(ct);
        self.key
            .unchecked_scalar_add_assign(&mut one.ct_vec_mantissa.last_mut().unwrap(), 1 as u8);
        self.key
            .unchecked_scalar_add_assign(&mut one.ct_vec_exponent.last_mut().unwrap(), cst as u8);

        let mut minus_one = one.clone();
        self.change_sign_assign(&mut minus_one);
        let ggsw = self.ggsw_ks_cbs(&ct.ct_sign, 0);
        let tmp = self.cmuxes_full(&one, &minus_one, &ggsw);

        let value = msg_modulus / 2;
        let accumulator = self.key.generate_lookup_table(|x| (x > value) as u64);
        let ct_last = self
            .key
            .apply_lookup_table(&mut ct.ct_vec_mantissa.last().unwrap(), &accumulator);

        //check if the exponent is big enough (return 1 if e is to small, 0 otherwise)
        let accumulator = self.key.generate_lookup_table(|x| ((x < cst) as u64));
        let mut ct_sign = self
            .key
            .apply_lookup_table(&mut ct.ct_vec_exponent.last().unwrap(), &accumulator);

        self.key.unchecked_add_assign(&mut ct_sign, &ct_last);
        let accumulator = self.key.generate_lookup_table(|x| ((x > 0) as u64));
        let ct_sign = self.key.apply_lookup_table(&mut ct_sign, &accumulator);

        let ggsw = self.ggsw_ks_cbs(&ct_sign, (log_carry_modulus + log_msg_modulus) as usize);
        self.cmuxes_full(&tmp, &ct, &ggsw)
    }
}
