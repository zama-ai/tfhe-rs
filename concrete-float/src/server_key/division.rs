use crate::ciphertext::Ciphertext;
use crate::server_key::ServerKey;
use tfhe::integer::ciphertext::RadixCiphertext;
use tfhe::integer::IntegerCiphertext;

impl ServerKey {
    pub fn division(&self,  ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        let msg_modulus = self.wopbs_key.param.message_modulus.0 as u64;
        let log_msg_modulus = f64::log2(msg_modulus as f64) as u64;
        let len_vec_exp = ct1.ct_vec_exponent.len();
        let len_vec_man = ct1.ct_vec_mantissa.len();

        let mut res = self.create_trivial_zero(
            ct1.ct_vec_mantissa.len(),
            ct1.ct_vec_exponent.len(),
            ct1.e_min,
        );
        let zero = self.create_trivial_zero(
            ct1.ct_vec_mantissa.len(),
            ct1.ct_vec_exponent.len(),
            ct1.e_min,
        );
        res.ct_sign = self.key.unchecked_add(&ct1.ct_sign, &ct2.ct_sign);
        res.ct_vec_exponent = ct1.ct_vec_exponent.clone();

        let cst = ct1.e_min + len_vec_man as i64 - 1;
        for i in 0..len_vec_exp {
            let cst = (cst.abs() as u64) >> (log_msg_modulus * i as u64);
            self.key.unchecked_scalar_add_assign(
                &mut res.ct_vec_exponent[i],
                (cst % msg_modulus) as u8,
            );
        }
        let (res_exp, sign) = self.sub(&res.ct_vec_exponent, &ct2.ct_vec_exponent);
        res.ct_vec_exponent = res_exp;
        let mut cct1 = RadixCiphertext::from(ct1.ct_vec_mantissa.clone());
        let mut cct2 = RadixCiphertext::from(ct2.ct_vec_mantissa.clone());

        let int_key = tfhe::integer::ServerKey::from_shortint_ex(self.key.clone());

        int_key.extend_radix_with_trivial_zero_blocks_lsb_assign(&mut cct1, len_vec_man - 1);
        int_key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut cct2, len_vec_man - 1);

        let res_mantissa = int_key.unchecked_div_parallelized(&cct1, &cct2);

        // message space == 0 because the sign is on the padding bit
        let sign_ggsw = self.ggsw_ks_cbs(&sign, 0);

        res.ct_vec_mantissa = res_mantissa.blocks()[..len_vec_man].to_vec();
        res = self.cmuxes_full(&zero, &res, &sign_ggsw);
        res
    }
}
