use crate::server_key::Ciphertext;
use crate::ServerKey;
use aligned_vec::ABox;
use rayon::prelude::*;
use tfhe::core_crypto::fft_impl::fft64::c64;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::FourierGgswCiphertext;
use tfhe::shortint;

impl ServerKey {
    // align the two mantissas of to floating points
    pub fn align_mantissa(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> (Ciphertext, Ciphertext) {
        let (ct_res, sign) = self.sub(&ct_left.ct_vec_exponent, &ct_right.ct_vec_exponent);
        let (vec_ggsw, sign_ggsw) =
            self.create_vec_ggsw_after_sub(&ct_res, &sign, ct_left.ct_vec_mantissa.len());
        let mut need_to_be_aligned = self.cmuxes(
            &ct_left.ct_vec_mantissa,
            &ct_right.ct_vec_mantissa,
            &sign_ggsw,
        );
        let aligned_exp = self.cmuxes(
            &ct_right.ct_vec_exponent,
            &ct_left.ct_vec_exponent,
            &sign_ggsw,
        );
        let aligned = self.cmux_tree_mantissa(&mut need_to_be_aligned, &vec_ggsw);
        let ct_left_aligned = self.cmuxes(&aligned, &ct_left.ct_vec_mantissa, &sign_ggsw);
        let ct_right_aligned = self.cmuxes(&ct_right.ct_vec_mantissa, &aligned, &sign_ggsw);
        let new_left = Ciphertext {
            ct_vec_mantissa: ct_left_aligned,
            ct_vec_exponent: aligned_exp.clone(),
            ct_sign: ct_left.ct_sign.clone(),
            e_min: ct_left.e_min,
        };
        let new_right = Ciphertext {
            ct_vec_mantissa: ct_right_aligned,
            ct_vec_exponent: aligned_exp,
            ct_sign: ct_right.ct_sign.clone(),
            e_min: ct_right.e_min,
        };
        (new_left, new_right)
    }

    pub fn align_mantissa_parallelized(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> (Ciphertext, Ciphertext) {
        let (mut ct_res, sign) =
            self.abs_diff_parallelized(&ct_left.ct_vec_exponent, &ct_right.ct_vec_exponent);

        let (vec_ggsw, sign_ggsw) = self.create_vec_ggsw_after_sub_parallelized(
            &mut ct_res,
            &sign,
            ct_left.ct_vec_mantissa.len(),
        );

        let (mut need_to_be_aligned, aligned_exp) = rayon::join(
            || {
                self.cmuxes_parallelized(
                    &ct_left.ct_vec_mantissa,
                    &ct_right.ct_vec_mantissa,
                    &sign_ggsw,
                )
            },
            || {
                self.cmuxes_parallelized(
                    &ct_right.ct_vec_exponent,
                    &ct_left.ct_vec_exponent,
                    &sign_ggsw,
                )
            },
        );
        let aligned = self.cmux_tree_mantissa_parallelized(&mut need_to_be_aligned, &vec_ggsw);
        let (ct_left_aligned, ct_right_aligned) = rayon::join(
            || self.cmuxes_parallelized(&aligned, &ct_left.ct_vec_mantissa, &sign_ggsw),
            || self.cmuxes_parallelized(&ct_right.ct_vec_mantissa, &aligned, &sign_ggsw),
        );
        let new_left = Ciphertext {
            ct_vec_mantissa: ct_left_aligned,
            ct_vec_exponent: aligned_exp.clone(),
            ct_sign: ct_left.ct_sign.clone(),
            e_min: ct_left.e_min,
        };
        let new_right = Ciphertext {
            ct_vec_mantissa: ct_right_aligned,
            ct_vec_exponent: aligned_exp,
            ct_sign: ct_right.ct_sign.clone(),
            e_min: ct_right.e_min,
        };
        (new_left, new_right)
    }

    pub fn create_vec_ggsw_after_sub(
        &self,
        ct_res: &Vec<shortint::ciphertext::Ciphertext>,
        sign: &shortint::ciphertext::Ciphertext,
        len_mantissa: usize,
    ) -> (
        Vec<FourierGgswCiphertext<ABox<[c64]>>>,
        FourierGgswCiphertext<ABox<[c64]>>,
    ) {
        let msg_modulus = self.wopbs_key.param.message_modulus.0 as u64;
        let car_modulus = self.wopbs_key.param.carry_modulus.0 as u64;
        let msg_space = (msg_modulus * car_modulus) as usize;

        let mut ct_res = ct_res.clone();
        self.full_propagate_exponent(&mut ct_res);
        let mut vec_ggsw = Vec::new();
        for i in 0..ct_res.len() {
            if len_mantissa < ((f64::log2(msg_modulus as f64) as usize) * i) {
                let mut ggsw = vec![self.ggsw_pbs_ks_cbs(&ct_res[i], msg_space)];
                ggsw.append(&mut vec_ggsw);
                vec_ggsw = ggsw
            } else {
                let mut ggsw = self.extract_bit_cbs(&ct_res[i]);
                ggsw.append(&mut vec_ggsw);
                vec_ggsw = ggsw;
            }
        }
        // message space == 0 because the sign is on the padding bit
        let sign_ggsw = self.ggsw_ks_cbs(&sign, 0);
        (vec_ggsw, sign_ggsw)
    }

    pub fn create_vec_ggsw_after_sub_parallelized(
        &self,
        ct_res: &mut [shortint::ciphertext::Ciphertext],
        sign: &shortint::ciphertext::Ciphertext,
        len_mantissa: usize,
    ) -> (
        Vec<FourierGgswCiphertext<ABox<[c64]>>>,
        FourierGgswCiphertext<ABox<[c64]>>,
    ) {
        let msg_modulus = self.wopbs_key.param.message_modulus.0 as u64;
        let car_modulus = self.wopbs_key.param.carry_modulus.0 as u64;
        let msg_space = (msg_modulus * car_modulus) as usize;

        self.full_propagate_exponent_parallelized(ct_res);

        let vec_ggsw: Vec<_> = ct_res
            .par_iter()
            .enumerate()
            .rev()
            .map(|(i, block)| {
                if (msg_modulus.ilog2() as usize * i) > len_mantissa {
                    vec![self.is_block_non_zero_ggsw_pbs_ks_cbs_parallelized(&block, msg_space)]
                } else {
                    self.extract_bit_cbs_parallelized(&block)
                }
            })
            .flatten()
            .collect();

        // message space == 0 because the sign is on the padding bit
        let sign_ggsw = self.ggsw_ks_cbs_parallelized(&sign, 0);
        (vec_ggsw, sign_ggsw)
    }
}
