use crate::ciphertext::Ciphertext;
use crate::ServerKey;
use rayon::prelude::*;
use shortint::ciphertext::Degree;
use std::cmp::max;
use tfhe::core_crypto::prelude::{Cleartext, Plaintext};
use tfhe::shortint;

impl ServerKey {
    // This operation return |a - b| and sing(a-b)
    // after sub all the blocks have the smallest degree except the most significant block
    pub fn sub(
        &self,
        ctxt_left: &Vec<shortint::Ciphertext>,
        ctxt_right: &Vec<shortint::Ciphertext>,
    ) -> (Vec<shortint::Ciphertext>, shortint::Ciphertext) {
        let mut ct_tmp: Vec<shortint::Ciphertext> = Vec::new();
        let msg_modulus = self.wopbs_key.param.message_modulus.0 as u64;
        let car_modulus = self.wopbs_key.param.carry_modulus.0 as u64;
        let msg_space = (msg_modulus * car_modulus) as u64;
        let size_ct = ctxt_left.len();
        for ct in ctxt_left.iter() {
            ct_tmp.push(
                self.key
                    .unchecked_scalar_add(ct, ((msg_space / 2) - car_modulus / 2) as u8),
            );
        }

        self.key
            .unchecked_scalar_add_assign(&mut ct_tmp[0], (car_modulus / 2) as u8);
        let cpy_right = ctxt_right.clone();
        for (c_left, c_right) in ct_tmp.iter_mut().zip(cpy_right.iter()) {
            tfhe::core_crypto::algorithms::lwe_ciphertext_sub_assign(&mut c_left.ct, &c_right.ct);
            let noise_level = c_left.noise_level() + c_right.noise_level();
            c_left.set_noise_level(noise_level);
        }
        self.partial_propagate(&mut ct_tmp);
        //extract the sign (the first value add on the most significant block)
        let accumulator = self.key.generate_lookup_table(|x| (x & (msg_space / 2)));
        let mut sign = self
            .key
            .apply_lookup_table(ct_tmp.last_mut().unwrap(), &accumulator);
        // the value sign encrypt only 1 or 0 so the degree is 1

        // We can always add as the sign is managed on the padding bit, the only important thing is
        // the noise
        sign.degree = Degree::new(0);

        // add the sign on each block
        for i in 0..(size_ct - 1) {
            self.key.unchecked_add_assign(&mut ct_tmp[i], &sign);
        }

        // if the sign on each block ==0, we take the opposite, otherwise we return the value.
        // to find the opposite we perform the same idea than the subtraction (but only with pbs as
        // we know one value ) opposite = (1 << (len * precision)) - x
        for (i, ct) in ct_tmp.iter_mut().enumerate() {
            if i == 0 {
                let accumulator = self.key.generate_lookup_table(|x| {
                    (((x - (msg_space / 2)) - (msg_modulus - x))
                        * ((x & (msg_space / 2)) / (msg_space / 2)))
                        + (msg_modulus - x)
                });
                self.key.apply_lookup_table_assign(ct, &accumulator);
                ct.degree = Degree::new(msg_modulus as usize)
            } else if i == size_ct - 1 {
                let accumulator = self.key.generate_lookup_table(|x| {
                    (((x - (msg_space / 2)) - (msg_space / 2 - x - 1))
                        * ((x & (msg_space / 2)) / (msg_space / 2)))
                        + (msg_space / 2 - x - 1)
                });
                self.key.apply_lookup_table_assign(ct, &accumulator);
                ct.degree = Degree::new(max(
                    (msg_space as usize / 2) - ct.degree.get(),
                    ct.degree.get(),
                ));
            } else {
                let accumulator = self.key.generate_lookup_table(|x| {
                    (((x - (msg_space / 2)) - (msg_modulus - x - 1))
                        * ((x & (msg_space / 2)) / (msg_space / 2)))
                        + (msg_modulus - x - 1)
                });
                self.key.apply_lookup_table_assign(ct, &accumulator);
                ct.degree = Degree::new(msg_modulus as usize)
            }
        }
        // move the sign bit on the msb
        // uncheck add, we juste create the sign
        tfhe::core_crypto::algorithms::lwe_ciphertext_cleartext_mul_assign(
            &mut sign.ct,
            Cleartext(2),
        );
        //self.key.unchecked_scalar_mul_assign(&mut sign, 2);
        (ct_tmp, sign)
    }

    // subtract the two mantissas
    // after the subtraction put the msb of the result on the mst significant block
    // if exponent == 0 and the first block == 0, the result is 0
    pub fn sub_mantissa(&self, ctxt_left: &Ciphertext, ctxt_right: &Ciphertext) -> Ciphertext {
        let msg_modulus = self.wopbs_key.param.message_modulus.0 as u64;
        let car_modulus = self.wopbs_key.param.carry_modulus.0 as u64;
        let msg_space = (msg_modulus * car_modulus) as usize;
        let (res, sign) = self.sub(&ctxt_left.ct_vec_mantissa, &ctxt_right.ct_vec_mantissa);

        let mut new = self.create_trivial_zero_from_ct(ctxt_left);
        new.ct_vec_mantissa = res;
        new.ct_vec_exponent = ctxt_left.ct_vec_exponent.clone();
        // if sign == 0 => need to change the sign of the operation
        // if sign == 1 we want to keep the same sign
        // new_s = old_s + sign + 1
        new.ct_sign = self.key.unchecked_add(&sign, ctxt_left.sign());
        self.key
            .unchecked_scalar_add_assign(&mut new.ct_sign, msg_space as u8);

        new = self.realign_sub(&new);
        new
    }

    // move the msb on the most significant block.
    // if e = 0 and the first block is empty, return zero
    // (no subnormal value)
    pub fn realign_sub(&self, ct0: &Ciphertext) -> Ciphertext {
        let msg_modulus = self.wopbs_key.param.message_modulus.0 as usize;
        let car_modulus = self.wopbs_key.param.carry_modulus.0 as usize;
        let msg_space = f64::log2((msg_modulus * car_modulus) as f64) as usize;
        let size_mantissa = ct0.ct_vec_mantissa.len();

        let zero = self.create_trivial_zero_from_ct(ct0);
        let mut res = zero.clone();
        res.ct_vec_mantissa = ct0.ct_vec_mantissa.clone();
        res.ct_sign = ct0.ct_sign.clone();
        let mut msb_mantissa_ggsw =
            self.ggsw_pbs_ks_cbs(&res.ct_vec_mantissa[size_mantissa - 1], msg_space);
        for i in 0..size_mantissa {
            let mut tmp = zero.clone();
            tmp.ct_vec_mantissa = zero.ct_vec_mantissa.clone();
            for j in 0..(size_mantissa - 1) {
                tmp.ct_vec_mantissa[j + 1] = res.ct_vec_mantissa[j].clone();
            }
            for (k, ct_exp_i) in tmp.ct_vec_exponent.iter_mut().enumerate() {
                self.key.unchecked_scalar_add_assign(
                    ct_exp_i,
                    (((i + 1) >> (f64::log2(msg_modulus as f64) as usize * (k))) % msg_modulus)
                        as u8,
                );
            }

            // return tmp if ggsw == 0; res otherwise
            res.ct_vec_mantissa = self.cmuxes(
                &tmp.ct_vec_mantissa,
                &res.ct_vec_mantissa,
                &msb_mantissa_ggsw,
            );
            res.ct_vec_exponent = self.cmuxes(
                &tmp.ct_vec_exponent,
                &res.ct_vec_exponent,
                &msb_mantissa_ggsw,
            );

            if i < size_mantissa - 1 {
                msb_mantissa_ggsw =
                    self.ggsw_pbs_ks_cbs(&res.ct_vec_mantissa[size_mantissa - 1], msg_space);
            }
        }

        let (mut diff_exp, sub_exp_sign) = self.sub(&ct0.ct_vec_exponent, &res.ct_vec_exponent);

        // message space == 0 because the sign is on the padding bit
        let sign_ggsw = self.ggsw_ks_cbs(&sub_exp_sign, 0); //let sign_ggsw = self.wopbs_key.extract_one_bit_cbs(&self.key, &sub_exp_sign, 63);
        diff_exp = self.cmuxes(&zero.ct_vec_exponent, &diff_exp, &msb_mantissa_ggsw);
        res.ct_vec_exponent = self.cmuxes(&zero.ct_vec_exponent, &diff_exp, &sign_ggsw);
        res.ct_vec_mantissa = self.cmuxes(&zero.ct_vec_mantissa, &res.ct_vec_mantissa, &sign_ggsw);
        res.ct_sign = res.ct_sign;
        res
    }

    // change the sign
    pub fn change_sign_assign(&self, ct0: &mut Ciphertext) {
        tfhe::core_crypto::algorithms::lwe_ciphertext_plaintext_add_assign(
            &mut ct0.ct_sign.ct,
            Plaintext(1 << 63),
        );
    }

    pub fn change_sign(&self, ct0: &Ciphertext) -> Ciphertext {
        let mut ct = ct0.clone();
        self.change_sign_assign(&mut ct);
        ct
    }

    pub fn sub_total(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        let ct2 = self.change_sign(ct2);
        self.add_total(&ct1, &ct2)
    }

    // This operation return |a - b| and sing(a-b)
    // after sub all the blocks have the smallest degree except the most significant block
    // TODO: would the overflowing_sub from integer (with some slight adaptations perhaps) do the
    // trick ?
    pub fn abs_diff_parallelized(
        &self,
        ctxt_left: &Vec<shortint::Ciphertext>,
        ctxt_right: &Vec<shortint::Ciphertext>,
    ) -> (Vec<shortint::Ciphertext>, shortint::Ciphertext) {
        let mut ct_tmp: Vec<shortint::Ciphertext> = Vec::with_capacity(ctxt_left.len());
        let msg_modulus = self.wopbs_key.param.message_modulus.0 as u64;
        let car_modulus = self.wopbs_key.param.carry_modulus.0 as u64;
        let msg_space = (msg_modulus * car_modulus) as u64;
        let size_ct = ctxt_left.len();
        for ct in ctxt_left.iter() {
            ct_tmp.push(
                self.key
                    .unchecked_scalar_add(ct, ((msg_space / 2) - car_modulus / 2) as u8),
            );
        }

        self.key
            .unchecked_scalar_add_assign(&mut ct_tmp[0], (car_modulus / 2) as u8);
        let cpy_right = ctxt_right.clone();
        // The operation is too small to be worth parallelizing
        ct_tmp
            .iter_mut()
            .zip(cpy_right.iter())
            .for_each(|(c_left, c_right)| {
                tfhe::core_crypto::algorithms::lwe_ciphertext_sub_assign(
                    &mut c_left.ct,
                    &c_right.ct,
                );
                let noise_level = c_left.noise_level() + c_right.noise_level();
                c_left.set_noise_level(noise_level);
            });

        self.partial_propagate_parallelized(&mut ct_tmp);
        //extract the sign (the first value add on the most significant block)
        let accumulator = self.key.generate_lookup_table(|x| (x & (msg_space / 2)));
        let mut sign = self
            .key
            .apply_lookup_table(ct_tmp.last_mut().unwrap(), &accumulator);
        // the value sign encrypt only 1 or 0 so the degree is 1

        // We can always add as the sign is managed on the padding bit, the only important thing is
        // the noise
        sign.degree = Degree::new(0);

        // add the sign on each block, except the last one
        // Operation is too small to be worth parallelizing
        ct_tmp[0..(size_ct - 1)]
            .iter_mut()
            .for_each(|tmp_block| self.key.unchecked_add_assign(tmp_block, &sign));

        // if the sign on each block ==0, we take the opposite, otherwise we return the value.
        // to find the opposite we perform the same idea than the subtraction (but only with pbs as
        // we know one value ) opposite = (1 << (len * precision)) - x
        ct_tmp.par_iter_mut().enumerate().for_each(|(i, ct)| {
            if i == 0 {
                let accumulator = self.key.generate_lookup_table(|x| {
                    (((x - (msg_space / 2)) - (msg_modulus - x))
                        * ((x & (msg_space / 2)) / (msg_space / 2)))
                        + (msg_modulus - x)
                });
                self.key.apply_lookup_table_assign(ct, &accumulator);
            } else if i == size_ct - 1 {
                let accumulator = self.key.generate_lookup_table(|x| {
                    (((x - (msg_space / 2)) - (msg_space / 2 - x - 1))
                        * ((x & (msg_space / 2)) / (msg_space / 2)))
                        + (msg_space / 2 - x - 1)
                });
                self.key.apply_lookup_table_assign(ct, &accumulator);
            } else {
                let accumulator = self.key.generate_lookup_table(|x| {
                    (((x - (msg_space / 2)) - (msg_modulus - x - 1))
                        * ((x & (msg_space / 2)) / (msg_space / 2)))
                        + (msg_modulus - x - 1)
                });
                self.key.apply_lookup_table_assign(ct, &accumulator);
            }
        });

        // move the sign bit on the msb
        // uncheck add, we juste create the sign
        tfhe::core_crypto::algorithms::lwe_ciphertext_cleartext_mul_assign(
            &mut sign.ct,
            Cleartext(2),
        );
        //self.key.unchecked_scalar_mul_assign(&mut sign, 2);
        (ct_tmp, sign)
    }

    // subtract the two mantissas
    // after the subtraction put the msb of the result on the mst significant block
    // if exponent == 0 and the first block == 0, the result is 0
    pub fn sub_mantissa_parallelized(
        &self,
        ctxt_left: &Ciphertext,
        ctxt_right: &Ciphertext,
    ) -> Ciphertext {
        // todo!("sub_mantissa_parallelized");
        let msg_modulus = self.wopbs_key.param.message_modulus.0 as u64;
        let car_modulus = self.wopbs_key.param.carry_modulus.0 as u64;
        let msg_space = (msg_modulus * car_modulus) as usize;
        // let now = std::time::Instant::now();
        let (res, sign) =
            self.abs_diff_parallelized(&ctxt_left.ct_vec_mantissa, &ctxt_right.ct_vec_mantissa);
        // let elapsed = now.elapsed();
        // println!("sub_mantissa_parallelized::sub_parallelized: {elapsed:?}");

        let mut new = self.create_trivial_zero_from_ct(ctxt_left);
        new.ct_vec_mantissa = res;
        new.ct_vec_exponent = ctxt_left.ct_vec_exponent.clone();
        // if sign == 0 => need to change the sign of the operation
        // if sign == 1 we want to keep the same sign
        // new_s = old_s + sign + 1
        new.ct_sign = self.key.unchecked_add(&sign, ctxt_left.sign());
        self.key
            .unchecked_scalar_add_assign(&mut new.ct_sign, msg_space as u8);

        // let now = std::time::Instant::now();
        new = self.realign_sub_parallelized(&new);
        // let elapsed = now.elapsed();
        // println!("sub_mantissa_parallelized::realign_sub_parallelized: {elapsed:?}");

        new
    }

    // move the msb on the most significant block.
    // if e = 0 and the first block is empty, return zero
    // (no subnormal value)
    pub fn realign_sub_parallelized(&self, ct0: &Ciphertext) -> Ciphertext {
        // todo!("realign_sub_parallelized");
        let msg_modulus = self.wopbs_key.param.message_modulus.0 as usize;
        let car_modulus = self.wopbs_key.param.carry_modulus.0 as usize;
        let msg_space = (msg_modulus * car_modulus).ilog2() as usize;
        let size_mantissa = ct0.ct_vec_mantissa.len();

        let zero = self.create_trivial_zero_from_ct(ct0);

        let cmux_tree_size = if size_mantissa.is_power_of_two() {
            size_mantissa
        } else {
            size_mantissa.next_power_of_two()
        };

        let mut ciphertexts_to_cmux: Vec<Ciphertext> = Vec::with_capacity(cmux_tree_size);
        let mut cmux_outputs: Vec<Ciphertext> = Vec::with_capacity(cmux_tree_size / 2);

        (0..cmux_tree_size)
            .into_par_iter()
            .map(|ciphertext_idx| {
                if ciphertext_idx < size_mantissa {
                    let mut ciphertext = zero.clone();

                    for (k, ct_exp_i) in ciphertext.ct_vec_exponent.iter_mut().enumerate() {
                        self.key.unchecked_scalar_add_assign(
                            ct_exp_i,
                            ((ciphertext_idx >> (msg_modulus.ilog2() as usize * (k))) % msg_modulus)
                                as u8,
                        );
                    }

                    let exponent_block_count = size_mantissa - ciphertext_idx;
                    ciphertext.ct_vec_mantissa[ciphertext_idx..]
                        .clone_from_slice(&ct0.ct_vec_mantissa[..exponent_block_count]);

                    ciphertext
                } else {
                    zero.clone()
                }
            })
            .collect_into_vec(&mut ciphertexts_to_cmux);

        while ciphertexts_to_cmux.len() > 1 {
            ciphertexts_to_cmux
                .par_chunks_exact(2)
                .map(|chunk| {
                    let less_modified_exponent = &chunk[0];
                    let more_modified_exponent = &chunk[1];

                    let msb_mantissa_ggsw = self.is_block_non_zero_ggsw_pbs_ks_cbs_parallelized(
                        &less_modified_exponent.ct_vec_mantissa[size_mantissa - 1],
                        msg_space,
                    );

                    // return tmp if ggsw == 0; res otherwise
                    let (mantissa, exponent) = rayon::join(
                        || {
                            self.cmuxes_parallelized(
                                &more_modified_exponent.ct_vec_mantissa,
                                &less_modified_exponent.ct_vec_mantissa,
                                &msb_mantissa_ggsw,
                            )
                        },
                        || {
                            self.cmuxes_parallelized(
                                &more_modified_exponent.ct_vec_exponent,
                                &less_modified_exponent.ct_vec_exponent,
                                &msb_mantissa_ggsw,
                            )
                        },
                    );

                    let mut res = zero.clone();
                    res.ct_vec_exponent = exponent;
                    res.ct_vec_mantissa = mantissa;

                    res
                })
                .collect_into_vec(&mut cmux_outputs);

            std::mem::swap(&mut ciphertexts_to_cmux, &mut cmux_outputs);
        }

        let mut res = ciphertexts_to_cmux.into_iter().next().unwrap();

        let (mut diff_exp, sub_exp_sign) =
            self.abs_diff_parallelized(&ct0.ct_vec_exponent, &res.ct_vec_exponent);

        // message space == 0 because the sign is on the padding bit
        let (sign_ggsw, msb_mantissa_ggsw) = rayon::join(
            || self.ggsw_ks_cbs_parallelized(&sub_exp_sign, 0),
            || {
                self.is_block_non_zero_ggsw_pbs_ks_cbs_parallelized(
                    &res.ct_vec_mantissa[size_mantissa - 1],
                    msg_space,
                )
            },
        );

        let (exponent, mantissa) = rayon::join(
            || {
                diff_exp =
                    self.cmuxes_parallelized(&zero.ct_vec_exponent, &diff_exp, &msb_mantissa_ggsw);
                self.cmuxes_parallelized(&zero.ct_vec_exponent, &diff_exp, &sign_ggsw)
            },
            || self.cmuxes_parallelized(&zero.ct_vec_mantissa, &res.ct_vec_mantissa, &sign_ggsw),
        );

        res.ct_vec_exponent = exponent;
        res.ct_vec_mantissa = mantissa;
        res.ct_sign = ct0.ct_sign.clone();
        res
    }

    pub fn sub_total_parallelized(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        let ct2 = self.change_sign(ct2);
        self.add_total_parallelized(&ct1, &ct2)
    }
}
