use crate::server_key::Ciphertext;
use crate::ServerKey;
use std::cmp::{max, min};
use tfhe::shortint;

impl ServerKey {
    pub fn mul(&self, ct1: &mut Ciphertext, ct2: &mut Ciphertext) -> Ciphertext {
        // carry need to be empty
        for ct in ct1.ct_vec_mantissa.iter_mut() {
            if ct.degree.get() > self.wopbs_key.param.message_modulus.0 {
                self.full_propagate_mantissa(&mut ct1.ct_vec_mantissa);
                break;
            }
        }
        for ct in ct2.ct_vec_mantissa.iter() {
            if ct.degree.get() > self.wopbs_key.param.message_modulus.0 {
                self.full_propagate_mantissa(&mut ct2.ct_vec_mantissa);
                break;
            }
        }

        let mut res = self.mul_mantissa(ct1, ct2);
        res = self.add_exponent_for_mul(&mut res.clone(), ct2);
        res.ct_sign = self.add_sign_for_mul(ct1, ct2);
        res
    }

    pub fn mul_parallelized(
        &self,
        ct1: &mut Ciphertext,
        ct2: &mut Ciphertext,
    ) -> (Ciphertext, shortint::Ciphertext) {
        // let now = std::time::Instant::now();
        let (mut res, mantissa_carry) = self.mul_mantissa_parallelized(ct1, ct2);
        // let elapsed = now.elapsed();
        // println!("mul_mantissa: {elapsed:?}");

        res = self.add_exponent_for_mul_parallelized(&mut res.clone(), ct2, &mantissa_carry);
        res.ct_sign = self.add_sign_for_mul_parallelized(ct1, ct2);
        (res, mantissa_carry)
    }

    fn mul_mantissa(&self, ct1: &mut Ciphertext, ct2: &mut Ciphertext) -> Ciphertext {
        let mantissa_len = ct1.ct_vec_mantissa.len();
        let value = (mantissa_len - 1) / 2;
        let mut result = self.create_trivial_zero(
            2 * mantissa_len - value - 1,
            ct1.ct_vec_exponent.len(),
            ct1.e_min,
        );

        for (i, ct2_i) in ct2.ct_vec_mantissa.iter().enumerate() {
            let bound = max((value - i) as i64, 0) as usize;
            let tmp = self.block_mul(
                &ct1.ct_vec_mantissa[bound..].to_vec(),
                ct2_i,
                i,
                ct1.ct_vec_mantissa.len(),
            );
            if !self.is_add_possible(
                &tmp,
                &result.ct_vec_mantissa
                    [min(0, (value - i) as i64).abs() as usize..(i + mantissa_len - value)],
            ) {
                // we propagate only the necessary blocks,
                // to not loose any information, we propagate one blocks before and one blocks after
                self.full_propagate_mantissa(
                    &mut result.ct_vec_mantissa[min(0, (value + 1 - i) as i64).abs() as usize
                        ..min(i + mantissa_len + 2 - value, 2 * mantissa_len - 1 - value)],
                );
                //self.full_propagate_mantissa(&mut result.ct_vec_mantissa);
            }
            for (ct_left_j, ct_right_j) in result.ct_vec_mantissa[min(0, (value - i) as i64).abs()
                as usize
                ..min(i + mantissa_len + 1 - value, 2 * mantissa_len - 1 - value)]
                .iter_mut()
                .zip(tmp.iter())
            {
                self.key.unchecked_add_assign(ct_left_j, ct_right_j);
            }
        }

        // the (log_msg_modulus * mantissa.len()) most significant bit of a multiplication are
        // include either in the [mantissa_len, 2*mantissa_len] or in [mantissa_len - 1,
        // 2*mantissa_len - 1] we choose the first one if the block 2*mantissa_len is not
        // empty otherwise we choose the first one
        let mut result_trunc = self.create_trivial_zero_from_ct(ct1);
        result_trunc.ct_vec_mantissa =
            result.ct_vec_mantissa[(mantissa_len - 1 - value)..].to_vec();
        result_trunc.ct_vec_exponent = ct1.ct_vec_exponent.clone();

        result_trunc
    }

    // Return the float ciphertext and the mantissa carry
    fn mul_mantissa_parallelized(
        &self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
    ) -> (Ciphertext, shortint::Ciphertext) {
        use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext};

        let mantissa_len = ct1.ct_vec_mantissa.len();
        let mantissa_len_for_mul_with_carry = mantissa_len * 2;
        let mut ct1_mantissa = ct1.ct_vec_mantissa.to_vec();
        ct1_mantissa.resize(mantissa_len_for_mul_with_carry, self.key.create_trivial(0));
        let mut ct2_mantissa = ct2.ct_vec_mantissa.to_vec();
        ct2_mantissa.resize(mantissa_len_for_mul_with_carry, self.key.create_trivial(0));
        let ct1_mantissa_as_integer = RadixCiphertext::from_blocks(ct1_mantissa);
        let ct2_mantissa_as_integer = RadixCiphertext::from_blocks(ct2_mantissa);

        // println!("ct1_len = {}", ct1_mantissa_as_integer.blocks().len());
        // println!("ct2_len = {}", ct2_mantissa_as_integer.blocks().len());

        // let now = std::time::Instant::now();
        let mul_result = self
            .integer_key
            .mul_parallelized(&ct1_mantissa_as_integer, &ct2_mantissa_as_integer);
        // let elapsed = now.elapsed();
        // println!("integer mul: {elapsed:?}");

        let mut mul_result_blocks = mul_result.into_blocks();
        let carry_block = mul_result_blocks.pop().unwrap();
        let mantissa = mul_result_blocks[mantissa_len - 1..].to_vec();
        assert_eq!(mantissa.len(), ct1.ct_vec_mantissa.len());
        let mut result_trunc = self.create_trivial_zero_from_ct(ct1);
        result_trunc.ct_vec_mantissa = mantissa;
        result_trunc.ct_vec_exponent = ct1.ct_vec_exponent.clone();

        (result_trunc, carry_block)
    }

    // multiply one block of a mantissa by each block of another mantissa and create a mantissa of
    // this mul
    fn block_mul(
        &self,
        ct1: &Vec<shortint::ciphertext::Ciphertext>,
        ct2: &shortint::ciphertext::Ciphertext,
        index: usize,
        len_man: usize,
    ) -> Vec<shortint::ciphertext::Ciphertext> {
        let zero = self.key.create_trivial(0);
        let mut result = vec![zero.clone()];
        let mut result_lsb = ct1.clone();
        let mut result_msb = ct1.clone();
        if index != len_man - 1 {
            for (ct_lsb_i, ct_msb_i) in result_lsb.iter_mut().zip(result_msb.iter_mut()) {
                self.key.unchecked_mul_msb_assign(ct_msb_i, ct2);
                self.key.unchecked_mul_lsb_assign(ct_lsb_i, ct2);
            }
            result_lsb.push(zero.clone());
            result.append(&mut result_msb.clone());
        } else {
            for (ct_lsb_i, ct_msb_i) in result_lsb[..len_man - 1]
                .iter_mut()
                .zip(result_msb[..len_man - 1].iter_mut())
            {
                self.key.unchecked_mul_msb_assign(ct_msb_i, ct2);
                self.key.unchecked_mul_lsb_assign(ct_lsb_i, ct2);
            }

            let msg_mod = self.key.message_modulus.0 as u64;
            let tmp = self.key.unchecked_scalar_mul(ct2, msg_mod as u8);
            self.key
                .unchecked_add_assign(result_lsb.last_mut().unwrap(), &tmp);

            // Generate the accumulator for the multiplication
            let acc = self
                .key
                .generate_lookup_table(|x| (x / msg_mod) * (x % msg_mod));
            self.key
                .apply_lookup_table_assign(result_lsb.last_mut().unwrap(), &acc);

            result.append(&mut result_msb.clone());
            result.pop();
        }

        for (ct1_i, ct2_i) in result.iter_mut().zip(result_lsb.iter()) {
            self.key.unchecked_add_assign(ct1_i, ct2_i)
        }
        result
    }

    //sum the two sign for the mul
    fn add_sign_for_mul(
        &self,
        ct1: &mut Ciphertext,
        ct2: &mut Ciphertext,
    ) -> shortint::ciphertext::Ciphertext {
        if self
            .key
            .is_add_possible(&ct1.ct_sign, &ct2.ct_sign)
            .is_err()
        {
            self.reduce_noise_sign(ct1);
            self.reduce_noise_sign(ct2);
        }
        self.key.unchecked_add(&ct1.ct_sign, &ct2.ct_sign)
    }

    fn add_sign_for_mul_parallelized(
        &self,
        ct1: &mut Ciphertext,
        ct2: &mut Ciphertext,
    ) -> shortint::ciphertext::Ciphertext {
        if self
            .key
            .is_add_possible(&ct1.ct_sign, &ct2.ct_sign)
            .is_err()
        {
            rayon::join(
                || self.reduce_noise_sign(ct1),
                || self.reduce_noise_sign(ct2),
            );
        }
        self.key.unchecked_add(&ct1.ct_sign, &ct2.ct_sign)
    }

    // add the two exponent and subtract the value e_min and the shift on the MSB blocks
    fn add_exponent_for_mul(&self, ct1: &mut Ciphertext, ct2: &mut Ciphertext) -> Ciphertext {
        let msg_modulus = self.wopbs_key.param.message_modulus.0 as u64;
        let carry_modulus = self.wopbs_key.param.carry_modulus.0 as u64;
        let log_msg_modulus = f64::log2(msg_modulus as f64) as u64;
        let log_msg_space = f64::log2((carry_modulus * msg_modulus) as f64) as usize;
        let len_vec_exp = ct1.ct_vec_exponent.len();

        if !self.is_add_possible(&ct1.ct_vec_exponent, &ct2.ct_vec_exponent) {
            self.partial_propagate(&mut ct1.ct_vec_exponent);
            self.partial_propagate(&mut ct2.ct_vec_exponent);
        }
        let mut res = ct1.clone();
        for (ct_left_j, ct_right_j) in res
            .ct_vec_exponent
            .iter_mut()
            .zip(ct2.ct_vec_exponent.iter())
        {
            self.key.unchecked_add_assign(ct_left_j, ct_right_j);
        }
        let cst = ct1.e_min + ct1.ct_vec_mantissa.len() as i64 - 1;
        let cst = (cst.abs() as u64) >> (log_msg_modulus * (len_vec_exp - 1) as u64);

        //check if the exponent is big enough (return 1 if e is to small, 0 otherwise)
        let accumulator = self.key.generate_lookup_table(|x| ((x < cst) as u64));
        let mut ct_sign = self
            .key
            .apply_lookup_table(&mut res.ct_vec_exponent.last().unwrap(), &accumulator);

        //check if the mantissa is not equals to zero (return 1 if ms_lwe== 0, 0 otherwise)
        let accumulator = self.key.generate_lookup_table(|x| ((x == 0) as u64));
        let ms_lwe = self
            .key
            .apply_lookup_table(&mut ct1.ct_vec_mantissa.last().unwrap(), &accumulator);
        self.key.unchecked_add_assign(&mut ct_sign, &ms_lwe);

        let accumulator = self.key.generate_lookup_table(|x| ((x > 0) as u64));
        let ct_sign = self.key.apply_lookup_table(&mut ct_sign, &accumulator);

        let sign_ggsw = self.ggsw_ks_cbs(&ct_sign, log_msg_space);
        let zero = self.create_trivial_zero_from_ct(ct1);

        let accumulator = self.key.generate_lookup_table(|x| (x - cst) % msg_modulus);
        self.key
            .apply_lookup_table_assign(&mut res.ct_vec_exponent[len_vec_exp - 1], &accumulator);
        res = self.cmuxes_full(&res, &zero, &sign_ggsw);
        res
    }

    // add the two exponent and subtract the value e_min and the shift on the MSB blocks
    fn add_exponent_for_mul_parallelized(
        &self,
        ct1: &mut Ciphertext,
        ct2: &mut Ciphertext,
        mantissa_carry: &shortint::Ciphertext,
    ) -> Ciphertext {
        let msg_modulus = self.wopbs_key.param.message_modulus.0 as u64;
        let carry_modulus = self.wopbs_key.param.carry_modulus.0 as u64;
        let log_msg_modulus = msg_modulus.ilog2() as u64;
        let log_msg_space = (carry_modulus * msg_modulus).ilog2() as usize;
        let len_vec_exp = ct1.ct_vec_exponent.len();

        if !self.is_add_possible(&ct1.ct_vec_exponent, &ct2.ct_vec_exponent) {
            rayon::join(
                || self.partial_propagate(&mut ct1.ct_vec_exponent),
                || self.partial_propagate(&mut ct2.ct_vec_exponent),
            );
        }
        let mut res = ct1.clone();
        for (ct_left_j, ct_right_j) in res
            .ct_vec_exponent
            .iter_mut()
            .zip(ct2.ct_vec_exponent.iter())
        {
            self.key.unchecked_add_assign(ct_left_j, ct_right_j);
        }
        let cst = ct1.e_min + ct1.ct_vec_mantissa.len() as i64 - 1;
        let cst = (cst.abs() as u64) >> (log_msg_modulus * (len_vec_exp - 1) as u64);

        let (mut ct_sign, ms_lwe) = rayon::join(
            || {
                //check if the exponent is big enough (return 1 if e is to small, 0 otherwise)
                let accumulator = self.key.generate_lookup_table(|x| ((x < cst) as u64));
                self.key
                    .apply_lookup_table(&mut res.ct_vec_exponent.last().unwrap(), &accumulator)
            },
            || {
                //check if the mantissa is not equals to zero (return 1 if ms_lwe== 0, 0 otherwise)
                let accumulator = self.key.generate_lookup_table(|x| ((x == 0) as u64));
                let mut last_mantissa_block = ct1.ct_vec_mantissa.last().unwrap().clone();
                // We recreate a mantissa block containing the msg + carry as we only want to know
                // if it was 0
                self.key
                    .unchecked_add_assign(&mut last_mantissa_block, &mantissa_carry);
                self.key
                    .apply_lookup_table(&last_mantissa_block, &accumulator)
            },
        );

        self.key.unchecked_add_assign(&mut ct_sign, &ms_lwe);

        rayon::join(
            || {
                let accumulator = self.key.generate_lookup_table(|x| ((x > 0) as u64));
                self.key
                    .apply_lookup_table_assign(&mut ct_sign, &accumulator);
            },
            || {
                let accumulator = self.key.generate_lookup_table(|x| (x - cst) % msg_modulus);
                self.key.apply_lookup_table_assign(
                    &mut res.ct_vec_exponent[len_vec_exp - 1],
                    &accumulator,
                );
            },
        );

        let sign_ggsw = self.ggsw_ks_cbs_parallelized(&ct_sign, log_msg_space);

        let zero = self.create_trivial_zero_from_ct(ct1);
        res = self.cmuxes_full_parallelized(&res, &zero, &sign_ggsw);
        res
    }

    pub fn mul_total(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        let mut res = self.mul(&mut ct1.clone(), &mut ct2.clone());
        self.clean_degree(&mut res);
        res
    }

    pub fn mul_total_parallelized(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        // let now = std::time::Instant::now();
        let (mut res, mantissa_carry) = self.mul_parallelized(&mut ct1.clone(), &mut ct2.clone());
        // let elapsed = now.elapsed();
        // println!("mul_parallelized: {elapsed:?}");

        // self.clean_degree_parallelized(&mut res);

        self.reduce_noise_sign(&mut res);
        // let now = std::time::Instant::now();
        self.full_propagate_exponent_parallelized(&mut res.ct_vec_exponent);
        // let elapsed = now.elapsed();
        // println!("elapsed exponent propagate: {elapsed:?}");

        // let now = std::time::Instant::now();
        // No need to propagate the mantissa it is clean after the integer mul parallelized
        // self.full_propagate_mantissa_increase_exponent_if_necessary_parallelized(&mut res);

        // TODO change the management of the carry
        self.increase_exponent_if_necessary_parallelized_carry(&mut res, &mantissa_carry);
        // let elapsed = now.elapsed();
        // println!("elapsed mantissa propagate: {elapsed:?}");

        res
    }
}
