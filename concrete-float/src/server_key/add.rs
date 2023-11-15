use crate::server_key::Ciphertext;
use crate::ServerKey;
use rayon::prelude::*;
use tfhe::shortint;

//use crate::keycache::{get_sks, get_cks};

impl ServerKey {
    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// ```
    pub fn unchecked_add_mantissa(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Ciphertext {
        let mut result = ct_left.clone();
        self.unchecked_add_mantissa_assign(&mut result, ct_right);
        result
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    /// ```rust
    /// ```
    pub fn unchecked_add_mantissa_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        for (ct_left_i, ct_right_i) in ct_left
            .ct_vec_mantissa
            .iter_mut()
            .zip(ct_right.ct_vec_mantissa.iter())
        {
            self.key.unchecked_add_assign(ct_left_i, ct_right_i);
        }
    }

    /// we suppose that the mantissa are align
    pub fn add_mantissa(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        for (ct_left_i, ct_right_i) in ct_left
            .ct_vec_mantissa
            .iter_mut()
            .zip(ct_right.ct_vec_mantissa.iter())
        {
            self.key.unchecked_add_assign(ct_left_i, ct_right_i);
        }
    }

    /// Verifies if ct1 and ct2 can be added together.
    ///
    /// # Example
    ///
    ///```rust
    /// ```
    pub fn is_add_possible(
        &self,
        ct_left: &[shortint::ciphertext::Ciphertext],
        ct_right: &[shortint::ciphertext::Ciphertext],
    ) -> bool {
        for (ct_left_i, ct_right_i) in ct_left.iter().zip(ct_right.iter()) {
            if self.key.is_add_possible(ct_left_i, ct_right_i).is_err() {
                return false;
            }
        }
        true
    }

    pub fn add_total(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        let res_sign = self.key.unchecked_add(&ct1.ct_sign, &ct2.ct_sign);
        let (mut ct1_aligned, mut ct2_aligned) = self.align_mantissa(&ct1, &ct2);
        let ct_sub = self.sub_mantissa(&ct1_aligned, &ct2_aligned);
        self.add_mantissa(&mut ct1_aligned, &mut ct2_aligned);

        // message space == 0 because the sign is on the padding bit
        let ggsw = self.ggsw_ks_cbs(&res_sign, 0); //        let ggsw = self.wopbs_key.extract_one_bit_cbs(&self.key, &res_sign, 63);
        let mut res = self.cmuxes_full(&ct1_aligned, &ct_sub, &ggsw);
        self.clean_degree(&mut res);
        res
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// ```
    pub fn unchecked_add_mantissa_parallelized(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Ciphertext {
        let mut result = ct_left.clone();
        self.unchecked_add_mantissa_assign_parallelized(&mut result, ct_right);
        result
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    /// ```rust
    /// ```
    pub fn unchecked_add_mantissa_assign_parallelized(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) {
        ct_left
            .ct_vec_mantissa
            .par_iter_mut()
            .zip(ct_right.ct_vec_mantissa.par_iter())
            .for_each(|(ct_left_i, ct_right_i)| {
                self.key.unchecked_add_assign(ct_left_i, ct_right_i);
            });
    }

    /// we suppose that the mantissa are align
    pub fn add_mantissa_parallelized(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        // The operation is too small to be worth parallelizing
        ct_left
            .ct_vec_mantissa
            .iter_mut()
            .zip(ct_right.ct_vec_mantissa.iter())
            .for_each(|(ct_left_i, ct_right_i)| {
                self.key.unchecked_add_assign(ct_left_i, ct_right_i);
            });
    }

    pub fn add_total_parallelized(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        let res_sign = self.key.unchecked_add(&ct1.ct_sign, &ct2.ct_sign);
        let (mut ct1_aligned, mut ct2_aligned) = self.align_mantissa_parallelized(&ct1, &ct2);
        let ct_sub = self.sub_mantissa_parallelized(&ct1_aligned, &ct2_aligned);
        self.add_mantissa_parallelized(&mut ct1_aligned, &mut ct2_aligned);
        // message space == 0 because the sign is on the padding bit
        let ggsw = self.ggsw_ks_cbs_parallelized(&res_sign, 0); //        let ggsw = self.wopbs_key.extract_one_bit_cbs(&self.key, &res_sign, 63);
        let mut res = self.cmuxes_full_parallelized(&ct1_aligned, &ct_sub, &ggsw);
        self.clean_degree_parallelized(&mut res);

        res
    }
}
