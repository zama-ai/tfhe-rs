use super::{CheckError, LookupTable, ServerKey};
use crate::core_crypto::prelude::container::Container;
use crate::shortint::ciphertext::MaxDegree;
use crate::shortint::server_key::add::unchecked_add_assign;
use crate::shortint::{Ciphertext, MessageModulus};

#[must_use]
pub struct BivariateLookupTable<C: Container<Element = u64>> {
    // A bivariate lookup table is an univariate loolookup table
    // where the message space is shared to encode
    // 2 values
    pub acc: LookupTable<C>,
    // By how much we shift the lhs in the LUT
    pub ct_right_modulus: MessageModulus,
}

pub type BivariateLookupTableOwned = BivariateLookupTable<Vec<u64>>;
pub type BivariateLookupTableMutView<'a> = BivariateLookupTable<&'a mut [u64]>;
pub type BivariateLookupTableView<'a> = BivariateLookupTable<&'a [u64]>;

impl<C: Container<Element = u64>> BivariateLookupTable<C> {
    pub fn is_bivariate_pbs_possible(
        &self,
        server_key: &ServerKey,
        lhs: &Ciphertext,
        rhs: &Ciphertext,
    ) -> Result<(), CheckError> {
        ciphertexts_can_be_packed_without_exceeding_space_or_noise(
            server_key,
            lhs,
            rhs,
            self.ct_right_modulus.0,
        )?;
        Ok(())
    }
}

/// Returns whether it is possible to pack lhs and rhs into a unique
/// ciphertext without exceeding the max storable value using the formula:
/// `unique_ciphertext = (lhs * factor) + rhs`
fn ciphertexts_can_be_packed_without_exceeding_space_or_noise(
    server_key: &ServerKey,
    lhs: &Ciphertext,
    rhs: &Ciphertext,
    factor: usize,
) -> Result<(), CheckError> {
    let final_degree = (lhs.degree * factor) + rhs.degree;

    let max_degree = MaxDegree::from_msg_carry_modulus(lhs.message_modulus, lhs.carry_modulus);

    max_degree.validate(final_degree)?;

    server_key
        .max_noise_level
        .validate(lhs.noise_level() * factor + rhs.noise_level())?;

    Ok(())
}

impl ServerKey {
    /// Generates a bivariate accumulator
    pub fn generate_lookup_table_bivariate_with_factor<F>(
        &self,
        f: F,
        left_message_scaling: MessageModulus,
    ) -> BivariateLookupTableOwned
    where
        F: Fn(u64, u64) -> u64,
    {
        // Depending on the factor used, rhs and / or lhs may have carries
        // (degree >= message_modulus) which is why we need to apply the message_modulus
        // to clear them
        let factor_u64 = left_message_scaling.0 as u64;
        let message_modulus = self.message_modulus.0 as u64;
        let wrapped_f = |input: u64| -> u64 {
            let lhs = (input / factor_u64) % message_modulus;
            let rhs = (input % factor_u64) % message_modulus;

            f(lhs, rhs)
        };
        let accumulator = self.generate_lookup_table(wrapped_f);

        BivariateLookupTable {
            acc: accumulator,
            ct_right_modulus: left_message_scaling,
        }
    }

    /// Constructs the lookup table for a given bivariate function as input.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 3;
    /// let msg_2 = 2;
    ///
    /// let mut ct1 = cks.encrypt(msg_1);
    /// let mut ct2 = cks.encrypt(msg_2);
    ///
    /// let f = |x, y| (x + y) % 4;
    ///
    /// let acc = sks.generate_lookup_table_bivariate(f);
    /// acc.is_bivariate_pbs_possible(&sks, &ct1, &ct2).unwrap();
    /// let ct_res = sks.smart_apply_lookup_table_bivariate(&mut ct1, &mut ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(dec, f(msg_1, msg_2));
    /// ```
    pub fn generate_lookup_table_bivariate<F>(&self, f: F) -> BivariateLookupTableOwned
    where
        F: Fn(u64, u64) -> u64,
    {
        self.generate_lookup_table_bivariate_with_factor(f, self.message_modulus)
    }

    /// Compute a keyswitch and programmable bootstrap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg: u64 = 3;
    /// let msg2: u64 = 2;
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg2);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    ///
    /// // Generate the lookup table for the function f: x, y -> (x * y * x) mod 4
    /// let acc = sks.generate_lookup_table_bivariate(|x, y| x * y * x % modulus);
    /// let ct_res = sks.unchecked_apply_lookup_table_bivariate(&ct1, &ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(dec, (msg * msg2 * msg) % modulus);
    /// ```
    pub fn unchecked_apply_lookup_table_bivariate(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) -> Ciphertext {
        let mut ct_res = ct_left.clone();
        self.unchecked_apply_lookup_table_bivariate_assign(&mut ct_res, ct_right, acc);
        ct_res
    }

    pub fn unchecked_apply_lookup_table_bivariate_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) {
        let modulus = (ct_right.degree.get() + 1) as u64;
        assert!(modulus <= acc.ct_right_modulus.0 as u64);

        // Message 1 is shifted
        self.unchecked_scalar_mul_assign(ct_left, acc.ct_right_modulus.0 as u8);

        unchecked_add_assign(ct_left, ct_right);

        // Compute the PBS
        self.apply_lookup_table_assign(ct_left, &acc.acc);
    }

    /// Compute a keyswitch and programmable bootstrap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg: u64 = 3;
    /// let msg2: u64 = 2;
    /// let mut ct1 = cks.encrypt(msg);
    /// let mut ct2 = cks.encrypt(msg2);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    ///
    /// // Generate the lookup table for the function f: x, y -> (x * y * x) mod 4
    /// let acc = sks.generate_lookup_table_bivariate(|x, y| x * y * x % modulus);
    /// let ct_res = sks.smart_apply_lookup_table_bivariate(&mut ct1, &mut ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(dec, (msg * msg2 * msg) % modulus);
    /// ```
    pub fn smart_apply_lookup_table_bivariate(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) -> Ciphertext {
        if self
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            // After the message_extract, we'll have ct_left, ct_right in [0, message_modulus[
            // so the factor has to be message_modulus
            assert_eq!(ct_right.message_modulus.0, acc.ct_right_modulus.0);
            self.message_extract_assign(ct_left);
            self.message_extract_assign(ct_right);
        }

        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();

        self.unchecked_apply_lookup_table_bivariate(ct_left, ct_right, acc)
    }

    pub fn smart_apply_lookup_table_bivariate_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) {
        if self
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            // After the message_extract, we'll have ct_left, ct_right in [0, message_modulus[
            // so the factor has to be message_modulus
            assert_eq!(ct_right.message_modulus.0, acc.ct_right_modulus.0);
            self.message_extract_assign(ct_left);
            self.message_extract_assign(ct_right);
        }

        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();

        self.unchecked_apply_lookup_table_bivariate_assign(ct_left, ct_right, acc);
    }
    /// Generic programmable bootstrap where messages are concatenated into one ciphertext to
    /// evaluate a bivariate function. This is used to apply many binary operations (comparisons,
    /// multiplications, division).
    pub fn unchecked_evaluate_bivariate_function<F>(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) -> Ciphertext
    where
        F: Fn(u64, u64) -> u64,
    {
        let mut ct_res = ct_left.clone();
        self.unchecked_evaluate_bivariate_function_assign(&mut ct_res, ct_right, f);
        ct_res
    }

    pub fn unchecked_evaluate_bivariate_function_assign<F>(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) where
        F: Fn(u64, u64) -> u64,
    {
        // Generate the lookup _table for the function
        let factor = MessageModulus(ct_right.degree.get() + 1);
        let lookup_table = self.generate_lookup_table_bivariate_with_factor(f, factor);

        self.unchecked_apply_lookup_table_bivariate_assign(ct_left, ct_right, &lookup_table);
    }

    /// Verify if a functional bivariate pbs can be applied on ct_left and ct_right.
    pub fn is_functional_bivariate_pbs_possible(
        &self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
    ) -> Result<(), CheckError> {
        ciphertexts_can_be_packed_without_exceeding_space_or_noise(
            self,
            ct1,
            ct2,
            ct2.degree.get() + 1,
        )?;

        Ok(())
    }

    pub fn smart_evaluate_bivariate_function_assign<F>(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        f: F,
    ) where
        F: Fn(u64, u64) -> u64,
    {
        *ct_left = self.smart_evaluate_bivariate_function(ct_left, ct_right, f);
    }

    pub fn smart_evaluate_bivariate_function<F>(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        f: F,
    ) -> Ciphertext
    where
        F: Fn(u64, u64) -> u64,
    {
        if self
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            // We don't have enough space in carries, so clear them
            self.message_extract_assign(ct_left);
            self.message_extract_assign(ct_right);
        }
        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();

        let factor = MessageModulus(ct_right.degree.get() + 1);

        // Generate the lookup table for the function
        let lookup_table = self.generate_lookup_table_bivariate_with_factor(f, factor);

        self.unchecked_apply_lookup_table_bivariate(ct_left, ct_right, &lookup_table)
    }
}
