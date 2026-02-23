use super::ServerKey;
use crate::integer::ciphertext::IntegerRadixCiphertext;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

impl ServerKey {
    /// Reverse the bits of the integer
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 0b10110100_u8;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.reverse_bits_parallelized(&ct);
    ///
    /// // Decrypt:
    /// let res: u8 = cks.decrypt(&ct_res);
    /// assert_eq!(msg.reverse_bits(), res);
    /// ```
    pub fn reverse_bits_parallelized<T>(&self, ct: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let message_modulus = self.message_modulus().0;

        let mut clean_ct;

        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            clean_ct = ct.clone();
            self.full_propagate_parallelized(&mut clean_ct);
            &clean_ct
        };

        let lut = self.key.generate_lookup_table(|x| {
            (x % message_modulus).reverse_bits() >> (64 - message_modulus.ilog2())
        });

        let blocks = ct
            .blocks()
            .par_iter()
            .rev()
            .map(|block| self.key.apply_lookup_table(block, &lut))
            .collect();

        T::from_blocks(blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::ServerKey;
    use crate::integer::ciphertext::RadixCiphertext;
    use crate::integer::keycache::KEY_CACHE;
    use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
    use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
    use crate::integer::tests::create_parameterized_test;
    use crate::integer::{IntegerKeyKind, RadixClientKey};
    #[cfg(tarpaulin)]
    use crate::shortint::parameters::coverage_parameters::*;
    use crate::shortint::parameters::test_params::*;
    use crate::shortint::parameters::*;
    use rand::prelude::*;
    use std::sync::Arc;

    pub(crate) fn reverse_bits_test<P, T>(param: P, mut executor: T)
    where
        P: Into<TestParameters>,
        T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
    {
        let param = param.into();
        let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
        let sks = Arc::new(sks);

        let nb_blocks = 4;

        let cks = RadixClientKey::from((cks, nb_blocks));

        executor.setup(&cks, sks);

        let log_modulus = nb_blocks * param.message_modulus().0.ilog2() as usize;
        let modulus = 1 << log_modulus;

        let nb_tests = 10;

        let mut rng = rand::rng();

        for _ in 0..nb_tests {
            let clear = rng.gen::<u64>() % modulus;

            let ct = cks.encrypt(clear);

            let result = executor.execute(&ct);
            let decrypted_result: u64 = cks.decrypt(&result);

            let expected_result = clear.reverse_bits() >> (64 - log_modulus);

            assert_eq!(
                decrypted_result, expected_result,
                "Invalid reverse_bits result, gave clear = {clear}, \
            expected {expected_result}, got {decrypted_result}"
            );
        }
    }

    fn integer_reverse_bits<P>(param: P)
    where
        P: Into<TestParameters>,
    {
        let executor = CpuFunctionExecutor::new(&ServerKey::reverse_bits_parallelized);
        reverse_bits_test(param, executor);
    }

    create_parameterized_test!(integer_reverse_bits);
}
