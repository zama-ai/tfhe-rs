use super::Ciphertext;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::prelude::{
    lwe_ciphertext_plaintext_add_assign, ActivatedRandomGenerator, Plaintext,
};
use crate::shortint::ciphertext::Degree;
use crate::shortint::server_key::LookupTableOwned;
use crate::shortint::ServerKey;
use concrete_csprng::seeders::Seed;

impl ServerKey {
    fn create_random_from_seed(&self, seed: Seed) -> Ciphertext {
        let mut ct = self.create_trivial(0);

        let mut generator = RandomGenerator::<ActivatedRandomGenerator>::new(seed);

        for mask_e in ct.ct.get_mut_mask().as_mut() {
            *mask_e = generator.random_uniform::<u64>();
        }

        ct
    }

    /// Uniformly generates a random encrypted value in `[0, 2^random_bits_count[`
    /// `2^random_bits_count` must be smaller than the message modulus
    /// The encryted value is oblivious to the server
    pub fn generate_oblivious_pseudo_random(
        &self,
        seed: Seed,
        random_bits_count: u64,
    ) -> Ciphertext {
        assert!(
            1 << random_bits_count <= self.message_modulus.0,
            "The range asked for a random value (=[0, 2^{}[) does not fit in the available range [0, {}[",
            random_bits_count, self.message_modulus.0
        );

        self.generate_oblivious_pseudo_random_message_and_carry(seed, random_bits_count)
    }

    /// Uniformly generates a random value in `[0, 2^random_bits_count[`
    /// The encryted value is oblivious to the server
    pub(crate) fn generate_oblivious_pseudo_random_message_and_carry(
        &self,
        seed: Seed,
        random_bits_count: u64,
    ) -> Ciphertext {
        assert!(
            self.message_modulus.0.is_power_of_two(),
            "The message modulus(={}), must be a power of 2 to use the OPRF",
            self.message_modulus.0
        );
        let message_bits_count = self.message_modulus.0.ilog2() as u64;

        assert!(
            self.carry_modulus.0.is_power_of_two(),
            "The carry modulus(={}), must be a power of 2 to use the OPRF",
            self.carry_modulus.0
        );
        let carry_bits_count = self.carry_modulus.0.ilog2() as u64;

        assert!(
            random_bits_count <= carry_bits_count + message_bits_count,
            "The number of random bits asked for (={random_bits_count}) is bigger than carry_bits_count (={carry_bits_count}) + message_bits_count(={message_bits_count})",
        );

        self.generate_oblivious_pseudo_random_custom_encoding(
            seed,
            random_bits_count,
            1 + carry_bits_count + message_bits_count,
        )
    }

    /// Uniformly generates a random encrypted value in `[0, 2^random_bits_count[`
    /// The output in in the form 0000rrr000noise (rbc=3, fbc=7)
    /// The encryted value is oblivious to the server
    pub(crate) fn generate_oblivious_pseudo_random_custom_encoding(
        &self,
        seed: Seed,
        random_bits_count: u64,
        full_bits_count: u64,
    ) -> Ciphertext {
        assert!(
            random_bits_count <= full_bits_count,
            "The number of random bits asked for (={random_bits_count}) is bigger than full_bits_count (={full_bits_count})"
        );

        let ct = self.create_random_from_seed(seed);

        let p = 1 << random_bits_count;

        let delta = 1_u64 << (64 - full_bits_count);

        let poly_delta = 2 * self.bootstrapping_key.polynomial_size().0 as u64 / p;

        let acc: LookupTableOwned =
            self.generate_lookup_table_no_encode(|x| (2 * (x / poly_delta) + 1) * delta / 2);

        let mut ct = self.apply_lookup_table(&ct, &acc);

        lwe_ciphertext_plaintext_add_assign(&mut ct.ct, Plaintext((p - 1) * delta / 2));

        ct.degree = Degree::new(p as usize - 1);

        ct
    }
}

#[cfg(test)]
pub(crate) mod test {
    use concrete_csprng::seeders::Seed;
    use rayon::prelude::*;
    use statrs::distribution::ContinuousCDF;
    use std::collections::HashMap;

    fn square(a: f64) -> f64 {
        a * a
    }

    #[test]
    fn oprf_test_uniformity_ci_run_filter() {
        let sample_count: usize = 100_000;

        let p_value_limit: f64 = 0.001;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let test_uniformity = |distinct_values: u64, f: &(dyn Fn(usize) -> u64 + Sync)| {
            test_uniformity(sample_count, p_value_limit, distinct_values, f)
        };

        let random_bits_count = 2;

        test_uniformity(1 << random_bits_count, &|seed| {
            let img = sk.generate_oblivious_pseudo_random(Seed(seed as u128), random_bits_count);

            ck.decrypt_message_and_carry(&img)
        });
    }

    pub fn test_uniformity<F>(sample_count: usize, p_value_limit: f64, distinct_values: u64, f: F)
    where
        F: Sync + Fn(usize) -> u64,
    {
        let p_value = uniformity_p_value(f, sample_count, distinct_values);

        assert!(
            p_value_limit < p_value,
            "p_value (={p_value}) expected to be bigger than {p_value_limit}"
        );
    }

    fn uniformity_p_value<F>(f: F, sample_count: usize, distinct_values: u64) -> f64
    where
        F: Sync + Fn(usize) -> u64,
    {
        let values: Vec<_> = (0..sample_count).into_par_iter().map(&f).collect();

        let mut values_count = HashMap::new();

        for i in &values {
            assert!(*i < distinct_values, "i {} dv{}", *i, distinct_values);

            *values_count.entry(i).or_insert(0) += 1;
        }

        let single_expected_count = sample_count as f64 / distinct_values as f64;

        // https://en.wikipedia.org/wiki/Pearson's_chi-squared_test
        let distance: f64 = (0..distinct_values)
            .map(|value| *values_count.get(&value).unwrap_or(&0))
            .map(|count| square(count as f64 - single_expected_count) / single_expected_count)
            .sum();

        statrs::distribution::ChiSquared::new((distinct_values - 1) as f64)
            .unwrap()
            .sf(distance)
    }
}
