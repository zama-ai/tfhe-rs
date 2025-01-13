use super::Ciphertext;
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::{
    keyswitch_lwe_ciphertext, lwe_ciphertext_plaintext_add_assign, CiphertextModulus,
    CiphertextModulusLog, LweCiphertext, LweSize, Plaintext,
};
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::NoiseLevel;
use crate::shortint::server_key::{apply_programmable_bootstrap, LookupTableOwned};
use crate::shortint::{PBSOrder, ServerKey};
use tfhe_csprng::seeders::Seed;

pub fn sha3_hash(values: &mut [u64], seed: Seed) {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut hasher = sha3::Shake256::default();

    let bytes = seed.0.to_le_bytes();

    hasher.update(bytes.as_slice());

    let mut reader = hasher.finalize_xof();

    for value in values {
        let mut bytes = [0u8; 8];
        reader.read(&mut bytes);
        *value = u64::from_le_bytes(bytes);
    }
}
pub fn create_random_from_seed(
    seed: Seed,
    lwe_size: LweSize,
    ciphertext_modulus: CiphertextModulus<u64>,
) -> LweCiphertext<Vec<u64>> {
    let mut ct = LweCiphertext::new(0, lwe_size, ciphertext_modulus);

    sha3_hash(ct.get_mut_mask().as_mut(), seed);

    ct
}

pub fn create_random_from_seed_modulus_switched(
    seed: Seed,
    lwe_size: LweSize,
    log_modulus: CiphertextModulusLog,
    ciphertext_modulus: CiphertextModulus<u64>,
) -> LweCiphertext<Vec<u64>> {
    let mut ct = create_random_from_seed(seed, lwe_size, ciphertext_modulus);

    for i in ct.as_mut() {
        *i = modulus_switch(*i, log_modulus) << (64 - log_modulus.0);
    }

    ct
}
impl ServerKey {
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

        let in_lwe_size = self.bootstrapping_key.input_lwe_dimension().to_lwe_size();

        let seeded = create_random_from_seed_modulus_switched(
            seed,
            in_lwe_size,
            self.bootstrapping_key
                .polynomial_size()
                .to_blind_rotation_input_modulus_log(),
            self.ciphertext_modulus,
        );

        let p = 1 << random_bits_count;

        let delta = 1_u64 << (64 - full_bits_count);

        let poly_delta = 2 * self.bootstrapping_key.polynomial_size().0 as u64 / p;

        let acc: LookupTableOwned =
            self.generate_lookup_table_no_encode(|x| (2 * (x / poly_delta) + 1) * delta / 2);

        let out_lwe_size = self.bootstrapping_key.output_lwe_dimension().to_lwe_size();

        let mut ct = LweCiphertext::new(0, out_lwe_size, self.ciphertext_modulus);

        ShortintEngine::with_thread_local_mut(|engine| {
            let (_, buffers) = engine.get_buffers(self);

            apply_programmable_bootstrap(
                &self.bootstrapping_key,
                &seeded,
                &mut ct,
                &acc.acc,
                buffers,
            );
        });

        lwe_ciphertext_plaintext_add_assign(&mut ct, Plaintext((p - 1) * delta / 2));

        let ct = match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => ct,
            PBSOrder::BootstrapKeyswitch => {
                let mut ct_ksed = LweCiphertext::new(0, in_lwe_size, self.ciphertext_modulus);

                keyswitch_lwe_ciphertext(&self.key_switching_key, &ct, &mut ct_ksed);

                ct_ksed
            }
        };

        Ciphertext {
            ct,
            degree: Degree::new(p - 1),
            noise_level: NoiseLevel::NOMINAL,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            pbs_order: self.pbs_order,
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::core_crypto::prelude::decrypt_lwe_ciphertext;
    use crate::shortint::oprf::create_random_from_seed_modulus_switched;
    use crate::shortint::{ClientKey, ServerKey};
    use rayon::prelude::*;
    use statrs::distribution::ContinuousCDF;
    use std::collections::HashMap;
    use tfhe_csprng::seeders::Seed;

    fn square(a: f64) -> f64 {
        a * a
    }

    #[test]
    fn oprf_compare_plain_ci_run_filter() {
        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        for seed in 0..1000 {
            oprf_compare_plain_from_seed(Seed(seed), &ck, &sk);
        }
    }

    fn oprf_compare_plain_from_seed(seed: Seed, ck: &ClientKey, sk: &ServerKey) {
        let params = ck.parameters;

        let random_bits_count = 2;

        let input_p = 2 * params.polynomial_size().0 as u64;

        let log_input_p = input_p.ilog2();

        let p_prime = 1 << random_bits_count;

        let output_p = 2 * params.carry_modulus().0 * params.message_modulus().0;

        let poly_delta = 2 * params.polynomial_size().0 as u64 / p_prime;

        let img = sk.generate_oblivious_pseudo_random(seed, random_bits_count);

        let lwe_size = sk.bootstrapping_key.input_lwe_dimension().to_lwe_size();

        let ct = create_random_from_seed_modulus_switched(
            seed,
            lwe_size,
            sk.bootstrapping_key
                .polynomial_size()
                .to_blind_rotation_input_modulus_log(),
            sk.ciphertext_modulus,
        );

        let sk = ck.small_lwe_secret_key();

        let plain_prf_input = decrypt_lwe_ciphertext(&sk, &ct)
            .0
            .wrapping_add(1 << (64 - log_input_p - 1))
            >> (64 - log_input_p);

        let half_negacyclic_part = |x| 2 * (x / poly_delta) + 1;

        let negacyclic_part = |x| {
            assert!(x < input_p);
            if x < input_p / 2 {
                half_negacyclic_part(x)
            } else {
                2 * output_p - half_negacyclic_part(x - (input_p / 2))
            }
        };

        let prf = |x| {
            let a = (negacyclic_part(x) + p_prime - 1) % (2 * output_p);
            assert!(a % 2 == 0);
            a / 2
        };

        let expected_output = prf(plain_prf_input);
        let output = ck.decrypt_message_and_carry(&img);

        assert!(output < p_prime);
        assert_eq!(output, expected_output);
    }

    #[test]
    fn oprf_test_uniformity_ci_run_filter() {
        let sample_count: usize = 100_000;

        let p_value_limit: f64 = 0.000_01;

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
