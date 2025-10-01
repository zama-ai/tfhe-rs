use super::server_key::{GenericServerKey, LookupTableSize, ShortintBootstrappingKey};
use super::Ciphertext;
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::*;
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::NoiseLevel;
use crate::shortint::server_key::{
    apply_multi_bit_blind_rotate, apply_standard_blind_rotate, generate_lookup_table_no_encode,
};
use itertools::Itertools;
use tfhe_csprng::seeders::Seed;

pub(crate) struct PrfSeededModulusSwitched {
    mask: Vec<usize>,
    body: usize,
    log_modulus: CiphertextModulusLog,
}

impl ModulusSwitchedLweCiphertext<usize> for PrfSeededModulusSwitched {
    fn log_modulus(&self) -> CiphertextModulusLog {
        self.log_modulus
    }

    fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.mask.len())
    }

    fn body(&self) -> usize {
        self.body
    }

    fn mask(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        self.mask.iter().copied()
    }
}

pub(crate) struct PrfMultiBitSeededModulusSwitched {
    seeded_modulus_switched: PrfSeededModulusSwitched,
    grouping_factor: LweBskGroupingFactor,
}

impl PrfMultiBitSeededModulusSwitched {
    pub(crate) fn from_raw_parts(
        seeded_modulus_switched: PrfSeededModulusSwitched,
        grouping_factor: LweBskGroupingFactor,
    ) -> Self {
        Self {
            seeded_modulus_switched,
            grouping_factor,
        }
    }
}

impl MultiBitModulusSwitchedLweCiphertext for PrfMultiBitSeededModulusSwitched {
    fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.seeded_modulus_switched.mask.len())
    }

    fn grouping_factor(&self) -> LweBskGroupingFactor {
        self.grouping_factor
    }

    fn switched_modulus_input_lwe_body(&self) -> usize {
        self.seeded_modulus_switched.body
    }

    fn switched_modulus_input_mask_per_group(
        &self,
        index: usize,
    ) -> impl Iterator<Item = usize> + '_ {
        let grouping_factor = self.grouping_factor;

        let lwe_mask_elements = &self.seeded_modulus_switched.mask
            [index * grouping_factor.0..(index + 1) * grouping_factor.0];

        let modulus = 1_usize
            .checked_shl(self.seeded_modulus_switched.log_modulus.0 as u32)
            .unwrap();

        (1..grouping_factor.ggsw_per_multi_bit_element().0).map(move |power_set_index| {
            let mut monomial_degree = 0;
            for (&mask_element, selection_bit) in lwe_mask_elements
                .iter()
                .zip_eq(selection_bit(grouping_factor, power_set_index))
            {
                monomial_degree = monomial_degree
                    .wrapping_add(selection_bit.wrapping_mul(mask_element))
                    % modulus;
            }

            monomial_degree
        })
    }
}

pub fn sha3_hash<Scalar>(values: &mut [Scalar], seed: Seed)
where
    Scalar: UnsignedInteger,
{
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut hasher = sha3::Shake256::default();

    let bytes = seed.0.to_le_bytes();

    hasher.update(bytes.as_slice());

    let mut reader = hasher.finalize_xof();

    for value in values {
        let bytes = bytemuck::bytes_of_mut(value);
        reader.read(bytes);
        // On little endian machine this is a no op, on big endian it will swap the bytes
        *value = value.to_le();
    }
}
pub fn create_random_from_seed<Scalar>(seed: Seed, lwe_size: LweSize) -> LweCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedInteger,
{
    // We use a native CiphertextModulus because the hash fills all the bits
    let mut ct = LweCiphertext::new(Scalar::ZERO, lwe_size, CiphertextModulus::new_native());

    sha3_hash(ct.get_mut_mask().as_mut(), seed);

    ct
}

pub(crate) fn create_random_from_seed_modulus_switched<Scalar>(
    seed: Seed,
    lwe_size: LweSize,
    log_modulus: CiphertextModulusLog,
) -> PrfSeededModulusSwitched
where
    Scalar: UnsignedInteger + CastInto<usize>,
{
    let ct = create_random_from_seed(seed, lwe_size);

    let mask = ct
        .get_mask()
        .as_ref()
        .iter()
        .map(|a: &Scalar| modulus_switch(*a, log_modulus).cast_into())
        .collect();

    let body = modulus_switch(*ct.get_body().data, log_modulus).cast_into();

    PrfSeededModulusSwitched {
        mask,
        body,
        log_modulus,
    }
}

#[allow(unused)]
pub(crate) fn raw_seeded_msed_to_lwe<Scalar: UnsignedInteger + CastFrom<usize>>(
    seeded: &PrfSeededModulusSwitched,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> LweCiphertextOwned<Scalar> {
    let log_modulus = seeded.log_modulus();

    let container: Vec<Scalar> = seeded
        .mask()
        .chain(std::iter::once(seeded.body()))
        .map(|i| {
            let i: Scalar = i.cast_into();
            i << (Scalar::BITS - log_modulus.0)
        })
        .collect();

    LweCiphertext::from_container(container, ciphertext_modulus)
}

/// Uniformly generates a random encrypted value in `[0, 2^random_bits_count[`, using a PBS.
///
/// `full_bits_count` is the size of the lwe message, ie the shortint message + carry + padding
/// bit.
/// The output in in the form 0000rrr000noise (rbc=3, fbc=7)
/// The encrypted value is oblivious to the server.
///
/// It is the reponsiblity of the calling AP to transform this into a shortint ciphertext. The
/// returned LWE is in the post PBS state, so a Keyswitch might be needed if the order is PBS-KS.
pub(crate) fn generate_pseudo_random_from_pbs<InputScalar>(
    bootstrapping_key: &ShortintBootstrappingKey<InputScalar>,
    seed: Seed,
    random_bits_count: u64,
    full_bits_count: u64,
    ciphertext_modulus: CiphertextModulus<u64>,
) -> (LweCiphertextOwned<u64>, Degree)
where
    InputScalar: UnsignedTorus + CastFrom<usize> + CastInto<usize>,
{
    assert!(
        random_bits_count <= full_bits_count,
        "The number of random bits asked for (={random_bits_count}) is bigger than full_bits_count (={full_bits_count})"
    );

    let in_lwe_size = bootstrapping_key.input_lwe_dimension().to_lwe_size();

    let polynomial_size = bootstrapping_key.polynomial_size();
    let seeded: PrfSeededModulusSwitched = create_random_from_seed_modulus_switched::<InputScalar>(
        seed,
        in_lwe_size,
        polynomial_size.to_blind_rotation_input_modulus_log(),
    );

    let p = 1 << random_bits_count;
    let degree = p - 1;

    let delta = 1_u64 << (64 - full_bits_count);

    let poly_delta = 2 * polynomial_size.0 as u64 / p;

    let lut_size = LookupTableSize::new(bootstrapping_key.glwe_size(), polynomial_size);
    let acc = generate_lookup_table_no_encode(lut_size, ciphertext_modulus, |x| {
        (2 * (x / poly_delta) + 1) * delta / 2
    });

    let out_lwe_size = bootstrapping_key.output_lwe_dimension().to_lwe_size();

    let mut ct = LweCiphertext::new(0, out_lwe_size, ciphertext_modulus);

    let mut glwe_out = acc;

    match bootstrapping_key {
        ShortintBootstrappingKey::Classic { bsk, .. } => {
            ShortintEngine::with_thread_local_mut(|engine| {
                let buffers = engine.get_computation_buffers();

                apply_standard_blind_rotate(bsk, &seeded, &mut glwe_out, buffers);
            });
        }
        ShortintBootstrappingKey::MultiBit {
            fourier_bsk,
            thread_count,
            deterministic_execution,
        } => {
            let seeded_multi_bit = PrfMultiBitSeededModulusSwitched::from_raw_parts(
                seeded,
                fourier_bsk.grouping_factor(),
            );

            apply_multi_bit_blind_rotate(
                &seeded_multi_bit,
                &mut glwe_out,
                fourier_bsk,
                *thread_count,
                *deterministic_execution,
            );
        }
    }

    extract_lwe_sample_from_glwe_ciphertext(&glwe_out, &mut ct, MonomialDegree(0));

    lwe_ciphertext_plaintext_add_assign(&mut ct, Plaintext(degree * delta / 2));
    (ct, Degree(degree))
}

impl<AP: AtomicPattern> GenericServerKey<AP> {
    /// Uniformly generates a random encrypted value in `[0, 2^random_bits_count[`
    /// `2^random_bits_count` must be smaller than the message modulus
    /// The encrypted value is oblivious to the server
    pub fn generate_oblivious_pseudo_random(
        &self,
        seed: Seed,
        random_bits_count: u64,
    ) -> Ciphertext {
        assert!(
            random_bits_count < 64,
            "random_bits_count >= 64 is not supported",
        );
        assert!(
            1 << random_bits_count <= self.message_modulus.0,
            "The range asked for a random value (=[0, 2^{}[) does not fit in the available range [0, {}[",
            random_bits_count, self.message_modulus.0
        );

        self.generate_oblivious_pseudo_random_message_and_carry(seed, random_bits_count)
    }

    /// Uniformly generates a random value in `[0, 2^random_bits_count[`
    /// The encrypted value is oblivious to the server
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

        let (ct, degree) = self.atomic_pattern.generate_oblivious_pseudo_random(
            seed,
            random_bits_count,
            1 + carry_bits_count + message_bits_count,
        );

        Ciphertext::new(
            ct,
            degree,
            NoiseLevel::NOMINAL,
            self.message_modulus,
            self.carry_modulus,
            self.atomic_pattern.kind(),
        )
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::core_crypto::prelude::{decrypt_lwe_ciphertext, CastInto, LweSecretKeyView};
    use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
    use crate::shortint::oprf::create_random_from_seed_modulus_switched;
    use crate::shortint::{ClientKey, ServerKey, ShortintParameterSet};
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
        use crate::shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        for params in [
            ShortintParameterSet::from(PARAM_MESSAGE_2_CARRY_2_KS_PBS),
            ShortintParameterSet::from(TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128),
        ] {
            let (ck, sk) = gen_keys(params);

            for seed in 0..1000 {
                oprf_compare_plain_from_seed(Seed(seed), &ck, &sk);
            }
        }
    }

    fn oprf_compare_plain_from_seed(seed: Seed, ck: &ClientKey, sk: &ServerKey) {
        let params = ck.parameters();

        let random_bits_count = 2;

        let input_p = 2 * params.polynomial_size().0 as u64;

        let p_prime = 1 << random_bits_count;

        let output_p = 2 * params.carry_modulus().0 * params.message_modulus().0;

        let poly_delta = 2 * params.polynomial_size().0 as u64 / p_prime;

        let img = sk.generate_oblivious_pseudo_random(seed, random_bits_count);

        let plain_prf_input = match &ck.atomic_pattern {
            AtomicPatternClientKey::Standard(ap_ck) => {
                gen_prf_input(&ap_ck.small_lwe_secret_key(), seed, params)
            }
            AtomicPatternClientKey::KeySwitch32(ap_ck) => {
                gen_prf_input(&ap_ck.small_lwe_secret_key(), seed, params)
            }
        };

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

    /// Returns the value used as input of the pbs for the prf with the provided seed
    fn gen_prf_input<Scalar>(
        sk: &LweSecretKeyView<Scalar>,
        seed: Seed,
        params: ShortintParameterSet,
    ) -> u64
    where
        Scalar: UnsignedInteger + CastFrom<usize> + CastInto<u64> + CastInto<usize>,
    {
        let lwe_size = params.lwe_dimension().to_lwe_size();
        let input_p = 2 * params.polynomial_size().0 as u64;
        let log_input_p = input_p.ilog2() as usize;

        let ciphertext_modulus = CiphertextModulus::new_native();

        let seeded = create_random_from_seed_modulus_switched::<Scalar>(
            seed,
            lwe_size,
            params
                .polynomial_size()
                .to_blind_rotation_input_modulus_log(),
        );

        let ct = raw_seeded_msed_to_lwe(&seeded, ciphertext_modulus);

        CastInto::<u64>::cast_into(
            decrypt_lwe_ciphertext(sk, &ct)
                .0
                .wrapping_add(Scalar::ONE << (Scalar::BITS - log_input_p - 1))
                >> (Scalar::BITS - log_input_p),
        )
    }

    #[test]
    fn oprf_test_uniformity_ci_run_filter() {
        let sample_count: usize = 100_000;

        let p_value_limit: f64 = 0.000_01;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::test_params::{
            TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        };
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        for params in [
            ShortintParameterSet::from(
                TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            ),
            ShortintParameterSet::from(PARAM_MESSAGE_2_CARRY_2_KS_PBS),
            ShortintParameterSet::from(TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128),
        ] {
            let (ck, sk) = gen_keys(params);

            let test_uniformity = |distinct_values: u64, f: &(dyn Fn(usize) -> u64 + Sync)| {
                test_uniformity(sample_count, p_value_limit, distinct_values, f)
            };

            let random_bits_count = 2;

            test_uniformity(1 << random_bits_count, &|seed| {
                let img =
                    sk.generate_oblivious_pseudo_random(Seed(seed as u128), random_bits_count);

                ck.decrypt_message_and_carry(&img)
            });
        }
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
