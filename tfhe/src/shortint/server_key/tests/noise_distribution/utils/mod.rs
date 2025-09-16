pub mod noise_simulation;
pub use noise_simulation::traits;

use crate::core_crypto::algorithms::glwe_encryption::decrypt_glwe_ciphertext;
use crate::core_crypto::algorithms::lwe_encryption::{
    allocate_and_encrypt_new_lwe_ciphertext, decrypt_lwe_ciphertext,
};
use crate::core_crypto::algorithms::misc::torus_modular_diff;
use crate::core_crypto::algorithms::test::round_decode;
use crate::core_crypto::commons::dispersion::{DispersionParameter, Variance};
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{ByteRandomGenerator, Gaussian, Uniform};
use crate::core_crypto::commons::noise_formulas::secure_noise::{
    minimal_lwe_variance_for_132_bits_security_gaussian,
    minimal_lwe_variance_for_132_bits_security_tuniform,
};
use crate::core_crypto::commons::numeric::{CastFrom, UnsignedInteger};
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DynamicDistribution, LweCiphertextCount, LweDimension, PlaintextCount,
};
use crate::core_crypto::commons::test_tools::{
    arithmetic_mean, equivalent_pfail_gaussian_noise, gaussian_mean_confidence_interval,
    gaussian_variance_confidence_interval, normality_test_f64,
    pfail_clopper_pearson_exact_confidence_interval, variance, NormalityTestResult,
};
use crate::core_crypto::commons::traits::container::Container;
use crate::core_crypto::commons::traits::Encryptable;
use crate::core_crypto::entities::glwe_ciphertext::GlweCiphertext;
use crate::core_crypto::entities::glwe_secret_key::GlweSecretKey;
use crate::core_crypto::entities::lwe_ciphertext::{LweCiphertext, LweCiphertextOwned};
use crate::core_crypto::entities::lwe_secret_key::LweSecretKey;
use crate::core_crypto::entities::{Cleartext, PlaintextList};
use crate::shortint::encoding::ShortintEncoding;
use crate::shortint::parameters::{
    AtomicPatternParameters, CarryModulus, MessageModulus, PBSParameters,
};

pub fn normality_check(
    noise_samples: &[f64],
    check_location: &str,
    alpha: f64,
) -> NormalityTestResult {
    let normality_check =
        normality_test_f64(&noise_samples[..5000.min(noise_samples.len())], alpha);

    if normality_check.null_hypothesis_is_valid {
        println!("Normality check {check_location} is OK\n");
    } else {
        println!("Normality check {check_location} failed\n");
    }

    normality_check
}

pub fn mean_and_variance_check<Scalar: UnsignedInteger>(
    noise_samples: &[f64],
    suffix: &str,
    expected_mean: f64,
    expected_variance: Variance,
    noise_distribution_used_for_encryption: DynamicDistribution<Scalar>,
    decryption_key_lwe_dimension: LweDimension,
    modulus_as_f64: f64,
) -> bool {
    assert!(expected_mean.is_finite(), "Expected mean is infinite");
    assert!(
        expected_variance.0.is_finite(),
        "Expected variance is infinite"
    );
    assert!(expected_variance.0 >= 0.0, "Expected positive variance");

    let measured_mean = arithmetic_mean(noise_samples);
    let measured_variance = variance(noise_samples);

    let mean_ci = gaussian_mean_confidence_interval(
        noise_samples.len() as f64,
        measured_mean,
        measured_variance.get_standard_dev(),
        0.99,
    );

    let variance_ci =
        gaussian_variance_confidence_interval(noise_samples.len() as f64, measured_variance, 0.99);

    println!("measured_variance_{suffix}={measured_variance:?}");
    println!("expected_variance_{suffix}={expected_variance:?}");
    println!("variance_lower_bound={:?}", variance_ci.lower_bound());
    println!("variance_upper_bound={:?}", variance_ci.upper_bound());
    println!("measured_mean_{suffix}={measured_mean:?}");
    println!("expected_mean_{suffix}={expected_mean:?}");
    println!("mean_{suffix}_lower_bound={:?}", mean_ci.lower_bound());
    println!("mean_{suffix}_upper_bound={:?}", mean_ci.upper_bound());

    // Expected mean is 0
    let mean_is_in_interval = mean_ci.mean_is_in_interval(expected_mean);

    if mean_is_in_interval {
        println!(
            "PASS: measured_mean_{suffix} confidence interval \
            contains the expected mean"
        );
    } else {
        println!(
            "FAIL: measured_mean_{suffix} confidence interval \
            does not contain the expected mean"
        );
    }

    // We want to be smaller but secure or in the interval
    let variance_is_ok = if measured_variance <= expected_variance {
        let noise_for_security = match noise_distribution_used_for_encryption {
            DynamicDistribution::Gaussian(_) => {
                minimal_lwe_variance_for_132_bits_security_gaussian(
                    decryption_key_lwe_dimension,
                    modulus_as_f64,
                )
            }
            DynamicDistribution::TUniform(_) => {
                minimal_lwe_variance_for_132_bits_security_tuniform(
                    decryption_key_lwe_dimension,
                    modulus_as_f64,
                )
            }
        };

        let variance_is_secure = measured_variance >= noise_for_security;

        if variance_is_secure {
            println!("PASS: measured_variance_{suffix} is smaller than expected variance.");

            if !variance_ci.variance_is_in_interval(expected_variance) {
                println!(
                    "\n==========\n\
                    Warning: noise formula might be over estimating the noise.\n\
                    ==========\n"
                );
            }
        } else {
            println!("FAIL: measured_variance_{suffix} is NOT secure.")
        }

        variance_is_secure
    } else {
        let interval_ok = variance_ci.variance_is_in_interval(expected_variance);

        if interval_ok {
            println!(
                "PASS: measured_variance_{suffix} confidence interval \
                contains the expected variance"
            );
        } else {
            println!(
                "FAIL: measured_variance_{suffix} confidence interval \
                does not contain the expected variance"
            );
        }

        interval_ok
    };

    mean_is_in_interval && variance_is_ok
}

pub fn encrypt_new_noiseless_lwe<
    Scalar: UnsignedInteger + Encryptable<Uniform, Gaussian<f64>> + CastFrom<u64>,
    InputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
>(
    lwe_secret_key: &LweSecretKey<InputKeyCont>,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    msg: Scalar,
    encoding: &ShortintEncoding<Scalar>,
    encryption_random_generation: &mut EncryptionRandomGenerator<Gen>,
) -> LweCiphertextOwned<Scalar> {
    let noiseless_distribution = Gaussian::from_dispersion_parameter(Variance(0.0), 0.0);

    let plaintext = encoding.encode(Cleartext(msg));

    allocate_and_encrypt_new_lwe_ciphertext(
        lwe_secret_key,
        plaintext,
        noiseless_distribution,
        ciphertext_modulus,
        encryption_random_generation,
    )
}

#[derive(Clone, Copy)]
pub struct PfailAndPrecision {
    pfail: f64,
    precision_with_padding: u32,
}

impl PfailAndPrecision {
    pub fn new(pfail: f64, msg_mod: MessageModulus, carry_mod: CarryModulus) -> Self {
        assert!(msg_mod.0.is_power_of_two());
        assert!(carry_mod.0.is_power_of_two());

        let precision_with_padding = precision_with_padding(msg_mod, carry_mod);

        Self {
            pfail,
            precision_with_padding,
        }
    }

    pub fn new_from_ap_params(ap_params: &AtomicPatternParameters) -> Self {
        Self::new(
            2.0f64.powf(ap_params.log2_p_fail()),
            ap_params.message_modulus(),
            ap_params.carry_modulus(),
        )
    }

    pub fn pfail(&self) -> f64 {
        self.pfail
    }

    pub fn precision_with_padding(&self) -> u32 {
        self.precision_with_padding
    }
}

#[derive(Clone, Copy)]
pub struct PfailTestMeta {
    original_pfail_and_precision: PfailAndPrecision,
    new_pfail_and_precision: PfailAndPrecision,
    expected_fails: u32,
    total_runs_for_expected_fails: u32,
}

impl PfailTestMeta {
    pub fn new_with_desired_expected_fails(
        original_pfail_and_precision: PfailAndPrecision,
        new_pfail_and_precision: PfailAndPrecision,
        expected_fails: u32,
    ) -> Self {
        let expected_fails_f64: f64 = expected_fails.into();
        let total_runs_for_expected_fails =
            (expected_fails_f64 / new_pfail_and_precision.pfail).round() as u32;

        println!("expected_fails: {expected_fails}");
        println!("total_runs_for_expected_fails: {total_runs_for_expected_fails}");

        Self {
            original_pfail_and_precision,
            new_pfail_and_precision,
            expected_fails,
            total_runs_for_expected_fails,
        }
    }

    pub fn new_with_total_runs(
        original_pfail_and_precision: PfailAndPrecision,
        new_pfail_and_precision: PfailAndPrecision,
        total_runs_for_expected_fails: u32,
    ) -> Self {
        let total_runs_f64: f64 = total_runs_for_expected_fails.into();
        let expected_fails = (total_runs_f64 * new_pfail_and_precision.pfail).round() as u32;

        println!("expected_fails: {expected_fails}");
        println!("total_runs_for_expected_fails: {total_runs_for_expected_fails}");

        Self {
            original_pfail_and_precision,
            new_pfail_and_precision,
            expected_fails,
            total_runs_for_expected_fails,
        }
    }

    pub fn original_pfail_and_precision(&self) -> PfailAndPrecision {
        self.original_pfail_and_precision
    }
    pub fn new_pfail_and_precision(&self) -> PfailAndPrecision {
        self.new_pfail_and_precision
    }
    pub fn expected_fails(&self) -> u32 {
        self.expected_fails
    }
    pub fn total_runs_for_expected_fails(&self) -> u32 {
        self.total_runs_for_expected_fails
    }
}

#[derive(Clone, Copy)]
pub struct PfailTestResult {
    pub measured_fails: f64,
}

pub fn pfail_check(pfail_test_meta: &PfailTestMeta, pfail_test_result: PfailTestResult) {
    let measured_fails = pfail_test_result.measured_fails;
    let total_runs_for_expected_fails = pfail_test_meta.total_runs_for_expected_fails;
    let expected_fails = pfail_test_meta.expected_fails();

    let new_pfail_and_precision = pfail_test_meta.new_pfail_and_precision();
    let expected_pfail = new_pfail_and_precision.pfail();
    let new_precision_with_padding = pfail_test_meta
        .new_pfail_and_precision
        .precision_with_padding();

    let original_pfail_and_precision = pfail_test_meta.original_pfail_and_precision();
    let original_pfail = original_pfail_and_precision.pfail();
    let original_precision_with_padding = original_pfail_and_precision.precision_with_padding();

    let measured_pfail = measured_fails / (total_runs_for_expected_fails as f64);

    println!("measured_fails={measured_fails}");
    println!("expected_fails={expected_fails}");
    println!("measured_pfail={measured_pfail}");
    println!("expected_pfail={expected_pfail}");

    let equivalent_measured_pfail = equivalent_pfail_gaussian_noise(
        new_precision_with_padding,
        measured_pfail,
        original_precision_with_padding,
    );

    println!("equivalent_measured_pfail={equivalent_measured_pfail}");
    println!("original_expected_pfail  ={original_pfail}");
    println!(
        "equivalent_measured_pfail_log2={}",
        equivalent_measured_pfail.log2()
    );
    println!("original_expected_pfail_log2  ={}", original_pfail.log2());

    if measured_fails > 0.0 {
        let pfail_confidence_interval = pfail_clopper_pearson_exact_confidence_interval(
            total_runs_for_expected_fails as f64,
            measured_fails,
            0.99,
        );

        let pfail_lower_bound = pfail_confidence_interval.lower_bound();
        let pfail_upper_bound = pfail_confidence_interval.upper_bound();
        println!("pfail_lower_bound={pfail_lower_bound}");
        println!("pfail_upper_bound={pfail_upper_bound}");

        let equivalent_pfail_lower_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_lower_bound,
            original_precision_with_padding,
        );
        let equivalent_pfail_upper_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_upper_bound,
            original_precision_with_padding,
        );

        println!("equivalent_pfail_lower_bound={equivalent_pfail_lower_bound}");
        println!("equivalent_pfail_upper_bound={equivalent_pfail_upper_bound}");
        println!(
            "equivalent_pfail_lower_bound_log2={}",
            equivalent_pfail_lower_bound.log2()
        );
        println!(
            "equivalent_pfail_upper_bound_log2={}",
            equivalent_pfail_upper_bound.log2()
        );

        if measured_pfail <= expected_pfail {
            if !pfail_confidence_interval.mean_is_in_interval(expected_pfail) {
                println!(
                    "\n==========\n\
                    WARNING: measured pfail is smaller than expected pfail \
                    and out of the confidence interval\n\
                    the optimizer might be pessimistic when generating parameters.\n\
                    ==========\n"
                );
            }
        } else {
            assert!(pfail_confidence_interval.mean_is_in_interval(expected_pfail));
        }
    } else {
        println!(
            "\n==========\n\
            WARNING: measured pfail is 0, it is either a bug or \
            it is way smaller than the expected pfail\n\
            the optimizer might be pessimistic when generating parameters, \
            or some hypothesis does not hold.\n\
            ==========\n"
        );
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NoiseSample {
    pub value: f64,
}

#[derive(Clone, Copy, Debug)]
pub enum DecryptionAndNoiseResult {
    DecryptionSucceeded { noise: NoiseSample },
    DecryptionFailed,
}

impl DecryptionAndNoiseResult {
    pub fn new_from_lwe<Scalar: UnsignedInteger + CastFrom<u64>, CtCont, KeyCont>(
        ct: &LweCiphertext<CtCont>,
        secret_key: &LweSecretKey<KeyCont>,
        expected_msg: Scalar,
        encoding: &ShortintEncoding<Scalar>,
    ) -> Self
    where
        CtCont: Container<Element = Scalar>,
        KeyCont: Container<Element = Scalar>,
    {
        let decrypted_plaintext = decrypt_lwe_ciphertext(secret_key, ct).0;

        let delta = encoding.delta();
        let cleartext_modulus_with_padding = encoding.full_cleartext_space();

        // We apply the modulus on the cleartext + the padding bit
        let decoded_msg = round_decode(decrypted_plaintext, delta) % cleartext_modulus_with_padding;

        let expected_plaintext = expected_msg * delta;

        // decrypted_plaintext = expected_plaintext + error
        // The order below computes:
        // decrypted_plaintext - expected_plaintext in a modular way, which is what we want
        // It only changes the average value sign, so that it is more intuitive when comparing to
        // theory
        let noise = torus_modular_diff(
            decrypted_plaintext,
            expected_plaintext,
            ct.ciphertext_modulus(),
        );

        if decoded_msg == expected_msg {
            Self::DecryptionSucceeded {
                noise: NoiseSample { value: noise },
            }
        } else {
            Self::DecryptionFailed
        }
    }

    pub fn new_from_glwe<Scalar: UnsignedInteger + CastFrom<u64>, CtCont, KeyCont>(
        ct: &GlweCiphertext<CtCont>,
        secret_key: &GlweSecretKey<KeyCont>,
        lwe_per_glwe: LweCiphertextCount,
        expected_msg: Scalar,
        encoding: &ShortintEncoding<Scalar>,
    ) -> Vec<Self>
    where
        CtCont: Container<Element = Scalar>,
        KeyCont: Container<Element = Scalar>,
    {
        let mut decrypted =
            PlaintextList::new(Scalar::ZERO, PlaintextCount(ct.polynomial_size().0));

        let delta = encoding.delta();
        let cleartext_modulus_with_padding = encoding.full_cleartext_space();

        decrypt_glwe_ciphertext(secret_key, ct, &mut decrypted);

        let expected_plaintext = expected_msg * delta;

        decrypted
            .as_ref()
            .iter()
            .take(lwe_per_glwe.0)
            .map(|&decrypted_plaintext| {
                // We apply the modulus on the cleartext + the padding bit
                let decoded_msg =
                    round_decode(decrypted_plaintext, delta) % cleartext_modulus_with_padding;

                let noise = torus_modular_diff(
                    expected_plaintext,
                    decrypted_plaintext,
                    ct.ciphertext_modulus(),
                );

                if decoded_msg == expected_msg {
                    Self::DecryptionSucceeded {
                        noise: NoiseSample { value: noise },
                    }
                } else {
                    Self::DecryptionFailed
                }
            })
            .collect()
    }

    pub fn get_noise_if_decryption_was_correct(&self) -> Option<NoiseSample> {
        match self {
            Self::DecryptionSucceeded { noise } => Some(*noise),
            Self::DecryptionFailed => None,
        }
    }

    /// If decryption failed (in context of pfail evaluation) returns 1.0 else 0.0, to easily sum
    /// failures to evaluate pfail
    pub fn failure_as_f64(&self) -> f64 {
        match self {
            Self::DecryptionSucceeded { .. } => 0.0,
            Self::DecryptionFailed => 1.0,
        }
    }
}

pub fn update_ap_params_for_pfail(
    ap_params: &mut AtomicPatternParameters,
    new_message_modulus: MessageModulus,
    new_carry_modulus: CarryModulus,
) -> (PfailAndPrecision, PfailAndPrecision) {
    let orig_pfail_and_precision = PfailAndPrecision::new_from_ap_params(&*ap_params);

    println!("original_pfail: {}", orig_pfail_and_precision.pfail());
    println!(
        "original_pfail_log2: {}",
        orig_pfail_and_precision.pfail().log2()
    );

    match ap_params {
        AtomicPatternParameters::Standard(pbsparameters) => match pbsparameters {
            PBSParameters::PBS(classic_pbsparameters) => {
                classic_pbsparameters.message_modulus = new_message_modulus;
                classic_pbsparameters.carry_modulus = new_carry_modulus;
            }
            PBSParameters::MultiBitPBS(multi_bit_pbsparameters) => {
                multi_bit_pbsparameters.message_modulus = new_message_modulus;
                multi_bit_pbsparameters.carry_modulus = new_carry_modulus;
            }
        },
        AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
            key_switch32_pbsparameters.message_modulus = new_message_modulus;
            key_switch32_pbsparameters.carry_modulus = new_carry_modulus;
        }
    }

    let new_expected_pfail = equivalent_pfail_gaussian_noise(
        orig_pfail_and_precision.precision_with_padding(),
        orig_pfail_and_precision.pfail(),
        precision_with_padding(ap_params.message_modulus(), ap_params.carry_modulus()),
    );
    let new_expected_log2_pfail = new_expected_pfail.log2();

    match ap_params {
        AtomicPatternParameters::Standard(pbsparameters) => match pbsparameters {
            PBSParameters::PBS(classic_pbsparameters) => {
                classic_pbsparameters.log2_p_fail = new_expected_log2_pfail;
            }
            PBSParameters::MultiBitPBS(multi_bit_pbsparameters) => {
                multi_bit_pbsparameters.log2_p_fail = new_expected_log2_pfail;
            }
        },
        AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
            key_switch32_pbsparameters.log2_p_fail = new_expected_log2_pfail;
        }
    }

    let new_expected_pfail = PfailAndPrecision::new_from_ap_params(&*ap_params);

    println!("new_expected_pfail: {}", new_expected_pfail.pfail());
    println!(
        "new_expected_pfail_log2: {}",
        new_expected_pfail.pfail().log2()
    );

    (orig_pfail_and_precision, new_expected_pfail)
}

pub fn precision_with_padding(msg_mod: MessageModulus, carr_mod: CarryModulus) -> u32 {
    let cleartext_modulus = msg_mod.0 * carr_mod.0;
    assert!(cleartext_modulus.is_power_of_two());
    cleartext_modulus.ilog2() + 1
}
