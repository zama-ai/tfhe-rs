pub mod noise_simulation;
pub mod to_json;
pub mod traits;

use crate::core_crypto::algorithms::glwe_encryption::decrypt_glwe_ciphertext;
use crate::core_crypto::algorithms::lwe_encryption::{
    allocate_and_encrypt_new_lwe_ciphertext, decrypt_lwe_ciphertext,
};
use crate::core_crypto::algorithms::lwe_multi_bit_programmable_bootstrapping::{
    MultiBitModulusSwitchedLweCiphertext, StandardMultiBitModulusSwitchedCt,
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
use crate::core_crypto::commons::numeric::{CastFrom, CastInto, UnsignedInteger};
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
use crate::core_crypto::entities::{Cleartext, Plaintext, PlaintextList};
use crate::shortint::encoding::ShortintEncoding;
use crate::shortint::parameters::{
    AtomicPatternParameters, CarryModulus, MessageModulus, MetaParameters, PBSParameters,
};
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    DynLwe, DynLweSecretKeyView, DynModSwitchedLwe, DynStandardMultiBitModulusSwitchedCt,
};
use crate::shortint::server_key::tests::noise_distribution::utils::to_json::{
    write_to_json_file, BoundedLog2Measurement, BoundedMeasurement, ConfidenceInterval,
    ConfidenceIntervalWithLog2, Measurement, NoBounds, PfailMetadata, PfailTestResultJson,
    StringConfidenceInterval, StringConfidenceIntervalWithLog2, ValueWithLog2,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrecisionWithPadding {
    value: u32,
}

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
) -> (bool, BoundedMeasurement, BoundedMeasurement) {
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

    let bounded_variance_measurement = BoundedMeasurement::new(
        measured_variance.0.to_string(),
        expected_variance.0.to_string(),
        ConfidenceInterval::Bounded(
            StringConfidenceInterval::builder()
                .lower(variance_ci.lower_bound().0.to_string())
                .upper(variance_ci.upper_bound().0.to_string())
                .build()
                .unwrap(),
        ),
    );
    let bounded_mean_measurement = BoundedMeasurement::new(
        measured_mean.to_string(),
        expected_mean.to_string(),
        ConfidenceInterval::Bounded(
            StringConfidenceInterval::builder()
                .lower(mean_ci.lower_bound().to_string())
                .upper(mean_ci.upper_bound().to_string())
                .build()
                .unwrap(),
        ),
    );

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

    (
        mean_is_in_interval && variance_is_ok,
        bounded_variance_measurement,
        bounded_mean_measurement,
    )
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
    precision_with_padding: PrecisionWithPadding,
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

    pub fn precision_with_padding(&self) -> PrecisionWithPadding {
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

    pub fn generate_serializable_data(self) -> PfailMetadata {
        PfailMetadata::new(
            ValueWithLog2::new(
                self.original_pfail_and_precision.pfail().to_string(),
                self.original_pfail_and_precision.pfail().log2().to_string(),
            ),
            ValueWithLog2::new(
                self.new_pfail_and_precision.pfail().to_string(),
                self.new_pfail_and_precision.pfail().log2().to_string(),
            ),
            self.expected_fails.to_string(),
            self.total_runs_for_expected_fails.to_string(),
        )
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

pub fn pfail_check(
    pfail_test_meta: &PfailTestMeta,
    pfail_test_result: PfailTestResult,
    param_name: &MetaParameters,
    test_name: &str,
    test_module_path: &str,
) {
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
        new_precision_with_padding.value,
        measured_pfail,
        original_precision_with_padding.value,
    );

    println!("equivalent_measured_pfail={equivalent_measured_pfail}");
    println!("original_expected_pfail  ={original_pfail}");
    println!(
        "equivalent_measured_pfail_log2={}",
        equivalent_measured_pfail.log2()
    );
    println!("original_expected_pfail_log2  ={}", original_pfail.log2());

    let pfail_meta_serialized = pfail_test_meta.generate_serializable_data();

    let fails_serialized = Measurement::new(measured_fails.to_string(), expected_fails.to_string());

    let pfail_serialized_closure = |confidence_interval: ConfidenceInterval| {
        BoundedMeasurement::new(
            measured_pfail.to_string(),
            expected_pfail.to_string(),
            confidence_interval,
        )
    };

    let pfail_original_serialized_closure =
        |confidence_interval_with_log2: ConfidenceIntervalWithLog2| {
            BoundedLog2Measurement::new(
                ValueWithLog2::new(
                    equivalent_measured_pfail.to_string(),
                    equivalent_measured_pfail.log2().to_string(),
                ),
                ValueWithLog2::new(
                    original_pfail.to_string(),
                    original_pfail.log2().to_string(),
                ),
                confidence_interval_with_log2,
            )
        };

    let write_json = |warning: Option<String>,
                      pass: bool,
                      pfail_serialized: BoundedMeasurement,
                      pfail_original_serialized: BoundedLog2Measurement| {
        write_to_json_file(
            param_name,
            test_name,
            test_module_path,
            pass,
            warning,
            PfailTestResultJson::new(
                pfail_meta_serialized.clone(),
                fails_serialized.clone(),
                pfail_serialized,
                pfail_original_serialized,
            )
            .into_test_result(),
        )
        .unwrap();
    };

    if measured_fails > 0.0 {
        let pfail_confidence_interval = pfail_clopper_pearson_exact_confidence_interval(
            total_runs_for_expected_fails as f64,
            measured_fails,
            0.99,
        );

        let pfail_lower_bound = pfail_confidence_interval.lower_bound();
        let pfail_upper_bound = pfail_confidence_interval.upper_bound();

        let equivalent_pfail_lower_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding.value,
            pfail_lower_bound,
            original_precision_with_padding.value,
        );
        let equivalent_pfail_upper_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding.value,
            pfail_upper_bound,
            original_precision_with_padding.value,
        );

        let confidence_interval = ConfidenceInterval::Bounded(
            StringConfidenceInterval::builder()
                .lower(pfail_lower_bound.to_string())
                .upper(pfail_upper_bound.to_string())
                .build()
                .unwrap(),
        );
        let confidence_interval_with_log2 = ConfidenceIntervalWithLog2::Bounded(
            StringConfidenceIntervalWithLog2::builder()
                .lower(ValueWithLog2::new(
                    equivalent_pfail_lower_bound.to_string(),
                    equivalent_pfail_lower_bound.log2().to_string(),
                ))
                .upper(ValueWithLog2::new(
                    equivalent_pfail_upper_bound.to_string(),
                    equivalent_pfail_upper_bound.log2().to_string(),
                ))
                .build()
                .unwrap(),
        );
        println!("pfail_lower_bound={pfail_lower_bound}");
        println!("pfail_upper_bound={pfail_upper_bound}");

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

        let pfail_serialized = pfail_serialized_closure(confidence_interval);
        let pfail_original_serialized =
            pfail_original_serialized_closure(confidence_interval_with_log2);

        if measured_pfail <= expected_pfail {
            let mut warning = None;
            if !pfail_confidence_interval.mean_is_in_interval(expected_pfail) {
                let warning_raw = "measured pfail is smaller than expected pfail \
                    and out of the confidence interval. \n\
                    the optimizer might be pessimistic when generating parameters.";
                let warning_message = format_warning_message(warning_raw);
                warning = Some(format_json_warning_message(warning_raw));
                println!("{warning_message}");
            }
            write_json(warning, true, pfail_serialized, pfail_original_serialized)
        } else {
            let cond = pfail_confidence_interval.mean_is_in_interval(expected_pfail);
            write_json(None, cond, pfail_serialized, pfail_original_serialized);
            assert!(cond);
        }
    } else {
        let confidence_interval = ConfidenceInterval::NoBounds(NoBounds::new(
            "Unable to compute bounds, 0 fails measured",
        ));
        let confidence_interval_with_log2 = ConfidenceIntervalWithLog2::NoBounds(NoBounds::new(
            "Unable to compute bounds, 0 fails measured",
        ));
        let warning_raw = "measured pfail is 0, it is either a bug or \
            it is way smaller than the expected pfail. \n\
            the optimizer might be pessimistic when generating parameters, \
            or some hypothesis does not hold.";
        let warning = format_warning_message(warning_raw);
        write_json(
            Some(format_json_warning_message(warning_raw)),
            true,
            pfail_serialized_closure(confidence_interval),
            pfail_original_serialized_closure(confidence_interval_with_log2),
        );
        println!("{warning}");
    }
}

fn format_json_warning_message(m: &str) -> String {
    m.replace(['\n', '\\'], "")
}

fn format_warning_message(to_print: &str) -> String {
    format!(
        "\n==========\n\
    WARNING: {to_print}\n\
    ==========\n"
    )
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
    pub fn new_from_plaintext<Scalar: UnsignedInteger + CastFrom<u64>>(
        decrypted_plaintext: Plaintext<Scalar>,
        expected_msg: Scalar,
        encoding: &ShortintEncoding<Scalar>,
    ) -> Self {
        let delta = encoding.delta();
        let cleartext_modulus_with_padding = encoding.full_cleartext_space();

        // We apply the modulus on the cleartext + the padding bit
        let decoded_msg =
            round_decode(decrypted_plaintext.0, delta) % cleartext_modulus_with_padding;

        let expected_plaintext = expected_msg * delta;

        // decrypted_plaintext = expected_plaintext + error
        // The order below computes:
        // decrypted_plaintext - expected_plaintext in a modular way, which is what we want
        // It only changes the average value sign, so that it is more intuitive when comparing to
        // theory
        let noise = torus_modular_diff(
            decrypted_plaintext.0,
            expected_plaintext,
            encoding.ciphertext_modulus,
        );

        if decoded_msg == expected_msg {
            Self::DecryptionSucceeded {
                noise: NoiseSample { value: noise },
            }
        } else {
            Self::DecryptionFailed
        }
    }

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
        let decrypted_plaintext = decrypt_lwe_ciphertext(secret_key, ct);

        Self::new_from_plaintext(decrypted_plaintext, expected_msg, encoding)
    }

    pub fn new_from_dyn_lwe(
        ct: &DynLwe,
        secret_key: &DynLweSecretKeyView<'_>,
        expected_msg: u64,
    ) -> Self {
        match (ct, secret_key) {
            (DynLwe::U32(lwe_ciphertext), DynLweSecretKeyView::U32 { key, encoding }) => {
                Self::new_from_lwe(
                    lwe_ciphertext,
                    key,
                    expected_msg.try_into().unwrap(),
                    encoding,
                )
            }
            (DynLwe::U64(lwe_ciphertext), DynLweSecretKeyView::U64 { key, encoding }) => {
                Self::new_from_lwe(lwe_ciphertext, key, expected_msg, encoding)
            }
            _ => panic!("Incompatible types in DecryptionAndNoiseResult::new_from_dyn_lwe"),
        }
    }

    pub fn new_from_dyn_multi_bit_mod_switched_lwe(
        ct: &DynStandardMultiBitModulusSwitchedCt,
        secret_key: &DynLweSecretKeyView<'_>,
        expected_msg: u64,
    ) -> Self {
        match (ct, secret_key) {
            (
                DynStandardMultiBitModulusSwitchedCt::U32(standard_multi_bit_modulus_switched_ct),
                DynLweSecretKeyView::U32 { key, encoding },
            ) => {
                let decrypted_plaintext = decrypt_multi_bit_mod_switched_lwe_ciphertext(
                    key,
                    standard_multi_bit_modulus_switched_ct,
                );
                Self::new_from_plaintext(
                    decrypted_plaintext,
                    expected_msg.try_into().unwrap(),
                    encoding,
                )
            }
            (
                DynStandardMultiBitModulusSwitchedCt::U64(standard_multi_bit_modulus_switched_ct),
                DynLweSecretKeyView::U64 { key, encoding },
            ) => {
                let decrypted_plaintext = decrypt_multi_bit_mod_switched_lwe_ciphertext(
                    key,
                    standard_multi_bit_modulus_switched_ct,
                );
                Self::new_from_plaintext(decrypted_plaintext, expected_msg, encoding)
            }
            _ => panic!(
                "Incompatible types in \
                DecryptionAndNoiseResult::new_from_dyn_multi_bit_mod_switched_lwe"
            ),
        }
    }

    pub fn new_from_dyn_modswitched_lwe(
        ct: &DynModSwitchedLwe,
        secret_key: &DynLweSecretKeyView<'_>,
        expected_msg: u64,
    ) -> Self {
        match ct {
            DynModSwitchedLwe::ModSwitchedLwe(dyn_lwe) => {
                Self::new_from_dyn_lwe(dyn_lwe, secret_key, expected_msg)
            }
            DynModSwitchedLwe::MultiBitModSwitchedLwe(
                dyn_standard_multi_bit_modulus_switched_ct,
            ) => Self::new_from_dyn_multi_bit_mod_switched_lwe(
                dyn_standard_multi_bit_modulus_switched_ct,
                secret_key,
                expected_msg,
            ),
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

pub fn update_ap_params_msg_and_carry_moduli(
    ap_params: &mut AtomicPatternParameters,
    new_message_modulus: MessageModulus,
    new_carry_modulus: CarryModulus,
) {
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
}

pub fn update_ap_params_for_pfail(
    ap_params: &mut AtomicPatternParameters,
    new_message_modulus: MessageModulus,
    new_carry_modulus: CarryModulus,
) -> (PfailAndPrecision, PfailAndPrecision) {
    let orig_pfail_and_precision = PfailAndPrecision::new_from_ap_params(ap_params);

    println!("original_pfail: {}", orig_pfail_and_precision.pfail());
    println!(
        "original_pfail_log2: {}",
        orig_pfail_and_precision.pfail().log2()
    );

    update_ap_params_msg_and_carry_moduli(ap_params, new_message_modulus, new_carry_modulus);

    let new_expected_pfail = equivalent_pfail_gaussian_noise(
        orig_pfail_and_precision.precision_with_padding().value,
        orig_pfail_and_precision.pfail(),
        precision_with_padding(ap_params.message_modulus(), ap_params.carry_modulus()).value,
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

pub fn precision_with_padding(
    msg_mod: MessageModulus,
    carry_mod: CarryModulus,
) -> PrecisionWithPadding {
    let cleartext_modulus = msg_mod.0 * carry_mod.0;
    assert!(cleartext_modulus.is_power_of_two());
    PrecisionWithPadding {
        value: cleartext_modulus.ilog2() + 1,
    }
}

pub fn expected_pfail_for_precision(
    precision_with_padding: PrecisionWithPadding,
    variance: Variance,
) -> f64 {
    // The additional 1 is to guarantee proper decryption
    let precision_for_proper_decryption: i32 =
        (precision_with_padding.value + 1).try_into().unwrap();
    let correctness_threshold = 2.0f64.powi(-precision_for_proper_decryption);

    let measured_std_dev = variance.get_standard_dev().0;
    let measured_std_score = correctness_threshold / measured_std_dev;

    statrs::function::erf::erfc(measured_std_score / core::f64::consts::SQRT_2)
}

pub fn decrypt_multi_bit_mod_switched_lwe_ciphertext<Scalar, CtCont, KeyCont>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    mod_switched_lwe: &StandardMultiBitModulusSwitchedCt<Scalar, CtCont>,
) -> Plaintext<Scalar>
where
    Scalar: UnsignedInteger + CastFrom<usize> + CastInto<usize>,
    CtCont: Container<Element = Scalar> + Sync,
    KeyCont: Container<Element = Scalar>,
{
    let mut result: Scalar = mod_switched_lwe
        .switched_modulus_input_lwe_body()
        .cast_into();

    let log_modulus = mod_switched_lwe.log_modulus;
    let grouping_factor = mod_switched_lwe.grouping_factor();

    let shift_to_native = Scalar::BITS - log_modulus.0;

    result <<= shift_to_native;

    for (loop_idx, lwe_key_bits) in lwe_secret_key
        .as_ref()
        .chunks_exact(grouping_factor.0)
        .enumerate()
    {
        let selector = {
            let mut selector = 0usize;
            for bit in lwe_key_bits.iter() {
                let bit: usize = (*bit).cast_into();
                selector <<= 1;
                selector |= bit;
            }
            if selector == 0 {
                // We dont generate a mod switched value for selector == 0 it corresponds to key
                // bits == 0
                None
            } else {
                // We subtract 1 to be coherent with the fact the first mod switched value is not
                // generated
                Some(selector - 1)
            }
        };

        if let Some(selector) = selector {
            let mod_switched: Scalar = mod_switched_lwe
                .switched_modulus_input_mask_per_group(loop_idx)
                .nth(selector)
                .unwrap()
                .cast_into();
            // Put in the high bits same as the body to be able to measure the noise in the
            // encompassing modulus
            let mod_switched = mod_switched << shift_to_native;
            result = result.wrapping_sub(mod_switched);
        }
    }
    Plaintext(result)
}

#[test]
fn test_expected_pfail_for_ci_run_filter() {
    // Practical check on a compression-like scenario, of interest because pfail is known to be very
    // low
    let precision_with_padding = precision_with_padding(MessageModulus(1 << 2), CarryModulus(1));
    let theoretical_variance = Variance(1.0216297411906617e-5);

    assert_eq!(
        expected_pfail_for_precision(precision_with_padding, theoretical_variance).log2(),
        -280.4295428516361
    );
}
