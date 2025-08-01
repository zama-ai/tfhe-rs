pub mod noise_simulation;
pub mod traits;

use crate::core_crypto::algorithms::glwe_encryption::decrypt_glwe_ciphertext;
use crate::core_crypto::algorithms::lwe_encryption::decrypt_lwe_ciphertext;
use crate::core_crypto::algorithms::lwe_keyswitch::{
    keyswitch_lwe_ciphertext, keyswitch_lwe_ciphertext_with_scalar_change,
};
use crate::core_crypto::algorithms::lwe_linear_algebra::{
    lwe_ciphertext_cleartext_mul, lwe_ciphertext_cleartext_mul_assign,
};
use crate::core_crypto::algorithms::lwe_packing_keyswitch::par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext;
use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::fft128_pbs::programmable_bootstrap_f128_lwe_ciphertext;
use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::fft64_pbs::programmable_bootstrap_lwe_ciphertext;
use crate::core_crypto::algorithms::misc::torus_modular_diff;
use crate::core_crypto::algorithms::test::round_decode;
use crate::core_crypto::commons::dispersion::{DispersionParameter, Variance};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::noise_formulas::secure_noise::{
    minimal_lwe_variance_for_132_bits_security_gaussian,
    minimal_lwe_variance_for_132_bits_security_tuniform,
};
use crate::core_crypto::commons::numeric::{CastFrom, CastInto, UnsignedInteger};
use crate::core_crypto::commons::parameters::{
    CiphertextModulusLog, DynamicDistribution, LweCiphertextCount, LweDimension, PlaintextCount,
};
use crate::core_crypto::commons::test_tools::{
    arithmetic_mean, equivalent_pfail_gaussian_noise, gaussian_mean_confidence_interval,
    gaussian_variance_confidence_interval, normality_test_f64,
    pfail_clopper_pearson_exact_confidence_interval, variance, NormalityTestResult,
};
use crate::core_crypto::commons::traits::container::{Container, ContainerMut};
use crate::core_crypto::entities::glwe_ciphertext::{GlweCiphertext, GlweCiphertextOwned};
use crate::core_crypto::entities::glwe_secret_key::GlweSecretKey;
use crate::core_crypto::entities::lwe_ciphertext::{LweCiphertext, LweCiphertextOwned};
use crate::core_crypto::entities::lwe_ciphertext_list::LweCiphertextList;
use crate::core_crypto::entities::lwe_keyswitch_key::LweKeyswitchKey;
use crate::core_crypto::entities::lwe_packing_keyswitch_key::LwePackingKeyswitchKey;
use crate::core_crypto::entities::lwe_secret_key::LweSecretKey;
use crate::core_crypto::entities::{Cleartext, PlaintextList};
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKey;
use crate::core_crypto::fft_impl::fft64::c64;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::fft64::math::fft::id;
use crate::shortint::encoding::ShortintEncoding;
use crate::shortint::parameters::{
    AtomicPatternParameters, CarryModulus, MessageModulus, PBSParameters,
};
use crate::shortint::server_key::modulus_switch_noise_reduction::ModulusSwitchNoiseReductionKey;
use std::any::TypeId;
use traits::*;

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
            println!("FAIL:measured_variance_{suffix} is NOT secure.")
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
    pub fn new<Scalar: UnsignedInteger + CastFrom<u64>, CtCont, KeyCont>(
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

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ScalarMul<Scalar>
    for LweCiphertext<C>
{
    type Output = LweCiphertextOwned<Scalar>;
    type SideResources = ();

    fn scalar_mul(&self, rhs: Scalar, _side_resources: &mut Self::SideResources) -> Self::Output {
        let mut output =
            LweCiphertextOwned::from_container(self.as_ref().to_vec(), self.ciphertext_modulus());
        lwe_ciphertext_cleartext_mul(&mut output, self, Cleartext(rhs));
        output
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ScalarMulAssign<Scalar>
    for LweCiphertext<C>
{
    type SideResources = ();

    fn scalar_mul_assign(&mut self, rhs: Scalar, _side_resources: &mut Self::SideResources) {
        lwe_ciphertext_cleartext_mul_assign(self, Cleartext(rhs));
    }
}

impl<Scalar: UnsignedInteger, KeyCont: Container<Element = Scalar>> AllocateKeyswtichResult
    for LweKeyswitchKey<KeyCont>
{
    type Output = LweCiphertextOwned<Scalar>;
    type SideResources = ();

    fn allocate_keyswitch_result(&self, _side_resources: &mut Self::SideResources) -> Self::Output {
        Self::Output::new(
            Scalar::ZERO,
            self.output_lwe_size(),
            self.ciphertext_modulus(),
        )
    }
}

impl<
        InputScalar: UnsignedInteger,
        OutputScalar: UnsignedInteger + CastFrom<InputScalar>,
        KeyCont: Container<Element = OutputScalar>,
        InputCont: Container<Element = InputScalar>,
        OutputCont: ContainerMut<Element = OutputScalar>,
    > Keyswitch<LweCiphertext<InputCont>, LweCiphertext<OutputCont>> for LweKeyswitchKey<KeyCont>
{
    type SideResources = ();

    fn keyswitch(
        &self,
        input: &LweCiphertext<InputCont>,
        output: &mut LweCiphertext<OutputCont>,
        _side_resources: &mut Self::SideResources,
    ) {
        // We are forced to do this because rust complains of conflicting trait implementations even
        // though generics are different, it's not enough to rule that actual concrete types are
        // different, but in our case they would be mutually exclusive
        if TypeId::of::<InputScalar>() == TypeId::of::<OutputScalar>() {
            // Cannot use Any as Any requires a type to be 'static (lifetime information is not
            // available at runtime, it's lost during compilation and only used for the rust borrock
            // "proofs", so types need to be 'static to use the dynamic runtime Any facilities)
            // Let's operate on views, we know types are supposed to be the same, so convert the
            // slice (as we already have the primitive) and cast the modulus which will be a no-op
            // in practice
            let input_content = input.as_ref();
            let input_as_output_scalar = LweCiphertext::from_container(
                id(input_content),
                input.ciphertext_modulus().try_to().unwrap(),
            );
            keyswitch_lwe_ciphertext(self, &input_as_output_scalar, output);
        } else {
            keyswitch_lwe_ciphertext_with_scalar_change(self, input, output);
        }
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> AllocateStandardPBSModSwitchResult
    for LweCiphertext<C>
{
    type Output = LweCiphertextOwned<Scalar>;
    type SideResources = ();

    fn allocate_standard_mod_switch_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        // We will mod switch but we keep the current modulus as the noise is interesting in the
        // context of the input modulus
        Self::Output::new(Scalar::ZERO, self.lwe_size(), self.ciphertext_modulus())
    }
}

impl<
        Scalar: UnsignedInteger,
        InputCont: Container<Element = Scalar>,
        OutputCont: ContainerMut<Element = Scalar>,
    > StandardPBSModSwitch<LweCiphertext<OutputCont>> for LweCiphertext<InputCont>
{
    type SideResources = ();

    fn standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        output: &mut LweCiphertext<OutputCont>,
        _side_resources: &mut Self::SideResources,
    ) {
        assert!(self
            .ciphertext_modulus()
            .is_compatible_with_native_modulus());
        assert_eq!(self.lwe_size(), output.lwe_size());
        // Mod switched but the noise is to be interpreted with respect to the input modulus, as
        // strictly the operation adding the noise is the rounding under the original rounding
        assert_eq!(self.ciphertext_modulus(), output.ciphertext_modulus());

        for (inp, out) in self.as_ref().iter().zip(output.as_mut().iter_mut()) {
            let msed = modulus_switch(*inp, output_modulus_log);
            // Shift in MSBs to match the power of 2 encoding in core
            *out = msed << (Scalar::BITS - output_modulus_log.0);
        }
    }
}

impl<Scalar: UnsignedInteger> AllocateDriftTechniqueStandardModSwitchResult
    for ModulusSwitchNoiseReductionKey<Scalar>
{
    type AfterDriftOutput = LweCiphertextOwned<Scalar>;
    type AfterMsOutput = LweCiphertextOwned<Scalar>;
    type SideResources = ();

    fn allocate_drift_technique_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> (Self::AfterDriftOutput, Self::AfterMsOutput) {
        let after_drift = Self::AfterDriftOutput::new(
            Scalar::ZERO,
            self.modulus_switch_zeros.lwe_size(),
            self.modulus_switch_zeros.ciphertext_modulus(),
        );
        let after_ms = after_drift.allocate_standard_mod_switch_result(side_resources);
        (after_drift, after_ms)
    }
}

impl<
        Scalar: UnsignedInteger,
        InputCont: Container<Element = Scalar>,
        AfterDriftCont: ContainerMut<Element = Scalar>,
        AfterMsCont: ContainerMut<Element = Scalar>,
    >
    DrifTechniqueStandardModSwitch<
        LweCiphertext<InputCont>,
        LweCiphertext<AfterDriftCont>,
        LweCiphertext<AfterMsCont>,
    > for ModulusSwitchNoiseReductionKey<Scalar>
{
    type SideResources = ();

    fn drift_technique_and_standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        input: &LweCiphertext<InputCont>,
        after_drift_technique: &mut LweCiphertext<AfterDriftCont>,
        after_mod_switch: &mut LweCiphertext<AfterMsCont>,
        side_resources: &mut Self::SideResources,
    ) {
        after_drift_technique
            .as_mut()
            .copy_from_slice(input.as_ref());
        self.improve_modulus_switch_noise(after_drift_technique, output_modulus_log);

        after_drift_technique.standard_mod_switch(
            output_modulus_log,
            after_mod_switch,
            side_resources,
        );
    }
}

impl<Scalar: UnsignedInteger, AccCont: Container<Element = Scalar>> AllocateBlindRotationResult
    for GlweCiphertext<AccCont>
{
    type Output = LweCiphertextOwned<Scalar>;
    type SideResources = ();

    fn allocated_blind_rotation_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        let glwe_dim = self.glwe_size().to_glwe_dimension();
        let poly_size = self.polynomial_size();
        let equivalent_lwe_dim = glwe_dim.to_equivalent_lwe_dimension(poly_size);

        LweCiphertext::new(
            Scalar::ZERO,
            equivalent_lwe_dim.to_lwe_size(),
            self.ciphertext_modulus(),
        )
    }
}

impl<
        InputScalar: UnsignedTorus + CastInto<usize>,
        OutputScalar: UnsignedTorus,
        KeyCont: Container<Element = c64>,
        InputCont: Container<Element = InputScalar>,
        OutputCont: ContainerMut<Element = OutputScalar>,
        AccCont: Container<Element = OutputScalar>,
    >
    StandardFftBootstrap<
        LweCiphertext<InputCont>,
        LweCiphertext<OutputCont>,
        GlweCiphertext<AccCont>,
    > for FourierLweBootstrapKey<KeyCont>
{
    type SideResources = ();

    fn standard_fft_pbs(
        &self,
        input: &LweCiphertext<InputCont>,
        output: &mut LweCiphertext<OutputCont>,
        accumulator: &GlweCiphertext<AccCont>,
        _side_resources: &mut Self::SideResources,
    ) {
        programmable_bootstrap_lwe_ciphertext(input, output, accumulator, self);
    }
}

impl<
        InputScalar: UnsignedTorus + CastInto<usize>,
        OutputScalar: UnsignedTorus,
        KeyCont: Container<Element = f64>,
        InputCont: Container<Element = InputScalar>,
        OutputCont: ContainerMut<Element = OutputScalar>,
        AccCont: Container<Element = OutputScalar>,
    >
    StandardFft128Bootstrap<
        LweCiphertext<InputCont>,
        LweCiphertext<OutputCont>,
        GlweCiphertext<AccCont>,
    > for Fourier128LweBootstrapKey<KeyCont>
{
    type SideResources = ();

    fn standard_fft_128_pbs(
        &self,
        input: &LweCiphertext<InputCont>,
        output: &mut LweCiphertext<OutputCont>,
        accumulator: &GlweCiphertext<AccCont>,
        _side_resources: &mut Self::SideResources,
    ) {
        programmable_bootstrap_f128_lwe_ciphertext(input, output, accumulator, self);
    }
}

impl<Scalar: UnsignedInteger, KeyCont: Container<Element = Scalar>> AllocatePackingKeyswitchResult
    for LwePackingKeyswitchKey<KeyCont>
{
    type Output = GlweCiphertextOwned<Scalar>;
    type SideResources = ();

    fn allocate_packing_keyswitch_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        Self::Output::new(
            Scalar::ZERO,
            self.output_glwe_size(),
            self.output_polynomial_size(),
            self.ciphertext_modulus(),
        )
    }
}

impl<
        Scalar: UnsignedInteger,
        InputCont: Container<Element = Scalar>,
        OutputCont: ContainerMut<Element = Scalar>,
        KeyCont: Container<Element = Scalar> + Sync,
    > LwePackingKeyswitch<[&LweCiphertext<InputCont>], GlweCiphertext<OutputCont>>
    for LwePackingKeyswitchKey<KeyCont>
{
    type SideResources = ();

    fn keyswitch_lwes_and_pack_in_glwe(
        &self,
        input: &[&LweCiphertext<InputCont>],
        output: &mut GlweCiphertext<OutputCont>,
        _side_resources: &mut Self::SideResources,
    ) {
        let input = LweCiphertextList::new_from_lwe_ciphertext_iterator(
            input.iter().map(|lwe| lwe.as_view()),
        )
        .unwrap();

        par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(self, &input, output);
    }
}
