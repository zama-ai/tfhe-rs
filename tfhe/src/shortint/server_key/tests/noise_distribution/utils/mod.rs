pub mod noise_simulation;
pub mod traits;

use crate::core_crypto::algorithms::lwe_encryption::decrypt_lwe_ciphertext;
use crate::core_crypto::algorithms::lwe_keyswitch::{
    keyswitch_lwe_ciphertext, keyswitch_lwe_ciphertext_with_scalar_change,
};
use crate::core_crypto::algorithms::lwe_linear_algebra::{
    lwe_ciphertext_cleartext_mul, lwe_ciphertext_cleartext_mul_assign,
};
use crate::core_crypto::algorithms::misc::torus_modular_diff;
use crate::core_crypto::algorithms::test::round_decode;
use crate::core_crypto::commons::dispersion::{DispersionParameter, Variance};
use crate::core_crypto::commons::noise_formulas::secure_noise::{
    minimal_lwe_variance_for_132_bits_security_gaussian,
    minimal_lwe_variance_for_132_bits_security_tuniform,
};
use crate::core_crypto::commons::numeric::{CastFrom, UnsignedInteger};
use crate::core_crypto::commons::parameters::{
    CiphertextModulusLog, DynamicDistribution, LweDimension,
};
use crate::core_crypto::commons::test_tools::{
    arithmetic_mean, gaussian_mean_confidence_interval, gaussian_variance_confidence_interval,
    variance,
};
use crate::core_crypto::commons::traits::container::{Container, ContainerMut};
use crate::core_crypto::entities::lwe_ciphertext::{LweCiphertext, LweCiphertextOwned};
use crate::core_crypto::entities::lwe_keyswitch_key::LweKeyswitchKey;
use crate::core_crypto::entities::lwe_secret_key::LweSecretKey;
use crate::core_crypto::entities::Cleartext;
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::fft_impl::fft64::c64;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::fft64::math::fft::id;
use crate::shortint::client_key::ClientKey;
use std::any::TypeId;
use traits::*;

pub fn mean_and_variance_check<Scalar: UnsignedInteger>(
    noise_samples: &[f64],
    suffix: &str,
    expected_mean: f64,
    expected_variance: Variance,
    noise_distribution_used_for_encryption: DynamicDistribution<Scalar>,
    decryption_key_lwe_dimension: LweDimension,
    modulus_as_f64: f64,
) -> bool {
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
    pub fn new<Scalar: UnsignedInteger, CtCont, KeyCont>(
        ct: &LweCiphertext<CtCont>,
        secret_key: &LweSecretKey<KeyCont>,
        expected_msg: Scalar,
        delta: Scalar,
        cleartext_modulus_with_padding: Scalar,
    ) -> Self
    where
        CtCont: Container<Element = Scalar>,
        KeyCont: Container<Element = Scalar>,
    {
        let decrypted_plaintext = decrypt_lwe_ciphertext(secret_key, ct).0;

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
}

impl Encrypt<ClientKey> for LweCiphertextOwned<u64> {
    fn encrypt(key: &ClientKey, msg: u64) -> Self {
        key.encrypt(msg).ct
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ScalarMul<Scalar>
    for LweCiphertext<C>
{
    type Output = LweCiphertextOwned<Scalar>;
    type SideResources = ();

    fn scalar_mul(&self, rhs: Scalar, _side_resources: &mut Self::SideResources) -> Self::Output {
        let mut output =
            LweCiphertextOwned::from_container(self.as_ref().to_vec(), self.ciphertext_modulus());
        lwe_ciphertext_cleartext_mul(&mut output, &self, Cleartext(rhs));
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
        // though generics are different
        if TypeId::of::<InputScalar>() == TypeId::of::<OutputScalar>() {
            // Cannot use Any as Any requires a type to be 'static and we would be operating on
            // views, we know types are supposed to be the same, so convert the slice (as we already
            // have the primitive) and cast the modulus which will be a no-op in practice
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

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> AllocateClassicPBSModSwitchResult
    for LweCiphertext<C>
{
    type Output = LweCiphertextOwned<Scalar>;
    type SideResources = ();

    fn allocate_classic_mod_switch_result(
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
    > ClassicPBSModSwitch<LweCiphertext<OutputCont>> for LweCiphertext<InputCont>
{
    type SideResources = ();

    fn classic_mod_switch(
        &self,
        modulus_log: CiphertextModulusLog,
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
            let msed = modulus_switch(*inp, modulus_log);
            // Shift in MSBs to match the power of 2 encoding in core
            *out = msed << (Scalar::BITS - modulus_log.0);
        }
    }
}
