use super::super::test::TestResources;
use super::*;

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::test_tools::{mean, variance};
use crate::core_crypto::prelude::{
    allocate_and_encrypt_new_lwe_ciphertext, allocate_and_generate_new_binary_lwe_secret_key,
    decrypt_lwe_ciphertext, encrypt_lwe_ciphertext, encrypt_lwe_ciphertext_list, new_seeder,
    EncryptionRandomGenerator, LweCiphertextCount, LweCiphertextList, LweCiphertextOwned,
    LweSecretKey, Plaintext, PlaintextCount, PlaintextList, Variance,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::cell::RefCell;
use tfhe_csprng::generators::DefaultRandomGenerator;

#[derive(Copy, Clone)]
struct MsNoiseReductionTestParams {
    pub lwe_dimension: LweDimension,
    pub lwe_noise_distribution: DynamicDistribution<u64>,
    pub ciphertext_modulus: CiphertextModulus<u64>,
    pub modulus_switch_zeros_count: usize,
    pub bound: f64,
    pub r_sigma_factor: f64,
    pub log_modulus: CiphertextModulusLog,
}

const TEST_PARAM: MsNoiseReductionTestParams = MsNoiseReductionTestParams {
    lwe_dimension: LweDimension(918),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    ciphertext_modulus: CiphertextModulus::new_native(),
    modulus_switch_zeros_count: 1452,
    bound: (1_u64 << (64 - 1 - 4 - 1)) as f64,
    r_sigma_factor: 14.658999256586121,
    log_modulus: PolynomialSize(2048).to_blind_rotation_input_modulus_log(),
};

#[cfg(feature = "shortint")]
mod conversion {
    use super::*;
    use crate::shortint::ClassicPBSParameters;

    impl TryFrom<ClassicPBSParameters> for MsNoiseReductionTestParams {
        type Error = ();

        fn try_from(value: ClassicPBSParameters) -> Result<Self, Self::Error> {
            value.modulus_switch_noise_reduction_params.map_or(
                Err(()),
                |modulus_switch_noise_reduction_params| {
                    Ok(Self {
                        lwe_dimension: value.lwe_dimension,
                        lwe_noise_distribution: value.lwe_noise_distribution,
                        ciphertext_modulus: value.ciphertext_modulus,
                        modulus_switch_zeros_count: modulus_switch_noise_reduction_params
                            .modulus_switch_zeros_count,
                        bound: modulus_switch_noise_reduction_params.ms_bound,
                        r_sigma_factor: modulus_switch_noise_reduction_params.ms_r_sigma_factor,
                        log_modulus: value.polynomial_size.to_blind_rotation_input_modulus_log(),
                    })
                },
            )
        }
    }
}

#[test]
fn improve_modulus_switch_noise_test_average_number_checks_parameterized() {
    let expected_average_number_checks = 16.8683590276303_f64;

    improve_modulus_switch_noise_test_average_number_checks(
        TEST_PARAM,
        expected_average_number_checks,
    );
}

fn improve_modulus_switch_noise_test_average_number_checks(
    params: MsNoiseReductionTestParams,
    expected_average_number_checks: f64,
) {
    let MsNoiseReductionTestParams {
        lwe_dimension,
        lwe_noise_distribution,
        ciphertext_modulus,
        modulus_switch_zeros_count,
        bound,
        r_sigma_factor,
        log_modulus,
    } = params;

    let number_loops = 100_000;

    let mut rsc = TestResources::new();

    let mut number_checks = 0;

    let sk = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    let plaintext_list = PlaintextList::new(0, PlaintextCount(modulus_switch_zeros_count));

    let mut encryptions_of_zero = LweCiphertextList::new(
        0,
        lwe_dimension.to_lwe_size(),
        LweCiphertextCount(modulus_switch_zeros_count),
        ciphertext_modulus,
    );

    encrypt_lwe_ciphertext_list(
        &sk,
        &mut encryptions_of_zero,
        &plaintext_list,
        lwe_noise_distribution,
        &mut rsc.encryption_random_generator,
    );

    let mut lwe = LweCiphertextOwned::new(0, sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);

    for _ in 0..number_loops {
        encrypt_lwe_ciphertext(
            &sk,
            &mut lwe,
            Plaintext(0),
            lwe_noise_distribution,
            &mut rsc.encryption_random_generator,
        );

        let index = choose_candidate_to_improve_modulus_switch_noise(
            &lwe,
            &encryptions_of_zero,
            r_sigma_factor,
            bound,
            log_modulus,
        )
        .expect("No candidate was good enough");

        number_checks += index;
    }

    let average_number_checks = number_checks as f64 / number_loops as f64;

    assert!(
        (average_number_checks - expected_average_number_checks).abs()
            / (average_number_checks + expected_average_number_checks)
            < 0.1_f64,
        "average_number_checks: measured (={average_number_checks}) too far from expected (={expected_average_number_checks})",
    );
}

fn ms_rescale<C: ContainerMut<Element = u64>>(
    ct: &mut LweCiphertext<C>,
    log_modulus: CiphertextModulusLog,
) {
    for a in ct.get_mut_mask().as_mut() {
        let closest = modulus_switch(*a, log_modulus) << (64 - log_modulus.0);

        *a = closest;
    }
}

fn operation_error<C1, C2>(
    sk: &LweSecretKey<C1>,
    mut ct: LweCiphertext<C2>,
    operation: impl Fn(&mut LweCiphertext<C2>),
) -> f64
where
    C1: Container<Element = u64>,
    C2: ContainerMut<Element = u64>,
{
    let decoded_before = decrypt_lwe_ciphertext(sk, &ct);

    operation(&mut ct);

    let decoded_after = decrypt_lwe_ciphertext(sk, &ct);

    decoded_after.0.wrapping_sub(decoded_before.0) as i64 as f64
}

#[test]
fn check_noise_improve_modulus_switch_noise_parameterized() {
    check_noise_improve_modulus_switch_noise(
        TEST_PARAM,
        Variance(4.834651119161795e32 - 9.68570987092478e+31),
    );
}

fn check_noise_improve_modulus_switch_noise(
    ms_noise_reduction_test_params: MsNoiseReductionTestParams,
    expected_variance_improved: Variance,
) {
    let MsNoiseReductionTestParams {
        lwe_dimension,
        lwe_noise_distribution,
        ciphertext_modulus,
        modulus_switch_zeros_count,
        bound,
        r_sigma_factor,
        log_modulus,
    } = ms_noise_reduction_test_params;

    let number_loops = 100_000;

    let mut rsc = TestResources::new();

    let sk = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    let sk_average_bit: f64 =
        sk.as_view().into_container().iter().sum::<u64>() as f64 / sk.lwe_dimension().0 as f64;

    println!("sk_average_bit {sk_average_bit:.3}");

    let plaintext_list = PlaintextList::new(0, PlaintextCount(modulus_switch_zeros_count));

    let mut encryptions_of_zero = LweCiphertextList::new(
        0,
        lwe_dimension.to_lwe_size(),
        LweCiphertextCount(modulus_switch_zeros_count),
        ciphertext_modulus,
    );

    encrypt_lwe_ciphertext_list(
        &sk,
        &mut encryptions_of_zero,
        &plaintext_list,
        lwe_noise_distribution,
        &mut rsc.encryption_random_generator,
    );

    thread_local! {
        static ENCRYPTION_GENERATOR: RefCell<EncryptionRandomGenerator<DefaultRandomGenerator>> = {
            let mut seeder = new_seeder();
            let encryption_random_generator =
                EncryptionRandomGenerator::new(seeder.seed(), seeder.as_mut());

            RefCell::new(encryption_random_generator)
        }
    };

    let errors: Vec<_> = (0..number_loops)
        .into_par_iter()
        .map(|_| {
            let lwe = ENCRYPTION_GENERATOR.with(|encryption_generator| {
                allocate_and_encrypt_new_lwe_ciphertext(
                    &sk,
                    Plaintext(0),
                    lwe_noise_distribution,
                    ciphertext_modulus,
                    &mut encryption_generator.borrow_mut(),
                )
            });

            (
                operation_error(&sk, lwe.clone(), |ct| ms_rescale(ct, log_modulus)),
                operation_error(&sk, lwe, |ct| {
                    improve_modulus_switch_noise(
                        ct,
                        &encryptions_of_zero,
                        r_sigma_factor,
                        bound,
                        log_modulus,
                    );

                    ms_rescale(ct, log_modulus)
                }),
            )
        })
        .collect();

    let mut ms_errors = vec![];

    let mut ms_errors_improved = vec![];

    for (ms_error, ms_error_improved) in errors {
        ms_errors.push(ms_error);
        ms_errors_improved.push(ms_error_improved);
    }

    println!(
        "mean(&ms_errors)                     {}2^{:.2}",
        if mean(&ms_errors) > 0_f64 { "+" } else { "-" },
        mean(&ms_errors).abs().log2()
    );

    println!(
        "mean(&ms_errors_improved)            {}2^{:.2}",
        if mean(&ms_errors_improved) > 0_f64 {
            "+"
        } else {
            "-"
        },
        mean(&ms_errors_improved).abs().log2()
    );

    let base_variance = variance(&ms_errors).0;

    println!(
        "variance(&ms_errors),                    2^{:.2}",
        base_variance.log2(),
    );

    let variance_improved = variance(&ms_errors_improved).0;

    println!(
        "variance(&ms_errors_improved)            2^{:.2}, ratio: {:.3}",
        variance_improved.log2(),
        variance_improved / base_variance,
    );

    let expected_base_variance = {
        let lwe_dim = lwe_dimension.0 as f64;

        let poly_size = 2_f64.powi((log_modulus.0 - 1) as i32);

        (lwe_dim + 2.) * 2_f64.powi(128) / (96. * poly_size * poly_size) + (lwe_dim - 4.) / 48.
    };

    assert!(
        (base_variance - expected_base_variance).abs() / (base_variance + expected_base_variance)
            < 0.1,
        "Expected {expected_base_variance}, got {base_variance}",
    );

    let expected_variance_improved = expected_variance_improved.0;

    assert!(
        (variance_improved - expected_variance_improved).abs()
            / (variance_improved + expected_variance_improved)
            < 0.1,
        "Expected {expected_variance_improved}, got {variance_improved}",
    );
}
