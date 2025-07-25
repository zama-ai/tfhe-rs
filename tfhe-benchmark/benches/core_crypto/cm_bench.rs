use cm_fft64::programmable_bootstrap_cm_lwe_ciphertext;
use criterion::{black_box, criterion_main, Criterion};
use itertools::Itertools;
use tfhe::core_crypto::prelude::cm_lwe_keyswitch_key_generation::*;
use tfhe::core_crypto::prelude::cm_modulus_switch_noise_reduction::improve_lwe_ciphertext_modulus_switch_noise_for_binary_key;
use tfhe::core_crypto::prelude::*;

fn cm_bench(c: &mut Criterion) {
    let bench_cm_params_2_minus_64: Vec<CmApParams> = vec![
        CM_PARAM_2_2_MINUS_64,
        CM_PARAM_4_2_MINUS_64,
        CM_PARAM_6_2_MINUS_64,
        CM_PARAM_8_2_MINUS_64,
        CM_PARAM_10_2_MINUS_64,
        CM_PARAM_2_4_MINUS_64,
        CM_PARAM_4_4_MINUS_64,
        CM_PARAM_6_4_MINUS_64,
        CM_PARAM_8_4_MINUS_64,
        CM_PARAM_10_4_MINUS_64,
        CM_PARAM_2_6_MINUS_64,
        CM_PARAM_4_6_MINUS_64,
        CM_PARAM_6_6_MINUS_64,
        // CM_PARAM_8_6_MINUS_64,
        // CM_PARAM_10_6_MINUS_64,
        // CM_PARAM_2_8_MINUS_64,
        // CM_PARAM_4_8_MINUS_64,
        // CM_PARAM_6_8_MINUS_64,
        // CM_PARAM_8_8_MINUS_64,
        // CM_PARAM_10_8_MINUS_64,
    ];

    cm_bench_for_pfail(c, &bench_cm_params_2_minus_64, "2^-64");

    let bench_cm_params_2_minus_128: Vec<CmApParams> = vec![
        CM_PARAM_2_2_MINUS_128,
        CM_PARAM_4_2_MINUS_128,
        CM_PARAM_6_2_MINUS_128,
        CM_PARAM_8_2_MINUS_128,
        CM_PARAM_10_2_MINUS_128,
        CM_PARAM_2_4_MINUS_128,
        CM_PARAM_4_4_MINUS_128,
        CM_PARAM_6_4_MINUS_128,
        CM_PARAM_8_4_MINUS_128,
        CM_PARAM_10_4_MINUS_128,
        CM_PARAM_2_6_MINUS_128,
        CM_PARAM_4_6_MINUS_128,
        CM_PARAM_6_6_MINUS_128,
        // CM_PARAM_8_6_MINUS_128,
        // CM_PARAM_10_6_MINUS_128,
        // CM_PARAM_2_8_MINUS_128,
        // CM_PARAM_4_8_MINUS_128,
        // CM_PARAM_6_8_MINUS_128,
        // CM_PARAM_8_8_MINUS_128,
        // CM_PARAM_10_8_MINUS_128,
    ];

    cm_bench_for_pfail(c, &bench_cm_params_2_minus_128, "2^-128");
}

fn cm_bench_for_pfail(c: &mut Criterion, bench_cm_params: &[CmApParams], p_fail: &str) {
    let mut bench_group = c.benchmark_group("Sharing_The_Mask");
    bench_group.sample_size(10);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    for cm_param in bench_cm_params {
        let cm_dimension = cm_param.cm_dimension;

        let total_number = cm_dimension.0;

        let bench_name = format!(
            "CM-KS->CM-PBS_p={}_w={}_pfail={p_fail}",
            cm_param.precision, cm_dimension.0,
        );

        let lwe_noise_distribution = DynamicDistribution::<u64>::new_gaussian_from_std_dev(
            StandardDev(cm_param.lwe_std_dev),
        );

        let ciphertext_modulus = CiphertextModulus::<u64>::new_native();
        let encoding_with_padding = 1 << 63;
        let glwe_dimension = cm_param.glwe_dimension;
        let polynomial_size = cm_param.polynomial_size;

        let msg_modulus = 1u64 << cm_param.precision;
        let delta = encoding_with_padding / msg_modulus;

        let f = |x| x;

        let accumulator = cm_generate_programmable_bootstrap_glwe_lut(
            polynomial_size,
            glwe_dimension,
            cm_dimension,
            msg_modulus.cast_into(),
            ciphertext_modulus,
            delta,
            f,
        );

        let CmBootstrapKeys {
            small_lwe_sk,
            big_lwe_sk,
            bsk,
            fbsk,
        } = generate_cm_pbs_keys(cm_param, &mut encryption_generator, &mut secret_generator);
        drop(bsk);

        let cm_lwe_keyswitch_key = allocate_and_generate_new_cm_lwe_keyswitch_key(
            &big_lwe_sk,
            &small_lwe_sk,
            cm_dimension,
            cm_param.base_log_ks,
            cm_param.level_ks,
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let plaintexts =
            PlaintextList::from_container((0..cm_dimension.0).map(|_| 0).collect_vec());

        let ct_in = allocate_and_encrypt_new_cm_lwe_ciphertext(
            &big_lwe_sk,
            &plaintexts,
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut ct_after_ks = CmLweCiphertext::new(
            0u64,
            fbsk.input_lwe_dimension(),
            cm_dimension,
            ciphertext_modulus,
        );

        let mut ct_out = CmLweCiphertext::new(
            0u64,
            fbsk.output_lwe_dimension(),
            cm_dimension,
            ciphertext_modulus,
        );

        let max_nb_zeros_n = (cm_param.max_nb_zeros_n + 1.) as usize;

        let mut encryptions_of_zero = CmLweCiphertextList::new(
            0,
            cm_param.lwe_dimension,
            cm_dimension,
            CmLweCiphertextCount(max_nb_zeros_n),
            ciphertext_modulus,
        );

        let plaintext_list = PlaintextList::new(0, PlaintextCount(cm_dimension.0));

        let plaintext_lists: Vec<_> = (0..max_nb_zeros_n)
            .map(|_| plaintext_list.clone())
            .collect();

        encrypt_cm_lwe_ciphertext_list(
            &small_lwe_sk,
            &mut encryptions_of_zero,
            &plaintext_lists,
            lwe_noise_distribution,
            &mut encryption_generator,
        );

        let log_modulus = polynomial_size.to_blind_rotation_input_modulus_log();

        {
            let id: String = format!("{bench_name}");
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    (0..total_number / cm_dimension.0).for_each(|_| {
                        cm_keyswitch_lwe_ciphertext(
                            &cm_lwe_keyswitch_key,
                            &ct_in,
                            &mut ct_after_ks,
                        );

                        improve_lwe_ciphertext_modulus_switch_noise_for_binary_key(
                            &mut ct_after_ks,
                            &encryptions_of_zero,
                            cm_param.r_sigma_factor_n,
                            cm_param.ms_bound_n,
                            cm_param.ms_input_variance_n,
                            log_modulus,
                        );

                        programmable_bootstrap_cm_lwe_ciphertext(
                            &ct_after_ks,
                            &mut ct_out,
                            &accumulator.as_view(),
                            &fbsk,
                        );

                        black_box(&mut ct_out);
                    })
                })
            });
        }
    }

    bench_group.finish();
}

pub fn cm_group() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();

    cm_bench(&mut criterion);
}

criterion_main!(cm_group);
