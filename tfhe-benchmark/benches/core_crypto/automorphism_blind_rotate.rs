use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::cell::LazyCell;
use std::sync::Arc;
use tfhe::core_crypto::experimental::entities::automorphism::trav_bsk::TravBsk;
use tfhe::core_crypto::experimental::entities::automorphism::travs::Travs;
use tfhe::core_crypto::experimental::prelude::automorphism::msed_for_automorphism::MsedLweFromAutomorphism;
use tfhe::core_crypto::experimental::prelude::automorphism::{Automorphism, Diff};
use tfhe::core_crypto::experimental::prelude::automorphism_based_blind_rotate::{
    blind_rotate, AUTOM_PARAMS_128,
};
use tfhe::core_crypto::prelude::*;

fn apply_automorphism(c: &mut Criterion) {
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let glwe_size = GlweSize(2);
    let polynomial_size = PolynomialSize(2048);

    let glwe_noise_distribution = Gaussian::from_dispersion_parameter(StandardDev(0.0), 0.0);
    let ciphertext_modulus = CiphertextModulus::new_native();

    let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_size.to_glwe_dimension(),
        polynomial_size,
        &mut secret_generator,
    );

    let base = 5;

    let mut in_glwe = GlweCiphertext::new(0_u64, glwe_size, polynomial_size, ciphertext_modulus);

    let mut out_glwe = GlweCiphertext::new(0_u64, glwe_size, polynomial_size, ciphertext_modulus);

    let m = polynomial_size.0 * 2;

    let automorphisms: Vec<Automorphism> = (0..10)
        .flat_map(|power_diff| {
            [false, true].iter().map(move |&sign_change| Diff {
                power_diff,
                sign_change,
            })
        })
        .map(|diff| Automorphism::new(diff.power(base, m), polynomial_size))
        .collect();

    let bench_name = "core_crypto::automorphism.apply_to_glwe_ciphertext";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(10));

    let plaintext_list = PlaintextList::new(0_u64, PlaintextCount(polynomial_size.0));

    encrypt_glwe_ciphertext(
        &glwe_secret_key,
        &mut in_glwe,
        &plaintext_list,
        glwe_noise_distribution,
        &mut encryption_generator,
    );

    let id = bench_name.to_string();
    bench_group.bench_function(&id, |bencher| {
        bencher.iter(|| {
            for automorphism in &automorphisms {
                automorphism.apply_to_glwe_ciphertext(&in_glwe, &mut out_glwe);
                automorphism.apply_to_glwe_ciphertext(&out_glwe, &mut in_glwe);
            }

            black_box(&mut out_glwe);
        });
    });
}

fn bench_automorphism_blind_rotate(c: &mut Criterion, with_ks: bool) {
    let params = AUTOM_PARAMS_128;

    let lwe_dimension = params.lwe_dimension;

    let glwe_dimension = params.glwe_dimension;
    let glwe_size = glwe_dimension.to_glwe_size();
    let polynomial_size = params.polynomial_size;

    let lwe_noise_distribution = params.lwe_noise_distribution;

    let glwe_noise_distribution = params.glwe_noise_distribution;

    let decomp_base_log_br = params.pbs_base_log;
    let decomp_level_count_br = params.pbs_level;

    let decomp_base_log_ks = params.ks_base_log;
    let decomp_level_count_ks = params.ks_level;

    let ciphertext_modulus = params.ciphertext_modulus;

    let allow_combine = true;

    let base = 5;

    let window_size = 20;

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    let lwe_secret_key = Arc::new(allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut secret_generator,
    ));

    let glwe_secret_key = Arc::new(allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut secret_generator,
    ));

    let lut_glwe = {
        let mut lut = vec![0u64; polynomial_size.0];
        lut[0] = 1 << 60;
        lut[1] = 2 << 60;
        lut[2] = 3 << 60;
        allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &PlaintextList::from_container(lut),
            ciphertext_modulus,
        )
    };

    for window_size_bsk in 1..20 {
        let lwe_key = Arc::clone(&lwe_secret_key);
        let glwe_key = Arc::clone(&glwe_secret_key);

        let bench_keys = LazyCell::new(move || {
            let mut boxed_seeder = new_seeder();
            let seeder = boxed_seeder.as_mut();
            let mut encryption_generator =
                EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

            let ksk = with_ks.then(|| {
                allocate_and_generate_new_lwe_keyswitch_key(
                    &glwe_key.as_lwe_secret_key(),
                    &*lwe_key,
                    decomp_base_log_ks,
                    decomp_level_count_ks,
                    lwe_noise_distribution,
                    ciphertext_modulus,
                    &mut encryption_generator,
                )
            });

            let travs = Travs::new(
                &*glwe_key,
                decomp_base_log_br,
                decomp_level_count_br,
                glwe_noise_distribution,
                ciphertext_modulus,
                window_size,
                base,
                &mut encryption_generator,
            );

            let bsks = TravBsk::new(
                base as usize,
                &*lwe_key,
                &*glwe_key,
                window_size_bsk,
                decomp_base_log_br,
                decomp_level_count_br,
                ciphertext_modulus,
                glwe_noise_distribution,
                &mut encryption_generator,
                allow_combine,
            );

            let m = polynomial_size.0 * 2;

            let automorphisms: Vec<Automorphism> = (0..bsks.len().div_ceil(2))
                .flat_map(|power_diff| {
                    [false, true].iter().map(move |&sign_change| Diff {
                        power_diff,
                        sign_change,
                    })
                })
                .map(|diff| Automorphism::new(diff.power(base, m), polynomial_size))
                .collect();

            (ksk, travs, bsks, automorphisms)
        });

        let bench_prefix = if with_ks {
            "ks_automorphism_blind_rotate"
        } else {
            "automorphism_blind_rotate"
        };
        let bench_name = &format!("core_crypto::{bench_prefix}, {window_size_bsk}");
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(10));

        let params_name = "Custom";

        let id = format!("{bench_name}::{params_name}");

        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        let mut in_lwe_no_ks =
            LweCiphertext::new(0, lwe_dimension.to_lwe_size(), ciphertext_modulus);

        let mut in_lwe_ks = LweCiphertext::new(
            0,
            glwe_dimension
                .to_equivalent_lwe_dimension(polynomial_size)
                .to_lwe_size(),
            ciphertext_modulus,
        );

        let mut post_ks_lwe =
            LweCiphertext::new(0, lwe_dimension.to_lwe_size(), ciphertext_modulus);

        let mut acc = lut_glwe.clone();

        if with_ks {
            encrypt_lwe_ciphertext(
                &glwe_secret_key.as_lwe_secret_key(),
                &mut in_lwe_ks,
                Plaintext(1 << 60),
                lwe_noise_distribution,
                &mut encryption_generator,
            );
        } else {
            encrypt_lwe_ciphertext(
                &*lwe_secret_key,
                &mut in_lwe_no_ks,
                Plaintext(1 << 60),
                lwe_noise_distribution,
                &mut encryption_generator,
            );
        }

        bench_group.bench_function(&id, |bencher| {
            let (ksk, travs, bsks, automorphisms) = &*bench_keys;

            bencher.iter(|| {
                acc.as_mut().copy_from_slice(lut_glwe.as_ref());

                let lwe_for_br = if let Some(ksk) = ksk {
                    keyswitch_lwe_ciphertext(ksk, &in_lwe_ks, &mut post_ks_lwe);
                    &post_ks_lwe
                } else {
                    &in_lwe_no_ks
                };

                let msed =
                    MsedLweFromAutomorphism::new(lwe_for_br, polynomial_size, base, allow_combine);

                blind_rotate(
                    &msed,
                    bsks,
                    travs,
                    acc.as_mut_view(),
                    polynomial_size,
                    glwe_size,
                    automorphisms,
                );

                black_box(&mut acc);
            });
        });
    }
}

fn automorphism_blind_rotate(c: &mut Criterion) {
    bench_automorphism_blind_rotate(c, false);
}

fn ks_automorphism_blind_rotate(c: &mut Criterion) {
    bench_automorphism_blind_rotate(c, true);
}

criterion_group!(
    automorphism_group,
    apply_automorphism,
    automorphism_blind_rotate,
    ks_automorphism_blind_rotate,
);
criterion_main!(automorphism_group);
