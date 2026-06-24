use itertools::Itertools;

use crate::core_crypto::experimental::algorithms::{blind_rotate, AUTOM_PARAMS_128};
use crate::core_crypto::experimental::entities::automorphism::msed_for_automorphism::{
    automorphism_modulus_switch, pbs_modulus_switch, MsedLweFromAutomorphism,
};
use crate::core_crypto::experimental::entities::{Automorphism, Diff, TravBsk, Travs};
use crate::core_crypto::prelude::test::TestResources;
use crate::core_crypto::prelude::*;
use std::iter::once;

fn decrypt(
    glwe_secret_key: &GlweSecretKey<Vec<u64>>,
    acc: &GlweCiphertext<&[u64]>,
) -> PlaintextList<Vec<u64>> {
    let mut result = PlaintextList::new(0, PlaintextCount(glwe_secret_key.polynomial_size().0));

    decrypt_glwe_ciphertext(glwe_secret_key, acc, &mut result);

    result
}

fn print_plaintext_list(result: &PlaintextList<Vec<u64>>) {
    for i in result.as_ref() {
        let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

        let decoded = decomposer.closest_representable(*i) >> 60;

        if decoded == 0 {
            print!("_");
        } else {
            print!(" {decoded} ");
        }
    }

    println!();
}

fn assert_eq_plaintext_lists(a: &PlaintextList<Vec<u64>>, b: &PlaintextList<Vec<u64>>) {
    for (i, j) in a.as_ref().iter().zip_eq(b.as_ref().iter()) {
        let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

        assert_eq!(
            decomposer.closest_representable(*i),
            decomposer.closest_representable(*j)
        );
    }
}

#[test]
fn test() {
    let params = AUTOM_PARAMS_128;

    let lwe_dimension = params.lwe_dimension;

    let glwe_size = params.glwe_dimension.to_glwe_size();
    let polynomial_size = params.polynomial_size;

    let lwe_noise_distribution = params.lwe_noise_distribution;

    let glwe_noise_distribution = params.glwe_noise_distribution;

    let decomp_base_log = params.pbs_base_log;
    let decomp_level_count = params.pbs_level;

    let mut rsc = TestResources::new();

    let ciphertext_modulus = params.ciphertext_modulus;

    let lwe_secret_key: LweSecretKey<Vec<u64>> = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_size.to_glwe_dimension(),
        polynomial_size,
        &mut rsc.secret_random_generator,
    );

    let mut lut = vec![0; polynomial_size.0];

    lut[0] = 1 << 60;

    lut[1] = 2 << 60;

    lut[2] = 3 << 60;

    lut[2047] = 1 << 60;

    let lut_glwe = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &PlaintextList::from_container(lut.clone()),
        ciphertext_modulus,
    );

    let base = 5;

    let window_size = 10;

    let bsk_window_size = 2;

    let travs = Travs::new(
        &glwe_secret_key,
        decomp_base_log,
        decomp_level_count,
        glwe_noise_distribution,
        ciphertext_modulus,
        window_size,
        base,
        &mut rsc.encryption_random_generator,
    );

    for allow_combine in [false, true] {
        let bsks = TravBsk::new(
            base as usize,
            &lwe_secret_key,
            &glwe_secret_key,
            bsk_window_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
            glwe_noise_distribution,
            &mut rsc.encryption_random_generator,
            allow_combine,
        );

        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_secret_key,
            Plaintext(1 << 60),
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        let m = polynomial_size.0 * 2;

        let automorphisms: Vec<Automorphism> = (0..lwe_secret_key.lwe_dimension().0.div_ceil(2))
            .flat_map(|power_diff| {
                [false, true].iter().map(move |&sign_change| Diff {
                    power_diff,
                    sign_change,
                })
            })
            .map(|diff| Automorphism::new(diff.power(base, m), polynomial_size))
            .collect();

        let (lwe_mask, lwe_body) = lwe.get_mask_and_body();

        let msed = MsedLweFromAutomorphism::new(&lwe, polynomial_size, base, allow_combine);

        let mut acc = lut_glwe.clone();

        blind_rotate(
            &msed,
            &bsks,
            &travs,
            acc.as_mut_view(),
            polynomial_size,
            glwe_size,
            &automorphisms,
        );

        println!("final");

        let decrypted = decrypt(&glwe_secret_key, &acc.as_view());

        print_plaintext_list(&decrypted);

        let log_modulus = polynomial_size.to_blind_rotation_input_modulus_log();

        // Clear equivalent
        {
            let body = pbs_modulus_switch(*lwe_body.data, polynomial_size);

            let masks: Vec<u64> = if allow_combine {
                lwe_mask
                    .as_ref()
                    .iter()
                    .map(|a| pbs_modulus_switch(*a, polynomial_size))
                    .collect()
            } else {
                lwe_mask
                    .as_ref()
                    .iter()
                    .map(|a| automorphism_modulus_switch(*a, polynomial_size))
                    .collect()
            };

            let container: Vec<u64> = masks
                .iter()
                .copied()
                .chain(once(body))
                .map(|a| a << (64 - log_modulus.0))
                .collect();

            let ms_ed = LweCiphertext::from_container(container, ciphertext_modulus);

            let shift = decrypt_lwe_ciphertext(&lwe_secret_key, &ms_ed);

            let decomposer = SignedDecomposer::new(
                DecompositionBaseLog(log_modulus.0),
                DecompositionLevelCount(1),
            );

            let decoded =
                (decomposer.closest_representable(shift.0) >> (64 - log_modulus.0)) as usize;

            println!("decoded {decoded}");

            let mut expected_lut = PlaintextList::from_container(lut.clone());
            rotate_lut_left_negacyclic(expected_lut.as_mut_view().into_container(), decoded);

            println!("expected");

            print_plaintext_list(&expected_lut);

            assert_eq_plaintext_lists(&decrypted, &expected_lut);
        }
    }
}

fn rotate_lut_left_negacyclic(lut: &mut [u64], rotation: usize) {
    let len = lut.len();

    if rotation < len {
        lut.rotate_left(rotation);
        for i in &mut lut[len - rotation..] {
            *i = i.wrapping_neg();
        }
    } else {
        lut.rotate_right(2 * len - rotation);
        for i in &mut lut[..2 * len - rotation] {
            *i = i.wrapping_neg();
        }
    }
}
