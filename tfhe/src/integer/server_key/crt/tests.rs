use super::make_basis;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::tests::create_parameterized_test_classical_params;
use crate::integer::IntegerKeyKind;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;

create_parameterized_test_classical_params!(integer_unchecked_crt_mul);

/// Number of loop iteration within randomized tests
#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 30;

// Use lower numbers for coverage to ensure fast tests to counter balance slowdown due to code
// instrumentation
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

#[cfg(not(tarpaulin))]
const PARAM: ClassicPBSParameters = TEST_PARAM_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M128;
#[cfg(tarpaulin)]
const PARAM: ClassicPBSParameters = COVERAGE_PARAM_MESSAGE_5_CARRY_1_KS_PBS;

#[test]
fn integer_unchecked_crt_add_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());
        let ct_one = cks.encrypt_crt(clear_1 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_add(&ct_zero, &ct_one);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!(
            ((clear_0 + clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_mul_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());
        let ct_one = cks.encrypt_crt(clear_1 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_mul(&ct_zero, &ct_one);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!(
            ((clear_0 * clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_neg_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_neg(&ct_zero);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!((modulus - clear_0) as u64, dec_res % modulus as u64);
    }
}

#[test]
fn integer_unchecked_crt_sub_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());
        let ct_one = cks.encrypt_crt(clear_1 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_sub(&ct_zero, &ct_one);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!(
            ((modulus + clear_0 - clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_scalar_add_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_scalar_add(&ct_zero, clear_1 as u64);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!(
            ((clear_0 + clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_scalar_mul_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_scalar_mul(&ct_zero, clear_1 as u64);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!(
            ((clear_0 * clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_scalar_sub_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_scalar_sub(&ct_zero, clear_1 as u64);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!(
            ((modulus + clear_0 - clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

fn integer_unchecked_crt_mul(param: ClassicPBSParameters) {
    // generate the server-client key set
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);

    let mut rng = rand::thread_rng();

    // Define CRT basis, and global modulus
    let basis = make_basis(param.message_modulus.0);
    let modulus = basis.iter().product::<u64>();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ct_zero = cks.encrypt_crt(clear_0, basis.clone());
        let ct_one = cks.encrypt_crt(clear_1, basis.clone());

        // add the two ciphertexts
        sks.unchecked_crt_mul_assign(&mut ct_zero, &ct_one);

        let dec_res = cks.decrypt_crt(&ct_zero);

        assert_eq!((clear_0 * clear_1) % modulus, dec_res % modulus);
    }
}
