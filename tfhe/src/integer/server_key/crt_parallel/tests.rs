use crate::integer::keycache::KEY_CACHE;
use crate::integer::IntegerKeyKind;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;

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
fn integer_unchecked_crt_add_parallelized_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());
        let ct_one = cks.encrypt_crt(clear_1 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_add_parallelized(&ct_zero, &ct_one);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!(
            ((clear_0 + clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_mul_parallelized_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());
        let ct_one = cks.encrypt_crt(clear_1 as u64, basis.to_vec());

        // multiply the two ciphertexts
        let ct_res = sks.unchecked_crt_mul_parallelized(&ct_zero, &ct_one);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!(
            ((clear_0 * clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_neg_parallelized_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_neg_parallelized(&ct_zero);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!((modulus - clear_0) as u64, dec_res % modulus as u64);
    }
}

#[test]
fn integer_unchecked_crt_sub_parallelized_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());
        let ct_one = cks.encrypt_crt(clear_1 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_sub_parallelized(&ct_zero, &ct_one);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!(
            ((modulus + clear_0 - clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_scalar_add_parallelized_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_scalar_add_parallelized(&ct_zero, clear_1 as u64);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!(
            ((clear_0 + clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_scalar_mul_parallelized_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_scalar_mul_parallelized(&ct_zero, clear_1 as u64);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!(
            ((clear_0 * clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_scalar_sub_parallelized_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM, IntegerKeyKind::CRT);
    let mut rng = rand::rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_scalar_sub_parallelized(&ct_zero, clear_1 as u64);

        let dec_res = cks.decrypt_crt(&ct_res);

        assert_eq!(
            ((modulus + clear_0 - clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}
