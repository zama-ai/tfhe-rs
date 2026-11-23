use crate::integer::keycache::KEY_CACHE;
use crate::shortint::ciphertext::NoiseLevel;
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
fn integer_unchecked_add_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_crt_from_params(PARAM, basis.to_vec());
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt(clear_0 as u64);
        let ct_one = cks.encrypt(clear_1 as u64);

        let ct_res = sks.unchecked_add(&ct_zero, &ct_one);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(
            ((clear_0 + clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_neg_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_crt_from_params(PARAM, basis.to_vec());
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt(clear_0 as u64);

        let ct_res = sks.unchecked_neg(&ct_zero);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((modulus - clear_0) as u64, dec_res % modulus as u64);
    }
}

#[test]
fn integer_unchecked_sub_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_crt_from_params(PARAM, basis.to_vec());
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt(clear_0 as u64);
        let ct_one = cks.encrypt(clear_1 as u64);

        let ct_res = sks.unchecked_sub(&ct_zero, &ct_one);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(
            ((modulus + clear_0 - clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_scalar_add_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_crt_from_params(PARAM, basis.to_vec());
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt(clear_0 as u64);

        let ct_res = sks.unchecked_scalar_add(&ct_zero, clear_1 as u64);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(
            ((clear_0 + clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_scalar_sub_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_crt_from_params(PARAM, basis.to_vec());
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt(clear_0 as u64);

        let ct_res = sks.unchecked_scalar_sub(&ct_zero, clear_1 as u64);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(
            ((modulus + clear_0 - clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_mul_parallelized_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_crt_from_params(PARAM, basis.to_vec());
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt(clear_0 as u64);
        let ct_one = cks.encrypt(clear_1 as u64);

        // multiply the two ciphertexts
        let ct_res = sks.unchecked_mul_parallelized(&ct_zero, &ct_one);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(
            ((clear_0 * clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_scalar_mul_parallelized_32_bits() {
    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_crt_from_params(PARAM, basis.to_vec());
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        let ct_zero = cks.encrypt(clear_0 as u64);

        let ct_res = sks.unchecked_scalar_mul_parallelized(&ct_zero, clear_1 as u64);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(
            ((clear_0 * clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_scalar_mul_noise_check_uses_reduced_scalar() {
    // Each block is multiplied by the scalar reduced modulo its basis element, so the noise check
    // must use that reduced scalar too.
    // With 2_2 params (max degree 15, max noise level 5) and fresh blocks (degree <= 4, nominal
    // noise), 32 mod (2, 3, 5) = (0, 2, 2) fits the linear path on every block, while a noise
    // check on 32 itself would wrongly fall back to a PBS.
    let basis = [2u64, 3, 5];
    let modulus: u64 = basis.iter().product();
    let (cks, sks) = KEY_CACHE.get_crt_from_params(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        basis.to_vec(),
    );

    let clear = 7;
    let scalar = 32;
    let ct = cks.encrypt(clear);

    let ct_res = sks.unchecked_scalar_mul_parallelized(&ct, scalar);

    for (block, modulus_i) in ct_res.blocks.iter().zip(basis) {
        // The linear path multiplies the noise by the reduced scalar, a PBS resets it to nominal
        assert_eq!(
            block.noise_level(),
            NoiseLevel::NOMINAL * (scalar % modulus_i)
        );
    }
    assert_eq!(cks.decrypt(&ct_res), (clear * scalar) % modulus);
}
