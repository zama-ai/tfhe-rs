use crate::integer::keycache::KEY_CACHE;
use crate::integer::IntegerKeyKind;
use crate::shortint::parameters::*;
use crate::shortint::ClassicPBSParameters;
use rand::Rng;

create_parametrized_test!(integer_unchecked_crt_mul);
create_parametrized_test!(integer_smart_crt_add);
create_parametrized_test!(integer_smart_crt_mul);
create_parametrized_test!(integer_smart_crt_neg);

create_parametrized_test!(integer_smart_crt_scalar_add);

create_parametrized_test!(integer_smart_crt_scalar_mul);
create_parametrized_test!(integer_smart_crt_scalar_sub);
create_parametrized_test!(integer_smart_crt_sub);

/// Number of loop iteration within randomized tests
const NB_TESTS: usize = 30;

/// Smaller number of loop iteration within randomized test,
/// meant for test where the function tested is more expensive
const NB_TESTS_SMALLER: usize = 10;

fn make_basis(message_modulus: usize) -> Vec<u64> {
    match message_modulus {
        2 => vec![2],
        3 => vec![2],
        n if n < 8 => vec![2, 3],
        n if n < 16 => vec![2, 5, 7],
        _ => vec![3, 7, 13],
    }
}

#[test]
fn integer_unchecked_crt_add_32_bits() {
    let param = PARAM_MESSAGE_5_CARRY_1_KS_PBS;

    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        // encryption of an integer
        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());
        let ct_one = cks.encrypt_crt(clear_1 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_add(&ct_zero, &ct_one);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_res);

        // assert
        assert_eq!(
            ((clear_0 + clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_mul_32_bits() {
    let param = PARAM_MESSAGE_5_CARRY_1_KS_PBS;

    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        // encryption of an integer
        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());
        let ct_one = cks.encrypt_crt(clear_1 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_mul(&ct_zero, &ct_one);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_res);

        // assert
        assert_eq!(
            ((clear_0 * clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_neg_32_bits() {
    let param = PARAM_MESSAGE_5_CARRY_1_KS_PBS;

    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;

        // encryption of an integer
        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_neg(&ct_zero);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_res);

        // assert
        assert_eq!((modulus - clear_0) as u64, dec_res % modulus as u64);
    }
}

#[test]
fn integer_unchecked_crt_sub_32_bits() {
    let param = PARAM_MESSAGE_5_CARRY_1_KS_PBS;

    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        // encryption of an integer
        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());
        let ct_one = cks.encrypt_crt(clear_1 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_sub(&ct_zero, &ct_one);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_res);

        // assert
        assert_eq!(
            ((modulus + clear_0 - clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_scalar_add_32_bits() {
    let param = PARAM_MESSAGE_5_CARRY_1_KS_PBS;

    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        // encryption of an integer
        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_scalar_add(&ct_zero, clear_1 as u64);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_res);

        // assert
        assert_eq!(
            ((clear_0 + clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_scalar_mul_32_bits() {
    let param = PARAM_MESSAGE_5_CARRY_1_KS_PBS;

    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        // encryption of an integer
        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_scalar_mul(&ct_zero, clear_1 as u64);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_res);

        // assert
        assert_eq!(
            ((clear_0 * clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

#[test]
fn integer_unchecked_crt_scalar_sub_32_bits() {
    let param = PARAM_MESSAGE_5_CARRY_1_KS_PBS;

    // Define CRT basis, and global modulus
    let basis = [3u64, 11, 13, 19, 23, 29, 31, 32];

    // Use u128 to avoid overflows as the modulus is slightly larger than 32 bits
    let modulus = basis.iter().copied().map(u128::from).product::<u128>();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u128>() % modulus;
        let clear_1 = rng.gen::<u128>() % modulus;

        // encryption of an integer
        let ct_zero = cks.encrypt_crt(clear_0 as u64, basis.to_vec());

        let ct_res = sks.unchecked_crt_scalar_sub(&ct_zero, clear_1 as u64);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_res);

        // assert
        assert_eq!(
            ((modulus + clear_0 - clear_1) % modulus) as u64,
            dec_res % modulus as u64
        );
    }
}

fn integer_unchecked_crt_mul(param: ClassicPBSParameters) {
    // generate the server-client key set
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);

    //RNG
    let mut rng = rand::thread_rng();

    // Define CRT basis, and global modulus
    let basis = make_basis(param.message_modulus.0);
    let modulus = basis.iter().product::<u64>();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ct_zero = cks.encrypt_crt(clear_0, basis.clone());
        let ct_one = cks.encrypt_crt(clear_1, basis.clone());

        // add the two ciphertexts
        sks.unchecked_crt_mul_assign(&mut ct_zero, &ct_one);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_zero);

        // assert
        assert_eq!((clear_0 * clear_1) % modulus, dec_res % modulus);
    }
}

fn integer_smart_crt_add(param: ClassicPBSParameters) {
    // Define CRT basis, and global modulus
    let basis = make_basis(param.message_modulus.0);
    let modulus = basis.iter().product::<u64>();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);

    //RNG
    let mut rng = rand::thread_rng();

    let mut clear_0 = rng.gen::<u64>() % modulus;
    let clear_1 = rng.gen::<u64>() % modulus;

    // encryption of an integer
    let mut ct_zero = cks.encrypt_crt(clear_0, basis.clone());
    let mut ct_one = cks.encrypt_crt(clear_1, basis);

    for _ in 0..NB_TESTS {
        // add the two ciphertexts
        sks.smart_crt_add_assign(&mut ct_zero, &mut ct_one);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_zero);

        // assert
        clear_0 += clear_1;
        assert_eq!(clear_0 % modulus, dec_res % modulus);
    }
}

fn integer_smart_crt_mul(param: ClassicPBSParameters) {
    // generate the server-client key set
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);

    // Define CRT basis, and global modulus
    let basis = make_basis(param.message_modulus.0);
    let modulus = basis.iter().product::<u64>();

    println!("BASIS = {basis:?}");

    //RNG
    let mut rng = rand::thread_rng();

    let mut clear_0 = rng.gen::<u64>() % modulus;
    let clear_1 = rng.gen::<u64>() % modulus;

    // encryption of an integer
    let mut ct_zero = cks.encrypt_crt(clear_0, basis.clone());
    let mut ct_one = cks.encrypt_crt(clear_1, basis);

    for _ in 0..NB_TESTS_SMALLER {
        // mul the two ciphertexts
        sks.smart_crt_mul_assign(&mut ct_zero, &mut ct_one);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_zero);

        clear_0 = (clear_0 * clear_1) % modulus;
        assert_eq!(clear_0 % modulus, dec_res % modulus);
    }
}

fn integer_smart_crt_neg(param: ClassicPBSParameters) {
    // Define CRT basis, and global modulus
    let basis = make_basis(param.message_modulus.0);
    let modulus = basis.iter().product::<u64>();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);

    //RNG
    let mut rng = rand::thread_rng();

    let mut clear_0 = rng.gen::<u64>() % modulus;

    // encryption of an integer
    let mut ct_zero = cks.encrypt_crt(clear_0, basis);

    for _ in 0..NB_TESTS {
        // add the two ciphertexts
        sks.smart_crt_neg_assign(&mut ct_zero);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_zero);

        clear_0 = (modulus - clear_0) % modulus;

        // println!("clear = {}", clear_0);
        // assert
        assert_eq!(clear_0, dec_res);
    }
}

fn integer_smart_crt_scalar_add(param: ClassicPBSParameters) {
    // Define CRT basis, and global modulus
    let basis = make_basis(param.message_modulus.0);
    let modulus = basis.iter().product::<u64>();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);

    //RNG
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ct_zero = cks.encrypt_crt(clear_0, basis.clone());

        // add the two ciphertexts
        sks.smart_crt_scalar_add_assign(&mut ct_zero, clear_1);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_zero);

        // assert
        assert_eq!((clear_0 + clear_1) % modulus, dec_res % modulus);
    }
}

fn integer_smart_crt_scalar_mul(param: ClassicPBSParameters) {
    // Define CRT basis, and global modulus
    let basis = make_basis(param.message_modulus.0);
    let modulus = basis.iter().product::<u64>();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);

    //RNG
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ct_zero = cks.encrypt_crt(clear_0, basis.clone());

        // add the two ciphertexts
        sks.smart_crt_scalar_mul_assign(&mut ct_zero, clear_1);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_zero);

        // assert
        assert_eq!((clear_0 * clear_1) % modulus, dec_res % modulus);
    }
}

fn integer_smart_crt_scalar_sub(param: ClassicPBSParameters) {
    // Define CRT basis, and global modulus
    let basis = make_basis(param.message_modulus.0);
    let modulus = basis.iter().product::<u64>();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);

    //RNG
    let mut rng = rand::thread_rng();

    let mut clear_0 = rng.gen::<u64>() % modulus;
    let clear_1 = rng.gen::<u64>() % modulus;

    // encryption of an integer
    let mut ct_zero = cks.encrypt_crt(clear_0, basis);

    for _ in 0..NB_TESTS {
        // add the two ciphertexts
        sks.smart_crt_scalar_sub_assign(&mut ct_zero, clear_1);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_zero);

        // println!("clear_0 = {}, clear_1 = {}, modulus = {}", clear_0, clear_1, modulus);

        // assert
        clear_0 = (clear_0 + modulus - clear_1) % modulus;
        assert_eq!(clear_0, dec_res % modulus);
    }
}

fn integer_smart_crt_sub(param: ClassicPBSParameters) {
    // Define CRT basis, and global modulus
    let basis = make_basis(param.message_modulus.0);
    let modulus = basis.iter().product::<u64>();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::CRT);

    //RNG
    let mut rng = rand::thread_rng();

    let mut clear_0 = rng.gen::<u64>() % modulus;
    let clear_1 = rng.gen::<u64>() % modulus;

    // encryption of an integer
    let mut ct_zero = cks.encrypt_crt(clear_0, basis.clone());
    let mut ct_one = cks.encrypt_crt(clear_1, basis);

    for _ in 0..NB_TESTS {
        // sub the two ciphertexts
        sks.smart_crt_sub_assign(&mut ct_zero, &mut ct_one);

        // decryption of ct_res
        let dec_res = cks.decrypt_crt(&ct_zero);

        // println!("clear_0 = {}, clear_1 = {}, modulus = {}", clear_0, clear_1, modulus);

        // assert
        clear_0 = (clear_0 + modulus - clear_1) % modulus;
        assert_eq!(clear_0, dec_res);
    }
}
