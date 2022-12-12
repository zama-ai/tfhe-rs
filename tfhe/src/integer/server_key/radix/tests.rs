use crate::integer::keycache::KEY_CACHE;
use crate::shortint::parameters::*;
use crate::shortint::Parameters;
use rand::Rng;

/// Number of loop iteration within randomized tests
const NB_TEST: usize = 30;

/// Smaller number of loop iteration within randomized test,
/// meant for test where the function tested is more expensive
const NB_TEST_SMALLER: usize = 10;
const NB_CTXT: usize = 4;

create_parametrized_test!(integer_encrypt_decrypt);
create_parametrized_test!(integer_unchecked_add);
create_parametrized_test!(integer_smart_add);
create_parametrized_test!(integer_unchecked_bitand);
create_parametrized_test!(integer_unchecked_bitor);
create_parametrized_test!(integer_unchecked_bitxor);
create_parametrized_test!(integer_smart_bitand);
create_parametrized_test!(integer_smart_bitor);
create_parametrized_test!(integer_smart_bitxor);
create_parametrized_test!(integer_unchecked_small_scalar_mul);
create_parametrized_test!(integer_smart_small_scalar_mul);
create_parametrized_test!(integer_blockshift);
create_parametrized_test!(integer_blockshift_right);
create_parametrized_test!(integer_smart_scalar_mul);
create_parametrized_test!(integer_unchecked_scalar_left_shift);
create_parametrized_test!(integer_unchecked_scalar_right_shift);
create_parametrized_test!(integer_unchecked_negation);
create_parametrized_test!(integer_smart_neg);
create_parametrized_test!(integer_unchecked_sub);
create_parametrized_test!(integer_smart_sub);
create_parametrized_test!(integer_unchecked_block_mul);
create_parametrized_test!(integer_smart_block_mul);
create_parametrized_test!(integer_smart_mul);

create_parametrized_test!(integer_smart_scalar_sub);
create_parametrized_test!(integer_smart_scalar_add);
create_parametrized_test!(integer_unchecked_scalar_sub);
create_parametrized_test!(integer_unchecked_scalar_add);

fn integer_encrypt_decrypt(param: Parameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param);

    // RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        //encryption
        let ct = cks.encrypt_radix(clear, NB_CTXT);

        // decryption
        let dec = cks.decrypt_radix(&ct);

        // assert
        assert_eq!(clear, dec);
    }
}

fn integer_unchecked_add(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // encryption of an integer
        let ctxt_1 = cks.encrypt_radix(clear_1, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.unchecked_add(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!((clear_0 + clear_1) % modulus, dec_res);
    }
}

fn integer_smart_add(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt_radix(clear_1, NB_CTXT);

        // add the two ciphertexts
        let mut ct_res = sks.smart_add(&mut ctxt_0, &mut ctxt_1);

        clear = (clear_0 + clear_1) % modulus;

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        //add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            ct_res = sks.smart_add(&mut ct_res, &mut ctxt_0);
            clear = (clear + clear_0) % modulus;

            // decryption of ct_res
            let dec_res = cks.decrypt_radix(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_unchecked_bitand(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // encryption of an integer
        let ctxt_1 = cks.encrypt_radix(clear_1, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.unchecked_bitand(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_0 & clear_1, dec_res);
    }
}

fn integer_unchecked_bitor(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // encryption of an integer
        let ctxt_1 = cks.encrypt_radix(clear_1, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.unchecked_bitor(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_0 | clear_1, dec_res);
    }
}

fn integer_unchecked_bitxor(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // encryption of an integer
        let ctxt_1 = cks.encrypt_radix(clear_1, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.unchecked_bitxor(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_0 ^ clear_1, dec_res);
    }
}

fn integer_smart_bitand(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt_radix(clear_1, NB_CTXT);

        // add the two ciphertexts
        let mut ct_res = sks.smart_bitand(&mut ctxt_0, &mut ctxt_1);

        clear = clear_0 & clear_1;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let mut ctxt_2 = cks.encrypt_radix(clear_2, NB_CTXT);

            ct_res = sks.smart_bitand(&mut ct_res, &mut ctxt_2);
            clear &= clear_2;

            // decryption of ct_res
            let dec_res = cks.decrypt_radix(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_smart_bitor(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt_radix(clear_1, NB_CTXT);

        // add the two ciphertexts
        let mut ct_res = sks.smart_bitor(&mut ctxt_0, &mut ctxt_1);

        clear = (clear_0 | clear_1) % modulus;

        for _ in 0..1 {
            let clear_2 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let mut ctxt_2 = cks.encrypt_radix(clear_2, NB_CTXT);

            ct_res = sks.smart_bitor(&mut ct_res, &mut ctxt_2);
            clear = (clear | clear_2) % modulus;

            // decryption of ct_res
            let dec_res = cks.decrypt_radix(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_smart_bitxor(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt_radix(clear_1, NB_CTXT);

        // add the two ciphertexts
        let mut ct_res = sks.smart_bitxor(&mut ctxt_0, &mut ctxt_1);

        clear = (clear_0 ^ clear_1) % modulus;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let mut ctxt_2 = cks.encrypt_radix(clear_2, NB_CTXT);

            ct_res = sks.smart_bitxor(&mut ct_res, &mut ctxt_2);
            clear = (clear ^ clear_2) % modulus;

            // decryption of ct_res
            let dec_res = cks.decrypt_radix(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_unchecked_small_scalar_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let scalar_modulus = param.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<u64>() % scalar_modulus;

        // encryption of an integer
        let ct = cks.encrypt_radix(clear, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.unchecked_small_scalar_mul(&ct, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!((clear * scalar) % modulus, dec_res);
    }
}

fn integer_smart_small_scalar_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let scalar_modulus = param.message_modulus.0 as u64;

    let mut clear_res;
    for _ in 0..NB_TEST_SMALLER {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<u64>() % scalar_modulus;

        // encryption of an integer
        let mut ct = cks.encrypt_radix(clear, NB_CTXT);

        let mut ct_res = sks.smart_small_scalar_mul(&mut ct, scalar);

        clear_res = clear * scalar;
        for _ in 0..NB_TEST_SMALLER {
            // scalar multiplication
            ct_res = sks.smart_small_scalar_mul(&mut ct_res, scalar);
            clear_res *= scalar;
        }

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_res % modulus, dec_res);
    }
}

fn integer_blockshift(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let power = rng.gen::<u64>() % NB_CTXT as u64;

        // encryption of an integer
        let ct = cks.encrypt_radix(clear, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.blockshift(&ct, power as usize);

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(
            (clear * param.message_modulus.0.pow(power as u32) as u64) % modulus,
            dec_res
        );
    }
}

fn integer_blockshift_right(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let power = rng.gen::<u64>() % NB_CTXT as u64;

        // encryption of an integer
        let ct = cks.encrypt_radix(clear, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.blockshift_right(&ct, power as usize);

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(
            (clear / param.message_modulus.0.pow(power as u32) as u64) % modulus,
            dec_res
        );
    }
}

fn integer_smart_scalar_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ct = cks.encrypt_radix(clear, NB_CTXT);

        // scalar mul
        let ct_res = sks.smart_scalar_mul(&mut ct, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!((clear * scalar) % modulus, dec_res);
    }
}

fn integer_unchecked_scalar_left_shift(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    //Nb of bits to shift
    let tmp_f64 = param.message_modulus.0 as f64;
    let nb_bits = tmp_f64.log2().floor() as usize * NB_CTXT;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<usize>() % nb_bits;

        // encryption of an integer
        let ct = cks.encrypt_radix(clear, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_left_shift(&ct, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!((clear << scalar) % modulus, dec_res);
    }
}

fn integer_unchecked_scalar_right_shift(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    //Nb of bits to shift
    let tmp_f64 = param.message_modulus.0 as f64;
    let nb_bits = tmp_f64.log2().floor() as usize * NB_CTXT;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<usize>() % nb_bits;

        // encryption of an integer
        let ct = cks.encrypt_radix(clear, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_right_shift(&ct, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear >> scalar, dec_res);
    }
}

fn integer_unchecked_negation(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear = rng.gen::<u64>() % modulus;

        // println!("clear = {}", clear);

        // Encrypt the integers
        let ctxt = cks.encrypt_radix(clear, NB_CTXT);

        // Negates the ctxt
        let ct_tmp = sks.unchecked_neg(&ctxt);

        // Decrypt the result
        let dec = cks.decrypt_radix(&ct_tmp);

        // Check the correctness
        let clear_result = clear.wrapping_neg() % modulus;

        //println!("clear = {}", clear);
        assert_eq!(clear_result, dec);
    }
}

fn integer_smart_neg(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear = rng.gen::<u64>() % modulus;

        // Encrypt the integers
        let mut ctxt = cks.encrypt_radix(clear, NB_CTXT);

        // Negates the ctxt
        let ct_tmp = sks.smart_neg(&mut ctxt);

        // Decrypt the result
        let dec = cks.decrypt_radix(&ct_tmp);

        // Check the correctness
        let clear_result = clear.wrapping_neg() % modulus;

        assert_eq!(clear_result, dec);
    }
}

fn integer_unchecked_sub(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    // RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Add the ciphertext 1 and 2
        let ct_tmp = sks.unchecked_sub(&ctxt_1, &ctxt_2);

        // Decrypt the result
        let dec = cks.decrypt_radix(&ct_tmp);

        // Check the correctness
        let clear_result = (clear1 - clear2) % modulus;
        assert_eq!(clear_result, dec);
    }
}

fn integer_smart_sub(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST_SMALLER {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let mut ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        //subtract multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            res = sks.smart_sub(&mut res, &mut ctxt_2);
            clear = (clear - clear2) % modulus;
            // println!("clear = {}, clear2 = {}", clear, cks.decrypt(&res));
        }
        let dec = cks.decrypt_radix(&res);

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_unchecked_block_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let block_modulus = param.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % block_modulus;

        // encryption of an integer
        let ct_zero = cks.encrypt_radix(clear_0, NB_CTXT);

        // encryption of an integer
        let ct_one = cks.encrypt_one_block(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_block_mul(&ct_zero, &ct_one, 0);

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!((clear_0 * clear_1) % modulus, dec_res);
    }
}

fn integer_smart_block_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let block_modulus = param.message_modulus.0 as u64;

    for _ in 0..5 {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % block_modulus;

        // Encrypt the integers
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_one_block(clear2);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        res = sks.smart_block_mul(&mut res, &ctxt_2, 0);
        for _ in 0..5 {
            res = sks.smart_block_mul(&mut res, &ctxt_2, 0);
            clear = (clear * clear2) % modulus;
        }
        let dec = cks.decrypt_radix(&res);

        clear = (clear * clear2) % modulus;

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_smart_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST_SMALLER {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // println!("clear1 = {}, clear2 = {}", clear1, clear2);

        // Encrypt the integers
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let mut ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        res = sks.smart_mul(&mut res, &mut ctxt_2);
        for _ in 0..5 {
            res = sks.smart_mul(&mut res, &mut ctxt_2);
            clear = (clear * clear2) % modulus;
        }
        let dec = cks.decrypt_radix(&res);

        clear = (clear * clear2) % modulus;

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_unchecked_scalar_add(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_add(&ctxt_0, clear_1);

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!((clear_0 + clear_1) % modulus, dec_res);
    }
}

fn integer_smart_scalar_add(param: Parameters) {
    // generate the server-client key set
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    // RNG
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // add the two ciphertexts
        let mut ct_res = sks.smart_scalar_add(&mut ctxt_0, clear_1);

        clear = (clear_0 + clear_1) % modulus;

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        //add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            ct_res = sks.smart_scalar_add(&mut ct_res, clear_1);
            clear = (clear + clear_1) % modulus;

            // decryption of ct_res
            let dec_res = cks.decrypt_radix(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_unchecked_scalar_sub(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_sub(&ctxt_0, clear_1);

        // decryption of ct_res
        let dec_res = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!((clear_0 - clear_1) % modulus, dec_res);
    }
}

fn integer_smart_scalar_sub(param: Parameters) {
    // generate the server-client key set
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    // RNG
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // add the two ciphertexts
        let mut ct_res = sks.smart_scalar_sub(&mut ctxt_0, clear_1);

        clear = (clear_0 - clear_1) % modulus;

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        //add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            ct_res = sks.smart_scalar_sub(&mut ct_res, clear_1);
            clear = (clear - clear_1) % modulus;

            // decryption of ct_res
            let dec_res = cks.decrypt_radix(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            // assert
            assert_eq!(clear, dec_res);
        }
    }
}
