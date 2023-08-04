use crate::integer::keycache::KEY_CACHE;
use crate::integer::U256;
use crate::shortint::parameters::*;
use crate::shortint::ClassicPBSParameters;
use rand::Rng;

/// Number of loop iteration within randomized tests
const NB_TEST: usize = 30;

/// Smaller number of loop iteration within randomized test,
/// meant for test where the function tested is more expensive
const NB_TEST_SMALLER: usize = 10;
const NB_CTXT: usize = 4;

create_parametrized_test!(integer_encrypt_decrypt);
create_parametrized_test!(integer_encrypt_decrypt_128_bits);
create_parametrized_test!(integer_encrypt_decrypt_128_bits_specific_values);
create_parametrized_test!(integer_encrypt_decrypt_256_bits_specific_values);
create_parametrized_test!(integer_encrypt_decrypt_256_bits);
create_parametrized_test!(integer_unchecked_add);
create_parametrized_test!(integer_smart_add);
create_parametrized_test! {
    integer_smart_add_128_bits {
        // Skip the 1_1 params for the smart add 128 bits which proved to be the slowest test in our test
        // suite
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    }
}
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
create_parametrized_test!(integer_unchecked_mul);

create_parametrized_test!(integer_smart_scalar_sub);
create_parametrized_test!(integer_smart_scalar_add);
create_parametrized_test!(integer_unchecked_scalar_sub);
create_parametrized_test!(integer_unchecked_scalar_add);

create_parametrized_test!(integer_unchecked_scalar_decomposition_overflow);

fn integer_encrypt_decrypt(param: ClassicPBSParameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param);

    let mut rng = rand::thread_rng();

    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let ct = cks.encrypt_radix(clear, NB_CTXT);

        let dec: u64 = cks.decrypt_radix(&ct);

        assert_eq!(clear, dec);
    }
}

fn integer_encrypt_decrypt_128_bits(param: ClassicPBSParameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param);

    let mut rng = rand::thread_rng();
    let num_block = (128f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;
    for _ in 0..10 {
        let clear = rng.gen::<u128>();

        let ct = cks.encrypt_radix(clear, num_block);

        let dec: u128 = cks.decrypt_radix(&ct);

        assert_eq!(clear, dec);
    }
}

fn integer_encrypt_decrypt_128_bits_specific_values(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    let num_block = (128f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;
    {
        let a = u64::MAX as u128;
        let ct = cks.encrypt_radix(a, num_block);

        let dec: u128 = cks.decrypt_radix(&ct);

        assert_eq!(a, dec);
    }
    {
        let a = (u64::MAX as u128) << 64;
        let ct = cks.encrypt_radix(a, num_block);

        let dec: u128 = cks.decrypt_radix(&ct);

        assert_eq!(a, dec);
    }

    {
        let clear_0 = ((u64::MAX as u128) << 64) + 1;
        let clear_1 = 1u128 << 64;

        let mut ct = cks.encrypt_radix(clear_0, num_block);
        let mut ct2 = cks.encrypt_radix(clear_1, num_block);
        let ct = sks.smart_add(&mut ct, &mut ct2);

        // decryption
        let dec: u128 = cks.decrypt_radix(&ct);

        // assert
        assert_eq!(clear_0.wrapping_add(clear_1), dec);
    }

    {
        let clear_0 = 330885270518284254268036566988540330316u128;
        let clear_1 = 296783836660960220449461214688067032122u128;

        let mut ct = cks.encrypt_radix(clear_0, num_block);
        let mut ct2 = cks.encrypt_radix(clear_1, num_block);
        let ct = sks.smart_add(&mut ct, &mut ct2);

        // decryption
        let dec: u128 = cks.decrypt_radix(&ct);

        // assert
        assert_eq!(clear_0.wrapping_add(clear_1), dec);
    }
}

fn integer_encrypt_decrypt_256_bits_specific_values(param: ClassicPBSParameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param);

    let num_block = (256f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;
    {
        let a = (u64::MAX as u128) << 64;
        let b = 0;
        let clear = crate::integer::U256::from((a, b));
        let ct = cks.encrypt_radix(clear, num_block);

        let dec: U256 = cks.decrypt_radix(&ct);
        assert_eq!(clear, dec);
    }
    {
        let a = 0;
        let b = u128::MAX;
        let clear = crate::integer::U256::from((a, b));
        let ct = cks.encrypt_radix(clear, num_block);

        let dec: U256 = cks.decrypt_radix(&ct);
        assert_eq!(clear, dec);
    }
}

fn integer_encrypt_decrypt_256_bits(param: ClassicPBSParameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param);

    // RNG
    let mut rng = rand::thread_rng();
    let num_block = (256f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    for _ in 0..10 {
        let clear0 = rng.gen::<u128>();
        let clear1 = rng.gen::<u128>();

        let clear = crate::integer::U256::from((clear0, clear1));

        //encryption
        let ct = cks.encrypt_radix(clear, num_block);

        // decryption
        let dec: U256 = cks.decrypt_radix(&ct);

        // assert
        assert_eq!(clear, dec);
    }
}

fn integer_smart_add_128_bits(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    let mut rng = rand::thread_rng();
    let num_block = (128f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    for _ in 0..100 {
        let clear_0 = rng.gen::<u128>();

        let clear_1 = rng.gen::<u128>();

        println!("{clear_0} {clear_1}");

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt_radix(clear_0, num_block);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt_radix(clear_1, num_block);

        // add the two ciphertexts
        let mut ct_res = sks.smart_add(&mut ctxt_0, &mut ctxt_1);

        let mut clear_result = clear_0 + clear_1;

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        //add multiple times to raise the degree
        for _ in 0..2 {
            ct_res = sks.smart_add(&mut ct_res, &mut ctxt_0);
            clear_result += clear_0;

            // decryption of ct_res
            let dec_res: u128 = cks.decrypt_radix(&ct_res);
            // println!("clear = {}, dec_res = {}", clear, dec_res);
            assert_eq!(clear_result, dec_res);
        }
    }
}

fn integer_unchecked_add(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_radix(clear_1, NB_CTXT);

        let ct_res = sks.unchecked_add(&ctxt_0, &ctxt_1);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);
        assert_eq!((clear_0 + clear_1) % modulus, dec_res);
    }
}

fn integer_smart_add(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    let mut rng = rand::thread_rng();

    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);
        let mut ctxt_1 = cks.encrypt_radix(clear_1, NB_CTXT);

        let mut ct_res = sks.smart_add(&mut ctxt_0, &mut ctxt_1);
        clear = (clear_0 + clear_1) % modulus;

        // add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            ct_res = sks.smart_add(&mut ct_res, &mut ctxt_0);
            clear = (clear + clear_0) % modulus;

            let dec_res: u64 = cks.decrypt_radix(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_unchecked_bitand(param: ClassicPBSParameters) {
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
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_0 & clear_1, dec_res);
    }
}

fn integer_unchecked_bitor(param: ClassicPBSParameters) {
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
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_0 | clear_1, dec_res);
    }
}

fn integer_unchecked_bitxor(param: ClassicPBSParameters) {
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
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_0 ^ clear_1, dec_res);
    }
}

fn integer_smart_bitand(param: ClassicPBSParameters) {
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
            let dec_res: u64 = cks.decrypt_radix(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_smart_bitor(param: ClassicPBSParameters) {
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
            let dec_res: u64 = cks.decrypt_radix(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_smart_bitxor(param: ClassicPBSParameters) {
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
            let dec_res: u64 = cks.decrypt_radix(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_unchecked_small_scalar_mul(param: ClassicPBSParameters) {
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
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!((clear * scalar) % modulus, dec_res);
    }
}

fn integer_smart_small_scalar_mul(param: ClassicPBSParameters) {
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
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_res % modulus, dec_res);
    }
}

fn integer_blockshift(param: ClassicPBSParameters) {
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
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(
            (clear * param.message_modulus.0.pow(power as u32) as u64) % modulus,
            dec_res
        );
    }
}

fn integer_blockshift_right(param: ClassicPBSParameters) {
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
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(
            (clear / param.message_modulus.0.pow(power as u32) as u64) % modulus,
            dec_res
        );
    }
}

fn integer_smart_scalar_mul(param: ClassicPBSParameters) {
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
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!((clear * scalar) % modulus, dec_res);
    }
}

fn integer_unchecked_scalar_left_shift(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;
    let nb_bits = modulus.ilog2();

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt_radix(clear, NB_CTXT);

        // case when 0<= scalar < nb_bits
        {
            let scalar = scalar % nb_bits;
            let ct_res = sks.unchecked_scalar_left_shift(&ct, scalar as u64);
            let dec_res: u64 = cks.decrypt_radix(&ct_res);
            assert_eq!(clear.wrapping_shl(scalar) % modulus, dec_res);
        }

        // case when scalar >= nb_bits
        {
            let scalar = scalar.saturating_add(nb_bits);
            let ct_res = sks.unchecked_scalar_left_shift(&ct, scalar as u64);
            let dec_res: u64 = cks.decrypt_radix(&ct_res);
            assert_eq!(clear.wrapping_shl(scalar % nb_bits) % modulus, dec_res);
        }
    }
}

fn integer_unchecked_scalar_right_shift(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;
    let nb_bits = modulus.ilog2();

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt_radix(clear, NB_CTXT);

        // case when 0<= scalar < nb_bits
        {
            let scalar = scalar % nb_bits;
            let ct_res = sks.unchecked_scalar_right_shift(&ct, scalar as u64);
            let dec_res: u64 = cks.decrypt_radix(&ct_res);
            assert_eq!(clear.wrapping_shr(scalar) % modulus, dec_res);
        }

        // case when scalar >= nb_bits
        {
            let scalar = scalar.saturating_add(nb_bits);
            let ct_res = sks.unchecked_scalar_right_shift(&ct, scalar as u64);
            let dec_res: u64 = cks.decrypt_radix(&ct_res);
            assert_eq!(clear.wrapping_shr(scalar % nb_bits) % modulus, dec_res);
        }
    }
}

fn integer_unchecked_negation(param: ClassicPBSParameters) {
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
        let dec: u64 = cks.decrypt_radix(&ct_tmp);

        // Check the correctness
        let clear_result = clear.wrapping_neg() % modulus;

        //println!("clear = {}", clear);
        assert_eq!(clear_result, dec);
    }
}

fn integer_smart_neg(param: ClassicPBSParameters) {
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
        let dec: u64 = cks.decrypt_radix(&ct_tmp);

        // Check the correctness
        let clear_result = clear.wrapping_neg() % modulus;

        assert_eq!(clear_result, dec);
    }
}

fn integer_unchecked_sub(param: ClassicPBSParameters) {
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
        let dec: u64 = cks.decrypt_radix(&ct_tmp);

        // Check the correctness
        let clear_result = (clear1 - clear2) % modulus;
        assert_eq!(clear_result, dec);
    }
}

fn integer_smart_sub(param: ClassicPBSParameters) {
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
        let dec: u64 = cks.decrypt_radix(&res);

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_unchecked_block_mul(param: ClassicPBSParameters) {
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
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!((clear_0 * clear_1) % modulus, dec_res);
    }
}

fn integer_smart_block_mul(param: ClassicPBSParameters) {
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
        let dec: u64 = cks.decrypt_radix(&res);

        clear = (clear * clear2) % modulus;

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_unchecked_mul(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..1 {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        let res = sks.unchecked_mul(&ctxt_1, &ctxt_2);

        let dec: u64 = cks.decrypt_radix(&res);

        let expected = (clear1 * clear2) % modulus;

        // Check the correctness
        assert_eq!(expected, dec);
    }
}

fn integer_smart_mul(param: ClassicPBSParameters) {
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
        let dec: u64 = cks.decrypt_radix(&res);

        clear = (clear * clear2) % modulus;

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_unchecked_scalar_add(param: ClassicPBSParameters) {
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
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!((clear_0 + clear_1) % modulus, dec_res);
    }
}

fn integer_smart_scalar_add(param: ClassicPBSParameters) {
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
            let dec_res: u64 = cks.decrypt_radix(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_unchecked_scalar_sub(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    // To force having one case where we subtract zero
    {
        let clear_0 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);
        let ct_res = sks.unchecked_scalar_sub(&ctxt_0, 0u64);

        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        assert_eq!(clear_0, dec_res);
    }

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;
        // encryption of an integer
        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_sub(&ctxt_0, clear_1);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!((clear_0.wrapping_sub(clear_1)) % modulus, dec_res);
    }
}

fn integer_smart_scalar_sub(param: ClassicPBSParameters) {
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
            let dec_res: u64 = cks.decrypt_radix(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_unchecked_scalar_decomposition_overflow(param: ClassicPBSParameters) {
    // This is a regression test.
    //
    // The purpose here is to check the behaviour when the scalar value has less bits
    // than the ciphertext.

    let mut rng = rand::thread_rng();

    let num_block = (128_f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    let (cks, sks) = KEY_CACHE.get_from_params(param);

    // Check addition
    // --------------
    let scalar = rng.gen::<u64>();
    let clear_0 = rng.gen::<u128>();
    let ct_0 = cks.encrypt_radix(clear_0, num_block);

    let ct_res = sks.unchecked_scalar_add(&ct_0, scalar);
    // decryption of ct_res
    let dec_res = cks.decrypt_radix(&ct_res);

    assert_eq!((clear_0 + scalar as u128), dec_res);

    // Check subtraction
    // -----------------
    let scalar = rng.gen::<u64>();
    let clear_0 = rng.gen::<u128>();
    let ct_0 = cks.encrypt_radix(clear_0, num_block);

    let ct_res = sks.unchecked_scalar_sub(&ct_0, scalar);
    let dec_res = cks.decrypt_radix(&ct_res);

    assert_eq!((clear_0 - scalar as u128), dec_res);
}

#[test]
fn integer_smart_scalar_mul_decomposition_overflow() {
    // This is a regression test. The purpose here is to check if the number of decomposition
    // blocks doesn't exceed 64 bits. This is why we test only 128 bits size.
    // Since smart_scalar_mul is a slow operation, we test against only one parameters set.
    // If overflow occurs the test case will panic.

    // RNG
    let mut rng = rand::thread_rng();

    let param = PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    let num_block = (128_f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    let (cks, sks) = KEY_CACHE.get_from_params(param);

    let scalar = rng.gen::<u64>();
    let clear_0 = rng.gen::<u128>();
    let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

    let ct_res = sks.smart_scalar_mul(&mut ct_0, scalar);
    let dec_res = cks.decrypt_radix(&ct_res);

    assert_eq!((clear_0 * scalar as u128), dec_res);
}
