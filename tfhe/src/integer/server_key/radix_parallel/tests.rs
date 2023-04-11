use crate::integer::keycache::KEY_CACHE;
use crate::integer::{RadixClientKey, ServerKey};
use crate::shortint::parameters::*;
use crate::shortint::Parameters;
use paste::paste;
use rand::Rng;

/// Number of loop iteration within randomized tests
const NB_TEST: usize = 30;

/// Smaller number of loop iteration within randomized test,
/// meant for test where the function tested is more expensive
const NB_TEST_SMALLER: usize = 10;
const NB_CTXT: usize = 4;

macro_rules! create_parametrized_test{
    ($name:ident { $($param:ident),* }) => {
        paste! {
            $(
            #[test]
            fn [<test_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
     ($name:ident)=> {
        create_parametrized_test!($name
        {
            PARAM_MESSAGE_1_CARRY_1,
            PARAM_MESSAGE_2_CARRY_2,
            PARAM_MESSAGE_3_CARRY_3,
            PARAM_MESSAGE_4_CARRY_4
        });
    };
}

create_parametrized_test!(integer_smart_add);
create_parametrized_test!(integer_smart_add_sequence_multi_thread);
create_parametrized_test!(integer_smart_add_sequence_single_thread);
create_parametrized_test!(integer_default_add);
create_parametrized_test!(integer_default_add_sequence_multi_thread);
// Other tests are pretty slow, and the code is the same as a smart add but slower
#[test]
fn test_integer_default_add_sequence_single_thread_param_message_2_carry_2() {
    integer_default_add_sequence_single_thread(PARAM_MESSAGE_2_CARRY_2)
}
create_parametrized_test!(integer_smart_bitand);
create_parametrized_test!(integer_smart_bitor);
create_parametrized_test!(integer_smart_bitxor);
create_parametrized_test!(integer_default_bitand);
create_parametrized_test!(integer_default_bitor);
create_parametrized_test!(integer_default_bitxor);
create_parametrized_test!(integer_unchecked_small_scalar_mul);
create_parametrized_test!(integer_smart_small_scalar_mul);
create_parametrized_test!(integer_default_small_scalar_mul);
create_parametrized_test!(integer_smart_scalar_mul);
create_parametrized_test!(integer_default_scalar_mul);
create_parametrized_test!(integer_unchecked_scalar_left_shift);
create_parametrized_test!(integer_unchecked_scalar_right_shift);
create_parametrized_test!(integer_smart_neg);
create_parametrized_test!(integer_default_neg);
create_parametrized_test!(integer_smart_sub);
create_parametrized_test!(integer_default_sub);
create_parametrized_test!(integer_unchecked_block_mul);
create_parametrized_test!(integer_smart_block_mul);
create_parametrized_test!(integer_default_block_mul);
create_parametrized_test!(integer_smart_mul);
create_parametrized_test!(integer_default_mul);
create_parametrized_test!(integer_smart_scalar_sub);
create_parametrized_test!(integer_default_scalar_sub);
create_parametrized_test!(integer_smart_scalar_add);
create_parametrized_test!(integer_default_scalar_add);

fn integer_smart_add(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.smart_add_parallelized(&mut ctxt_0, &mut ctxt_1);

        clear = (clear_0 + clear_1) % modulus;

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        //add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            ct_res = sks.smart_add_parallelized(&mut ct_res, &mut ctxt_0);
            clear = (clear + clear_0) % modulus;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_smart_add_sequence_multi_thread(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for len in [1, 2, 15, 16, 17, 64, 65] {
        for _ in 0..NB_TEST_SMALLER {
            let clears = (0..len)
                .map(|_| rng.gen::<u64>() % modulus)
                .collect::<Vec<_>>();

            // encryption of integers
            let mut ctxts = clears
                .iter()
                .copied()
                .map(|clear| cks.encrypt(clear))
                .collect::<Vec<_>>();

            // add the ciphertexts
            let ct_res = sks
                .smart_binary_op_seq_parallelized(&mut ctxts, ServerKey::smart_add_parallelized)
                .unwrap();
            let ct_res: u64 = cks.decrypt(&ct_res);
            let clear = clears.iter().sum::<u64>() % modulus;

            assert_eq!(ct_res, clear);
        }
    }
}

fn integer_smart_add_sequence_single_thread(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for len in [1, 2, 15, 16, 17] {
        for _ in 0..NB_TEST_SMALLER {
            let clears = (0..len)
                .map(|_| rng.gen::<u64>() % modulus)
                .collect::<Vec<_>>();

            // encryption of integers
            let mut ctxts = clears
                .iter()
                .copied()
                .map(|clear| cks.encrypt(clear))
                .collect::<Vec<_>>();

            // add the ciphertexts
            let threadpool = rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .unwrap();

            let ct_res = threadpool.install(|| {
                sks.smart_binary_op_seq_parallelized(&mut ctxts, ServerKey::smart_add_parallelized)
                    .unwrap()
            });
            let ct_res: u64 = cks.decrypt(&ct_res);
            let clear = clears.iter().sum::<u64>() % modulus;

            assert_eq!(ct_res, clear);
        }
    }
}

fn integer_default_add(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.add_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());

        clear = (clear_0 + clear_1) % modulus;

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        //add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            ct_res = sks.add_parallelized(&ct_res, &ctxt_0);
            assert!(ct_res.block_carries_are_empty());
            clear = (clear + clear_0) % modulus;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_default_add_sequence_multi_thread(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for len in [1, 2, 15, 16, 17, 64, 65] {
        for _ in 0..NB_TEST_SMALLER {
            let clears = (0..len)
                .map(|_| rng.gen::<u64>() % modulus)
                .collect::<Vec<_>>();

            // encryption of integers
            let ctxts = clears
                .iter()
                .copied()
                .map(|clear| cks.encrypt(clear))
                .collect::<Vec<_>>();

            // add the ciphertexts
            let ct_res = sks
                .default_binary_op_seq_parallelized(&ctxts, ServerKey::add_parallelized)
                .unwrap();
            assert!(ct_res.block_carries_are_empty());
            let ct_res: u64 = cks.decrypt(&ct_res);
            let clear = clears.iter().sum::<u64>() % modulus;

            assert_eq!(ct_res, clear);
        }
    }
}

fn integer_default_add_sequence_single_thread(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for len in [1, 2, 15, 16, 17] {
        for _ in 0..NB_TEST_SMALLER {
            let clears = (0..len)
                .map(|_| rng.gen::<u64>() % modulus)
                .collect::<Vec<_>>();

            // encryption of integers
            let ctxts = clears
                .iter()
                .copied()
                .map(|clear| cks.encrypt(clear))
                .collect::<Vec<_>>();

            // add the ciphertexts
            let threadpool = rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .unwrap();

            let ct_res = threadpool.install(|| {
                sks.default_binary_op_seq_parallelized(&ctxts, ServerKey::add_parallelized)
                    .unwrap()
            });
            assert!(ct_res.block_carries_are_empty());
            let ct_res: u64 = cks.decrypt(&ct_res);
            let clear = clears.iter().sum::<u64>() % modulus;

            assert_eq!(ct_res, clear);
        }
    }
}

fn integer_smart_bitand(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.smart_bitand_parallelized(&mut ctxt_0, &mut ctxt_1);

        clear = clear_0 & clear_1;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let mut ctxt_2 = cks.encrypt(clear_2);

            ct_res = sks.smart_bitand_parallelized(&mut ct_res, &mut ctxt_2);
            clear &= clear_2;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_smart_bitor(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.smart_bitor_parallelized(&mut ctxt_0, &mut ctxt_1);

        clear = (clear_0 | clear_1) % modulus;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let mut ctxt_2 = cks.encrypt(clear_2);

            ct_res = sks.smart_bitor_parallelized(&mut ct_res, &mut ctxt_2);
            clear = (clear | clear_2) % modulus;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_smart_bitxor(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.smart_bitxor_parallelized(&mut ctxt_0, &mut ctxt_1);

        clear = (clear_0 ^ clear_1) % modulus;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let mut ctxt_2 = cks.encrypt(clear_2);

            ct_res = sks.smart_bitxor_parallelized(&mut ct_res, &mut ctxt_2);
            clear = (clear ^ clear_2) % modulus;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_default_bitand(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.bitand_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());

        clear = clear_0 & clear_1;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let ctxt_2 = cks.encrypt(clear_2);

            ct_res = sks.bitand_parallelized(&ct_res, &ctxt_2);
            assert!(ct_res.block_carries_are_empty());
            clear &= clear_2;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_default_bitor(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.bitor_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());

        clear = (clear_0 | clear_1) % modulus;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let ctxt_2 = cks.encrypt(clear_2);

            ct_res = sks.bitor_parallelized(&ct_res, &ctxt_2);
            assert!(ct_res.block_carries_are_empty());
            clear = (clear | clear_2) % modulus;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_default_bitxor(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.bitxor_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());

        clear = (clear_0 ^ clear_1) % modulus;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let ctxt_2 = cks.encrypt(clear_2);

            ct_res = sks.bitxor_parallelized(&ct_res, &ctxt_2);
            assert!(ct_res.block_carries_are_empty());
            clear = (clear ^ clear_2) % modulus;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_unchecked_small_scalar_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let scalar_modulus = param.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<u64>() % scalar_modulus;

        // encryption of an integer
        let ct = cks.encrypt(clear);

        // add the two ciphertexts
        let ct_res = sks.unchecked_small_scalar_mul_parallelized(&ct, scalar);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear * scalar) % modulus, dec_res);
    }
}

fn integer_smart_small_scalar_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

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
        let mut ct = cks.encrypt(clear);

        let mut ct_res = sks.smart_small_scalar_mul_parallelized(&mut ct, scalar);

        clear_res = clear * scalar;
        for _ in 0..NB_TEST_SMALLER {
            // scalar multiplication
            ct_res = sks.smart_small_scalar_mul_parallelized(&mut ct_res, scalar);
            clear_res *= scalar;
        }

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_res % modulus, dec_res);
    }
}

fn integer_default_small_scalar_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

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
        let ct = cks.encrypt(clear);

        let mut ct_res = sks.small_scalar_mul_parallelized(&ct, scalar);
        assert!(ct_res.block_carries_are_empty());

        clear_res = clear * scalar;
        for _ in 0..NB_TEST_SMALLER {
            // scalar multiplication
            ct_res = sks.small_scalar_mul_parallelized(&ct_res, scalar);
            assert!(ct_res.block_carries_are_empty());
            clear_res *= scalar;
        }

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_res % modulus, dec_res);
    }
}

fn integer_smart_scalar_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ct = cks.encrypt(clear);

        // scalar mul
        let ct_res = sks.smart_scalar_mul_parallelized(&mut ct, scalar);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear * scalar) % modulus, dec_res);
    }
}

fn integer_default_scalar_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ct = cks.encrypt(clear);

        // scalar mul
        let ct_res = sks.scalar_mul_parallelized(&ct, scalar);
        assert!(ct_res.block_carries_are_empty());

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear * scalar) % modulus, dec_res);
    }
}

fn integer_unchecked_scalar_left_shift(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

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
        let ct = cks.encrypt(clear);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_left_shift_parallelized(&ct, scalar);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear << scalar) % modulus, dec_res);
    }
}

fn integer_unchecked_scalar_right_shift(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

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
        let ct = cks.encrypt(clear);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_right_shift_parallelized(&ct, scalar);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear >> scalar, dec_res);
    }
}

fn integer_smart_neg(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear = rng.gen::<u64>() % modulus;

        // Encrypt the integers
        let mut ctxt = cks.encrypt(clear);

        // Negates the ctxt
        let ct_tmp = sks.smart_neg_parallelized(&mut ctxt);

        // Decrypt the result
        let dec: u64 = cks.decrypt(&ct_tmp);

        // Check the correctness
        let clear_result = clear.wrapping_neg() % modulus;

        assert_eq!(clear_result, dec);
    }
}

fn integer_default_neg(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear = rng.gen::<u64>() % modulus;

        // Encrypt the integers
        let ctxt = cks.encrypt(clear);

        // Negates the ctxt
        let ct_tmp = sks.neg_parallelized(&ctxt);
        assert!(ct_tmp.block_carries_are_empty());

        // Decrypt the result
        let dec: u64 = cks.decrypt(&ct_tmp);

        // Check the correctness
        let clear_result = clear.wrapping_neg() % modulus;

        assert_eq!(clear_result, dec);
    }
}

fn integer_smart_sub(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST_SMALLER {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers
        let ctxt_1 = cks.encrypt(clear1);
        let mut ctxt_2 = cks.encrypt(clear2);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        //subtract multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            res = sks.smart_sub_parallelized(&mut res, &mut ctxt_2);
            clear = (clear - clear2) % modulus;
            // println!("clear = {}, clear2 = {}", clear, cks.decrypt(&res));
        }
        let dec: u64 = cks.decrypt(&res);

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_default_sub(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST_SMALLER {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers
        let ctxt_1 = cks.encrypt(clear1);
        let ctxt_2 = cks.encrypt(clear2);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        //subtract multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            res = sks.sub_parallelized(&res, &ctxt_2);
            assert!(res.block_carries_are_empty());
            clear = (clear.wrapping_sub(clear2)) % modulus;
            // println!("clear = {}, clear2 = {}", clear, cks.decrypt(&res));
        }
        let dec: u64 = cks.decrypt(&res);

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_unchecked_block_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let block_modulus = param.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % block_modulus;

        // encryption of an integer
        let ct_zero = cks.encrypt(clear_0);

        // encryption of an integer
        let ct_one = cks.encrypt_one_block(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_block_mul_parallelized(&ct_zero, &ct_one, 0);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 * clear_1) % modulus, dec_res);
    }
}

fn integer_smart_block_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

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
        let ctxt_1 = cks.encrypt(clear1);
        let ctxt_2 = cks.encrypt_one_block(clear2);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        res = sks.smart_block_mul_parallelized(&mut res, &ctxt_2, 0);
        for _ in 0..5 {
            res = sks.smart_block_mul_parallelized(&mut res, &ctxt_2, 0);
            clear = (clear * clear2) % modulus;
        }
        let dec: u64 = cks.decrypt(&res);

        clear = (clear * clear2) % modulus;

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_default_block_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

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
        let ctxt_1 = cks.encrypt(clear1);
        let ctxt_2 = cks.encrypt_one_block(clear2);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        res = sks.block_mul_parallelized(&res, &ctxt_2, 0);
        assert!(res.block_carries_are_empty());
        for _ in 0..5 {
            res = sks.block_mul_parallelized(&res, &ctxt_2, 0);
            assert!(res.block_carries_are_empty());
            clear = (clear * clear2) % modulus;
        }
        let dec: u64 = cks.decrypt(&res);

        clear = (clear * clear2) % modulus;

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_smart_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

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
        let ctxt_1 = cks.encrypt(clear1);
        let mut ctxt_2 = cks.encrypt(clear2);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        res = sks.smart_mul_parallelized(&mut res, &mut ctxt_2);
        for _ in 0..5 {
            res = sks.smart_mul_parallelized(&mut res, &mut ctxt_2);
            clear = (clear * clear2) % modulus;
        }
        let dec: u64 = cks.decrypt(&res);

        clear = (clear * clear2) % modulus;

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_default_mul(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

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
        let ctxt_1 = cks.encrypt(clear1);
        let ctxt_2 = cks.encrypt(clear2);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        res = sks.mul_parallelized(&res, &ctxt_2);
        assert!(res.block_carries_are_empty());
        for _ in 0..5 {
            res = sks.mul_parallelized(&res, &ctxt_2);
            assert!(res.block_carries_are_empty());
            clear = (clear * clear2) % modulus;
        }
        let dec: u64 = cks.decrypt(&res);

        clear = (clear * clear2) % modulus;

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_smart_scalar_add(param: Parameters) {
    // generate the server-client key set
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    // RNG
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // add the two ciphertexts
        let mut ct_res = sks.smart_scalar_add_parallelized(&mut ctxt_0, clear_1);

        clear = (clear_0 + clear_1) % modulus;

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        //add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            ct_res = sks.smart_scalar_add_parallelized(&mut ct_res, clear_1);
            clear = (clear + clear_1) % modulus;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_default_scalar_add(param: Parameters) {
    // generate the server-client key set
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    // RNG
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // add the two ciphertexts
        let mut ct_res = sks.scalar_add_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());

        clear = (clear_0 + clear_1) % modulus;

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        //add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            ct_res = sks.scalar_add_parallelized(&ct_res, clear_1);
            assert!(ct_res.block_carries_are_empty());
            clear = (clear + clear_1) % modulus;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_smart_scalar_sub(param: Parameters) {
    // generate the server-client key set
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    // RNG
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // add the two ciphertexts
        let mut ct_res = sks.smart_scalar_sub_parallelized(&mut ctxt_0, clear_1);

        clear = (clear_0 - clear_1) % modulus;

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        //add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            ct_res = sks.smart_scalar_sub_parallelized(&mut ct_res, clear_1);
            clear = (clear - clear_1) % modulus;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_default_scalar_sub(param: Parameters) {
    // generate the server-client key set
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    // RNG
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // add the two ciphertexts
        let mut ct_res = sks.scalar_sub_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());

        clear = (clear_0.wrapping_sub(clear_1)) % modulus;

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        //add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            ct_res = sks.scalar_sub_parallelized(&ct_res, clear_1);
            assert!(ct_res.block_carries_are_empty());
            clear = (clear.wrapping_sub(clear_1)) % modulus;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            // assert
            assert_eq!(clear, dec_res);
        }
    }
}
