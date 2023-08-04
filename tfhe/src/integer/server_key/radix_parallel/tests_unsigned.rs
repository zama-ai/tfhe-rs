use crate::integer::keycache::KEY_CACHE;
use crate::integer::{RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::parameters::*;
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
            PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
        });
    };
}

create_parametrized_test!(integer_smart_div_rem {
    // Due to the use of comparison,
    // this algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_default_div_rem {
    // Due to the use of comparison,
    // this algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_smart_add);
create_parametrized_test!(integer_smart_add_sequence_multi_thread);
create_parametrized_test!(integer_smart_add_sequence_single_thread);
create_parametrized_test!(integer_default_add);
create_parametrized_test!(integer_default_add_work_efficient {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
// These tests are slow and not very interesting nor efficient, keep small sizes
create_parametrized_test!(integer_default_add_sequence_multi_thread {
    PARAM_MESSAGE_1_CARRY_1_KS_PBS
});
// Other tests are pretty slow, and the code is the same as a smart add but slower
#[test]
fn test_integer_default_add_sequence_single_thread_param_message_2_carry_2_ks_pbs() {
    integer_default_add_sequence_single_thread(PARAM_MESSAGE_2_CARRY_2_KS_PBS)
}
create_parametrized_test!(integer_smart_bitand);
create_parametrized_test!(integer_smart_bitor);
create_parametrized_test!(integer_smart_bitxor);
create_parametrized_test!(integer_default_bitand);
create_parametrized_test!(integer_default_bitor);
create_parametrized_test!(integer_default_bitnot);
create_parametrized_test!(integer_default_bitxor);
create_parametrized_test!(integer_default_scalar_bitand);
create_parametrized_test!(integer_default_scalar_bitor);
create_parametrized_test!(integer_default_scalar_bitxor);
create_parametrized_test!(integer_unchecked_small_scalar_mul);
create_parametrized_test!(integer_smart_small_scalar_mul);
create_parametrized_test!(integer_default_small_scalar_mul);
create_parametrized_test!(integer_smart_scalar_mul_u128_fix_non_reg_test {
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS
});
create_parametrized_test!(integer_unchecked_mul_corner_cases);
create_parametrized_test!(integer_default_scalar_mul_u128_fix_non_reg_test {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS
});
create_parametrized_test!(integer_smart_scalar_mul);
create_parametrized_test!(integer_default_scalar_mul);
// scalar left/right shifts
create_parametrized_test!(integer_unchecked_scalar_left_shift);
create_parametrized_test!(integer_default_scalar_left_shift);
create_parametrized_test!(integer_unchecked_scalar_right_shift);
create_parametrized_test!(integer_default_scalar_right_shift);
// left/right shifts
create_parametrized_test!(integer_unchecked_left_shift {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_unchecked_right_shift {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
// left/right rotations
create_parametrized_test!(integer_unchecked_rotate_left {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_unchecked_rotate_right {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
// left/right rotations
create_parametrized_test!(integer_unchecked_scalar_rotate_right);
create_parametrized_test!(integer_unchecked_scalar_rotate_left);
create_parametrized_test!(integer_default_scalar_rotate_right);
create_parametrized_test!(integer_default_scalar_rotate_left);
// negations
create_parametrized_test!(integer_smart_neg);
create_parametrized_test!(integer_default_neg);
create_parametrized_test!(integer_smart_sub);
create_parametrized_test!(integer_default_sub);
create_parametrized_test!(integer_default_sub_work_efficient {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_default_scalar_div_rem);
create_parametrized_test!(integer_unchecked_block_mul);
create_parametrized_test!(integer_smart_block_mul);
create_parametrized_test!(integer_default_block_mul);
create_parametrized_test!(integer_smart_mul);
create_parametrized_test!(integer_default_mul);
create_parametrized_test!(integer_smart_scalar_sub);
create_parametrized_test!(integer_default_scalar_sub);
create_parametrized_test!(integer_smart_scalar_add);
create_parametrized_test!(integer_default_scalar_add);
create_parametrized_test!(integer_smart_if_then_else);
create_parametrized_test!(integer_default_if_then_else);

fn integer_smart_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

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

fn integer_smart_add_sequence_multi_thread<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

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

            let ct_res = sks
                .smart_binary_op_seq_parallelized(&mut ctxts, |sks, a, b| {
                    sks.smart_add_parallelized(a, b)
                })
                .unwrap();
            let ct_res: u64 = cks.decrypt(&ct_res);
            let clear = clears.iter().sum::<u64>() % modulus;

            assert_eq!(ct_res, clear);
        }
    }
}

fn integer_smart_add_sequence_single_thread<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

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

            let threadpool = rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .unwrap();

            let ct_res = threadpool.install(|| {
                sks.smart_binary_op_seq_parallelized(&mut ctxts, |sks, a, b| {
                    sks.smart_add_parallelized(a, b)
                })
                .unwrap()
            });
            let ct_res: u64 = cks.decrypt(&ct_res);
            let clear = clears.iter().sum::<u64>() % modulus;

            assert_eq!(ct_res, clear);
        }
    }
}

fn integer_default_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = sks.add_parallelized(&ctxt_0, &ctxt_1);
        let tmp_ct = sks.add_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct);

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

// Smaller test for this one
fn integer_default_add_work_efficient<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.add_parallelized_work_efficient(&ctxt_0, &ctxt_1);
        let tmp_ct = sks.add_parallelized_work_efficient(&ctxt_0, &ctxt_1);

        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct);

        let expected = (clear_0.wrapping_add(clear_1)) % modulus;
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(expected, dec_res);
    }
}

fn integer_default_add_sequence_multi_thread<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

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

            let ct_res = sks
                .default_binary_op_seq_parallelized(&ctxts, ServerKey::add_parallelized)
                .unwrap();
            let tmp_ct = sks
                .default_binary_op_seq_parallelized(&ctxts, ServerKey::add_parallelized)
                .unwrap();
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp_ct);
            let ct_res: u64 = cks.decrypt(&ct_res);
            let clear = clears.iter().sum::<u64>() % modulus;

            assert_eq!(ct_res, clear);
        }
    }
}

fn integer_default_add_sequence_single_thread<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

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

fn integer_smart_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

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

fn integer_smart_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

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

fn integer_smart_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

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

fn integer_default_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = sks.bitand_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());

        clear = clear_0 & clear_1;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let ctxt_2 = cks.encrypt(clear_2);

            let tmp = sks.bitand_parallelized(&ct_res, &ctxt_2);
            ct_res = sks.bitand_parallelized(&ct_res, &ctxt_2);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear &= clear_2;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_default_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = sks.bitor_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());

        clear = (clear_0 | clear_1) % modulus;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let ctxt_2 = cks.encrypt(clear_2);

            let tmp = sks.bitor_parallelized(&ct_res, &ctxt_2);
            ct_res = sks.bitor_parallelized(&ct_res, &ctxt_2);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear |= clear_2;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_default_bitnot<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt = cks.encrypt(clear);

        let tmp = sks.bitnot_parallelized(&ctxt);
        let ct_res = sks.bitnot_parallelized(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);

        // decryption of ct_res
        let dec: u64 = cks.decrypt(&ct_res);

        // Check the correctness
        let clear_result = !clear % modulus;
        assert_eq!(clear_result, dec);
    }
}

fn integer_default_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = sks.bitxor_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());

        clear = clear_0 ^ clear_1;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            // encryption of an integer
            let ctxt_2 = cks.encrypt(clear_2);

            let tmp = sks.bitxor_parallelized(&ct_res, &ctxt_2);
            ct_res = sks.bitxor_parallelized(&ct_res, &ctxt_2);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear = (clear ^ clear_2) % modulus;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_default_scalar_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // Do with a small clear to check the way we avoid
        // unecesseray work is correct
        let ct_res = sks.scalar_bitand_parallelized(&ctxt_0, 1);
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear_0 & 1, dec_res);

        let mut ct_res = sks.scalar_bitand_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());

        clear = clear_0 & clear_1;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            let tmp = sks.scalar_bitand_parallelized(&ct_res, clear_2);
            ct_res = sks.scalar_bitand_parallelized(&ct_res, clear_2);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear &= clear_2;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_default_scalar_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        // Do with a small clear to check the way we avoid
        // unecesseray work is correct
        let ct_res = sks.scalar_bitor_parallelized(&ctxt_0, 1);
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear_0 | 1, dec_res);

        let mut ct_res = sks.scalar_bitor_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());
        clear = (clear_0 | clear_1) % modulus;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            let tmp = sks.scalar_bitor_parallelized(&ct_res, clear_2);
            ct_res = sks.scalar_bitor_parallelized(&ct_res, clear_2);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear = (clear | clear_2) % modulus;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_default_scalar_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        // Do with a small clear to check the way we avoid
        // unecesseray work is correct
        let ct_res = sks.scalar_bitxor_parallelized(&ctxt_0, 1);
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear_0 ^ 1, dec_res);

        let mut ct_res = sks.scalar_bitxor_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());
        clear = (clear_0 ^ clear_1) % modulus;

        for _ in 0..NB_TEST_SMALLER {
            let clear_2 = rng.gen::<u64>() % modulus;

            let tmp = sks.scalar_bitxor_parallelized(&ct_res, clear_2);
            ct_res = sks.scalar_bitxor_parallelized(&ct_res, clear_2);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear = (clear ^ clear_2) % modulus;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_smart_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for i in 0..NB_TEST_SMALLER {
        println!("i: {i}");
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen_range(1..modulus); // avoid division by zero
        let clear_2 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let mut ctxt_1 = cks.encrypt(clear_1);

        // add to change degree
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        clear_0 += clear_2;
        clear_0 %= modulus;

        let (q_res, r_res) = sks.smart_div_rem_parallelized(&mut ctxt_0, &mut ctxt_1);
        let q: u64 = cks.decrypt(&q_res);
        let r: u64 = cks.decrypt(&r_res);

        assert_eq!(clear_0 / clear_1, q);
        assert_eq!(clear_0 % clear_1, r);

        // Test individual div/rem to check they are correctly bound
        let q_res = sks.smart_div_parallelized(&mut ctxt_0, &mut ctxt_1);
        let q: u64 = cks.decrypt(&q_res);
        assert_eq!(clear_0 / clear_1, q);

        let r_res = sks.smart_rem_parallelized(&mut ctxt_0, &mut ctxt_1);
        let r: u64 = cks.decrypt(&r_res);
        assert_eq!(clear_0 % clear_1, r);
    }
}

fn integer_default_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST_SMALLER {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen_range(1..modulus); // avoid division by zero
        let clear_2 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        // add to change degree
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        clear_0 += clear_2;
        clear_0 %= modulus;

        let (q_res, r_res) = sks.div_rem_parallelized(&ctxt_0, &ctxt_1);
        let q: u64 = cks.decrypt(&q_res);
        let r: u64 = cks.decrypt(&r_res);

        assert!(q_res.block_carries_are_empty());
        assert!(r_res.block_carries_are_empty());
        assert_eq!(clear_0 / clear_1, q);
        assert_eq!(clear_0 % clear_1, r);

        // Test individual div/rem to check they are correctly bound
        let q2_res = sks.div_parallelized(&ctxt_0, &ctxt_1);
        let q2: u64 = cks.decrypt(&q_res);
        assert!(q2_res.block_carries_are_empty());
        assert_eq!(clear_0 / clear_1, q2);

        let r2_res = sks.rem_parallelized(&ctxt_0, &ctxt_1);
        let r2: u64 = cks.decrypt(&r2_res);
        assert!(r_res.block_carries_are_empty());
        assert_eq!(clear_0 % clear_1, r2);

        // Determinism checks
        assert_eq!(q2, q, "Operation was not deterministic");
        assert_eq!(r2, r, "Operation was not deterministic");
    }
}

fn integer_unchecked_small_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let scalar_modulus = cks.parameters().message_modulus().0 as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<u64>() % scalar_modulus;

        // encryption of an integer
        let ct = cks.encrypt(clear);

        let ct_res = sks.unchecked_small_scalar_mul_parallelized(&ct, scalar);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear * scalar) % modulus, dec_res);
    }
}

fn integer_smart_small_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let scalar_modulus = cks.parameters().message_modulus().0 as u64;

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

fn integer_default_small_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let scalar_modulus = cks.parameters().message_modulus().0 as u64;

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
            let tmp = sks.small_scalar_mul_parallelized(&ct_res, scalar);
            ct_res = sks.small_scalar_mul_parallelized(&ct_res, scalar);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(tmp, ct_res);
            clear_res *= scalar;
        }

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_res % modulus, dec_res);
    }
}

fn integer_smart_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

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

fn integer_default_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST_SMALLER {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ct = cks.encrypt(clear);

        // scalar mul
        let ct_res = sks.scalar_mul_parallelized(&ct, scalar);
        let tmp = sks.scalar_mul_parallelized(&ct, scalar);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear * scalar) % modulus, dec_res);
    }
}

fn integer_unchecked_mul_corner_cases<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    // This example will not pass if the terms reduction is wrong
    // on the chunk size it uses to reduce the 'terms' resulting
    // from blockmuls
    {
        let nb_ct =
            (128f64 / (cks.parameters().message_modulus().0 as f64).log2().ceil()).ceil() as usize;
        let clear = 307096569525960547621731375222677666984u128;
        let scalar = 5207034748027904122u64;

        let ct = cks.encrypt_radix(clear, nb_ct);
        let ct_res = sks.unchecked_scalar_mul_parallelized(&ct, scalar);
        let dec_res: u128 = cks.decrypt_radix(&ct_res);
        assert_eq!(clear.wrapping_mul(scalar as u128), dec_res);

        let nb_ct =
            (128f64 / (cks.parameters().message_modulus().0 as f64).log2().ceil()).ceil() as usize;
        let clear = 307096569525960547621731375222677666984u128;
        let scalar = 5207034748027904122u64;

        // Same thing but with scalar encrypted
        let ct = cks.encrypt_radix(clear, nb_ct);
        let ct2 = cks.encrypt_radix(scalar, nb_ct);
        let ct_res = sks.unchecked_mul_parallelized(&ct, &ct2);
        let dec_res: u128 = cks.decrypt_radix(&ct_res);
        assert_eq!(clear.wrapping_mul(scalar as u128), dec_res);
    }

    {
        let nb_ct =
            (128f64 / (cks.parameters().message_modulus().0 as f64).log2().ceil()).ceil() as usize;
        let clear = u128::MAX;
        let scalar = u64::MAX;

        let ct = cks.encrypt_radix(clear, nb_ct);
        let ct_res = sks.unchecked_scalar_mul_parallelized(&ct, scalar);
        let dec_res: u128 = cks.decrypt_radix(&ct_res);
        assert_eq!(clear.wrapping_mul(scalar as u128), dec_res);

        // Same thing but with scalar encrypted
        let clear = u128::MAX;
        let scalar = u128::MAX;
        let ct = cks.encrypt_radix(clear, nb_ct);
        let ct2 = cks.encrypt_radix(scalar, nb_ct);
        let ct_res = sks.unchecked_mul_parallelized(&ct, &ct2);
        let dec_res: u128 = cks.decrypt_radix(&ct_res);
        assert_eq!(clear.wrapping_mul(scalar), dec_res);
    }

    // Trying to multiply a ciphertext with a scalar value
    // bigger than the ciphertext modulus should work
    {
        let nb_ct =
            (8f64 / (cks.parameters().message_modulus().0 as f64).log2().ceil()).ceil() as usize;
        let clear = 123u64;
        let scalar = 17823812983255694336u64;
        assert_eq!(scalar % 256, 0);

        let ct = cks.encrypt_radix(clear, nb_ct);
        let ct_res = sks.unchecked_scalar_mul_parallelized(&ct, scalar);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);
        assert_eq!(clear.wrapping_mul(scalar) % 256, dec_res);
    }
}

fn integer_smart_scalar_mul_u128_fix_non_reg_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let nb_ct =
        (128f64 / (cks.parameters().message_modulus().0 as f64).log2().ceil()).ceil() as usize;
    let cks = RadixClientKey::from((cks, nb_ct));

    //RNG
    let mut rng = rand::thread_rng();

    let clear = rng.gen::<u128>();

    let scalar = rng.gen::<u64>();

    // encryption of an integer
    let mut ct = cks.encrypt(clear);

    // scalar mul
    let ct_res = sks.smart_scalar_mul_parallelized(&mut ct, scalar);

    // decryption of ct_res, native modulus takes care of the mod operation
    let dec_res: u128 = cks.decrypt(&ct_res);

    // assert
    assert_eq!(clear.wrapping_mul(scalar as u128), dec_res);
}

fn integer_default_scalar_mul_u128_fix_non_reg_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let nb_ct =
        (128f64 / (cks.parameters().message_modulus().0 as f64).log2().ceil()).ceil() as usize;
    let cks = RadixClientKey::from((cks, nb_ct));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    let clear = rng.gen::<u128>();

    let scalar = rng.gen::<u64>();

    // encryption of an integer
    let ct = cks.encrypt(clear);

    // scalar mul
    let ct_res = sks.scalar_mul_parallelized(&ct, scalar);

    // decryption of ct_res, native modulus takes care of the mod operation
    let dec_res: u128 = cks.decrypt(&ct_res);

    // assert
    assert_eq!(clear.wrapping_mul(scalar as u128), dec_res);
}

fn integer_unchecked_scalar_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    let nb_bits = modulus.ilog2();

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0<= scalar < nb_bits
        {
            let scalar = scalar % nb_bits;
            let ct_res = sks.unchecked_scalar_left_shift_parallelized(&ct, scalar as u64);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.wrapping_shl(scalar) % modulus, dec_res);
        }

        // case when scalar >= nb_bits
        {
            let scalar = scalar.saturating_add(nb_bits);
            let ct_res = sks.unchecked_scalar_left_shift_parallelized(&ct, scalar as u64);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.wrapping_shl(scalar % nb_bits) % modulus, dec_res);
        }
    }

    let clear = rng.gen::<u64>() % modulus;
    let ct = cks.encrypt(clear);

    let nb_bits_in_block = cks.parameters().message_modulus().0.ilog2();
    for scalar in 0..nb_bits_in_block {
        let ct_res = sks.unchecked_scalar_left_shift_parallelized(&ct, scalar as u64);
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear.wrapping_shl(scalar) % modulus, dec_res);
    }
}

fn integer_unchecked_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    assert!(modulus.is_power_of_two());
    let nb_bits = modulus.ilog2();

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_left_shift_parallelized(&ct, &shift);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!((clear << clear_shift) % modulus, dec_res);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_left_shift_parallelized(&ct, &shift);
            let dec_res: u64 = cks.decrypt(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let mut nb_bits = modulus.ilog2();
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            assert_eq!((clear << (clear_shift % nb_bits)) % modulus, dec_res);
        }
    }
}

fn integer_unchecked_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    assert!(modulus.is_power_of_two());
    let nb_bits = modulus.ilog2();

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_right_shift_parallelized(&ct, &shift);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!((clear >> clear_shift) % modulus, dec_res);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_right_shift_parallelized(&ct, &shift);
            let dec_res: u64 = cks.decrypt(&ct_res);

            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let mut nb_bits = modulus.ilog2();
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            // We mimic wrapping_shr manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            assert_eq!((clear >> (clear_shift % nb_bits)) % modulus, dec_res);
        }
    }
}

fn integer_unchecked_rotate_left<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    assert!(modulus.is_power_of_two());
    let nb_bits = modulus.ilog2();

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0 <= rotate < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_rotate_left_parallelized(&ct, &shift);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_rotate_left_parallelized(&ct, &shift);
            let dec_res: u64 = cks.decrypt(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let true_nb_bits = nb_bits;
            let mut nb_bits = nb_bits;
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            let expected = rotate_left_helper(clear, clear_shift % nb_bits, true_nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

fn integer_unchecked_rotate_right<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    assert!(modulus.is_power_of_two());
    let nb_bits = modulus.ilog2();

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0 <= rotate < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_rotate_right_parallelized(&ct, &shift);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_rotate_right_parallelized(&ct, &shift);
            let dec_res: u64 = cks.decrypt(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let true_nb_bits = nb_bits;
            let mut nb_bits = nb_bits;
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            let expected = rotate_right_helper(clear, clear_shift % nb_bits, true_nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

fn integer_default_scalar_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    let nb_bits = modulus.ilog2();

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0<= scalar < nb_bits
        {
            let scalar = scalar % nb_bits;
            let ct_res = sks.scalar_left_shift_parallelized(&ct, scalar as u64);
            let tmp = sks.scalar_left_shift_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.checked_shl(scalar).unwrap_or(0) % modulus, dec_res);
        }

        // case when scalar >= nb_bits
        {
            let scalar = scalar.saturating_add(nb_bits);
            let ct_res = sks.scalar_left_shift_parallelized(&ct, scalar as u64);
            let tmp = sks.scalar_left_shift_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.wrapping_shl(scalar % nb_bits) % modulus, dec_res);
        }
    }

    let clear = rng.gen::<u64>() % modulus;
    let ct = cks.encrypt(clear);

    let nb_bits_in_block = cks.parameters().message_modulus().0.ilog2();
    for scalar in 0..nb_bits_in_block {
        let ct_res = sks.scalar_left_shift_parallelized(&ct, scalar as u64);
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear.wrapping_shl(scalar % nb_bits) % modulus, dec_res);
    }
}

fn integer_unchecked_scalar_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    let nb_bits = modulus.ilog2();

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0<= scalar < nb_bits
        {
            let scalar = scalar % nb_bits;
            let ct_res = sks.unchecked_scalar_right_shift_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.checked_shr(scalar).unwrap_or(0) % modulus, dec_res);
        }

        // case when scalar >= nb_bits
        {
            let scalar = scalar.saturating_add(nb_bits);
            let ct_res = sks.unchecked_scalar_right_shift_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.wrapping_shr(scalar % nb_bits) % modulus, dec_res);
        }
    }

    let clear = rng.gen::<u64>() % modulus;

    let ct = cks.encrypt(clear);
    let nb_bits_in_block = cks.parameters().message_modulus().0.ilog2();
    for scalar in 0..nb_bits_in_block {
        let ct_res = sks.unchecked_scalar_right_shift_parallelized(&ct, scalar as u64);
        assert!(ct_res.block_carries_are_empty());
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear.checked_shr(scalar).unwrap_or(0) % modulus, dec_res);
    }
}

fn integer_default_scalar_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    let nb_bits = modulus.ilog2();

    for _ in 0..NB_TEST_SMALLER {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0<= scalar < nb_bits
        {
            let scalar = scalar % nb_bits;
            let ct_res = sks.scalar_right_shift_parallelized(&ct, scalar as u64);
            let tmp = sks.scalar_right_shift_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.wrapping_shr(scalar) % modulus, dec_res);
        }

        // case when scalar >= nb_bits
        {
            let scalar = scalar.saturating_add(nb_bits);
            let ct_res = sks.scalar_right_shift_parallelized(&ct, scalar as u64);
            let tmp = sks.scalar_right_shift_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.wrapping_shr(scalar % nb_bits) % modulus, dec_res);
        }
    }

    let clear = rng.gen::<u64>() % modulus;

    let ct = cks.encrypt(clear);
    let nb_bits_in_block = cks.parameters().message_modulus().0.ilog2();
    for scalar in 0..nb_bits_in_block {
        let ct_res = sks.scalar_right_shift_parallelized(&ct, scalar as u64);
        let tmp = sks.scalar_right_shift_parallelized(&ct, scalar as u64);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear.wrapping_shr(scalar) % modulus, dec_res);
    }
}

/// helper function to do a rotate left when the type used to store
/// the value is bigger than the actual intended bit size
fn rotate_left_helper(value: u64, n: u32, actual_bit_size: u32) -> u64 {
    // We start with:
    // [0000000000000|xxxx]
    // 64           b    0
    //
    // rotated will be
    // [0000000000xx|xx00]
    // 64           b    0
    let n = n % actual_bit_size;
    let mask = 1u64.wrapping_shl(actual_bit_size) - 1;
    let shifted_mask = mask.wrapping_shl(n) & !mask;

    let rotated = value.rotate_left(n);

    (rotated & mask) | ((rotated & shifted_mask) >> actual_bit_size)
}

/// helper function to do a rotate right when the type used to store
/// the value is bigger than the actual intended bit size
fn rotate_right_helper(value: u64, n: u32, actual_bit_size: u32) -> u64 {
    // We start with:
    // [0000000000000|xxxx]
    // 64           b    0
    //
    // mask: [000000000000|mmmm]
    // shifted_ mask: [mm0000000000|0000]
    //
    // rotated will be
    // [xx0000000000|00xx]
    // 64           b    0
    //
    // To get the 'cycled' bits where they should be,
    // we get them using a mask then shift
    let n = n % actual_bit_size;
    let mask = 1u64.wrapping_shl(actual_bit_size) - 1;
    // shifted mask only needs the bits that cycled
    let shifted_mask = mask.rotate_right(n) & !mask;

    let rotated = value.rotate_right(n);

    (rotated & mask) | ((rotated & shifted_mask) >> (u64::BITS - actual_bit_size))
}

fn integer_unchecked_scalar_rotate_right<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    let nb_bits = modulus.ilog2();
    let bits_per_block = cks.parameters().message_modulus().0.ilog2();

    for _ in 0..(NB_TEST / 3).max(1) {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // Force case where n is multiple of block size
        {
            let scalar = scalar - (scalar % bits_per_block);
            let ct_res = sks.unchecked_scalar_rotate_right_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // Force case where n is not multiple of block size
        {
            let rest = scalar % bits_per_block;
            let scalar = if rest == 0 {
                scalar + (rng.gen::<u32>() % bits_per_block)
            } else {
                scalar
            };
            let ct_res = sks.unchecked_scalar_rotate_right_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // Force case where
        // The value is non zero
        // we rotate so that at least one non zero bit, cycle/wraps around
        {
            let value = rng.gen_range(1..=u32::MAX);
            let scalar = value.trailing_zeros() + rng.gen_range(1..nb_bits);
            let ct_res = sks.unchecked_scalar_rotate_right_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

fn integer_unchecked_scalar_rotate_left<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    let nb_bits = modulus.ilog2();
    let bits_per_block = cks.parameters().message_modulus().0.ilog2();

    for _ in 0..(NB_TEST / 3).max(1) {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // Force case where n is multiple of block size
        {
            let scalar = scalar - (scalar % bits_per_block);
            let ct_res = sks.unchecked_scalar_rotate_left_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_left_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // Force case where n is not multiple of block size
        {
            let rest = scalar % bits_per_block;
            let scalar = if rest == 0 {
                scalar + (rng.gen::<u32>() % bits_per_block)
            } else {
                scalar
            };
            let ct_res = sks.unchecked_scalar_rotate_left_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_left_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // Force case where
        // The value is non zero
        // we rotate so that at least one non zero bit, cycle/wraps around
        {
            let value = rng.gen_range(1..=u32::MAX);
            let scalar = value.leading_zeros() + rng.gen_range(1..nb_bits);
            let ct_res = sks.unchecked_scalar_rotate_right_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

fn integer_default_scalar_rotate_right<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    let nb_bits = modulus.ilog2();
    let bits_per_block = cks.parameters().message_modulus().0.ilog2();

    for _ in 0..(NB_TEST / 2).max(1) {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // Force case where n is multiple of block size
        {
            let scalar = scalar - (scalar % bits_per_block);
            let ct_res = sks.scalar_rotate_right_parallelized(&ct, scalar as u64);
            let tmp = sks.scalar_rotate_right_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // Force case where n is not multiple of block size
        {
            let rest = scalar % bits_per_block;
            let scalar = if rest == 0 {
                scalar + (rng.gen::<u32>() % bits_per_block)
            } else {
                scalar
            };
            let ct_res = sks.scalar_rotate_right_parallelized(&ct, scalar as u64);
            let tmp = sks.scalar_rotate_right_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // Force case where
        // The value is non zero
        // we rotate so that at least one non zero bit, cycle/wraps around
        {
            let value = rng.gen_range(1..=u32::MAX);
            let scalar = value.trailing_zeros() + rng.gen_range(1..nb_bits);
            let ct_res = sks.unchecked_scalar_rotate_right_parallelized(&ct, scalar as u64);
            let tmp = sks.unchecked_scalar_rotate_right_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

fn integer_default_scalar_rotate_left<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    let nb_bits = modulus.ilog2();
    let bits_per_block = cks.parameters().message_modulus().0.ilog2();

    for _ in 0..(NB_TEST / 3).max(1) {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // Force case where n is multiple of block size
        {
            let scalar = scalar - (scalar % bits_per_block);
            let ct_res = sks.scalar_rotate_left_parallelized(&ct, scalar as u64);
            let tmp = sks.scalar_rotate_left_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_left_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // Force case where n is not multiple of block size
        {
            let rest = scalar % bits_per_block;
            let scalar = if rest == 0 {
                scalar + (rng.gen::<u32>() % bits_per_block)
            } else {
                scalar
            };
            let ct_res = sks.scalar_rotate_left_parallelized(&ct, scalar as u64);
            let tmp = sks.scalar_rotate_left_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_left_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // Force case where
        // The value is non zero
        // we rotate so that at least one non zero bit, cycle/wraps around
        {
            let value = rng.gen_range(1..=u32::MAX);
            let scalar = value.leading_zeros() + rng.gen_range(1..nb_bits);
            let ct_res = sks.unchecked_scalar_rotate_right_parallelized(&ct, scalar as u64);
            let tmp = sks.unchecked_scalar_rotate_right_parallelized(&ct, scalar as u64);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

fn integer_default_scalar_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    sks.set_deterministic_pbs_execution(true);

    let num_block =
        (32f64 / (cks.parameters().message_modulus().0 as f64).log(2.0)).ceil() as usize;

    let cks = RadixClientKey::from((cks, num_block));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(num_block as u32) as u64;

    // the scalar is a u32, so the numerator must encrypt at least 32 bits
    // to take the normal path of execution
    assert!(modulus >= (1 << u32::BITS));

    let result = std::panic::catch_unwind(|| {
        let numerator = sks.create_trivial_radix(1, num_block);
        sks.scalar_div_rem_parallelized(&numerator, 0u8);
    });
    assert!(result.is_err(), "division by zero should panic");

    // hard-coded tests
    // 10, 7, 14 are from the paper and should trigger different branches
    // 16 is a power of two and should trigger the corresponding branch
    let hard_coded_divisors: [u32; 4] = [10, 7, 14, 16];
    for divisor in hard_coded_divisors {
        let clear = rng.gen::<u64>() % modulus;
        let ct = cks.encrypt(clear);

        let (q, r) = sks.scalar_div_rem_parallelized(&ct, divisor);

        let q_res: u64 = cks.decrypt(&q);
        let r_res: u64 = cks.decrypt(&r);
        assert_eq!(q_res, clear / divisor as u64);
        assert_eq!(r_res, clear % divisor as u64);
    }

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen_range(1u32..=u32::MAX);

        let ct = cks.encrypt(clear);

        {
            let (q, r) = sks.scalar_div_rem_parallelized(&ct, scalar);
            let (q2, r2) = sks.scalar_div_rem_parallelized(&ct, scalar);
            assert!(q.block_carries_are_empty());
            assert!(r.block_carries_are_empty());
            assert_eq!(q, q2);
            assert_eq!(r, r2);

            let q_res: u64 = cks.decrypt(&q);
            let r_res: u64 = cks.decrypt(&r);
            assert_eq!(q_res, clear / scalar as u64);
            assert_eq!(r_res, clear % scalar as u64);
        }

        {
            // Test when scalar is trivially bigger than the ct
            let scalar = rng.gen_range(u32::MAX as u64 + 1..=u64::MAX);

            let (q, r) = sks.scalar_div_rem_parallelized(&ct, scalar);
            let (q2, r2) = sks.scalar_div_rem_parallelized(&ct, scalar);
            assert!(q.block_carries_are_empty());
            assert!(r.block_carries_are_empty());
            assert_eq!(q, q2);
            assert_eq!(r, r2);

            let q_res: u64 = cks.decrypt(&q);
            let r_res: u64 = cks.decrypt(&r);
            assert_eq!(q_res, clear / scalar);
            assert_eq!(r_res, clear % scalar);
        }
    }
}

fn integer_smart_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

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

fn integer_default_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST_SMALLER {
        // Define the cleartexts
        let clear = rng.gen::<u64>() % modulus;

        // Encrypt the integers
        let ctxt = cks.encrypt(clear);

        // Negates the ctxt
        let ct_res = sks.neg_parallelized(&ctxt);
        let tmp = sks.neg_parallelized(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);

        // Decrypt the result
        let dec: u64 = cks.decrypt(&ct_res);

        // Check the correctness
        let clear_result = clear.wrapping_neg() % modulus;

        assert_eq!(clear_result, dec);
    }
}

fn integer_smart_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

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

fn integer_default_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

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
            let tmp = sks.sub_parallelized(&res, &ctxt_2);
            res = sks.sub_parallelized(&res, &ctxt_2);
            assert!(res.block_carries_are_empty());
            assert_eq!(res, tmp);
            clear = (clear.wrapping_sub(clear2)) % modulus;
            // println!("clear = {}, clear2 = {}", clear, cks.decrypt(&res));
        }
        let dec: u64 = cks.decrypt(&res);

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_default_sub_work_efficient<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST_SMALLER {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        let ctxt_1 = cks.encrypt(clear1);
        let ctxt_2 = cks.encrypt(clear2);

        let tmp = sks.sub_parallelized_work_efficient(&ctxt_1, &ctxt_2);
        let res = sks.sub_parallelized_work_efficient(&ctxt_1, &ctxt_2);

        assert!(res.block_carries_are_empty());
        assert_eq!(res, tmp);

        let expected = (clear1.wrapping_sub(clear2)) % modulus;
        let dec: u64 = cks.decrypt(&res);

        // Check the correctness
        assert_eq!(expected, dec);
    }
}

fn integer_unchecked_block_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let block_modulus = cks.parameters().message_modulus().0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % block_modulus;

        // encryption of an integer
        let ct_zero = cks.encrypt(clear_0);

        // encryption of an integer
        let ct_one = cks.encrypt_one_block(clear_1);

        let ct_res = sks.unchecked_block_mul_parallelized(&ct_zero, &ct_one, 0);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 * clear_1) % modulus, dec_res);
    }
}

fn integer_smart_block_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let block_modulus = cks.parameters().message_modulus().0 as u64;

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

fn integer_default_block_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let block_modulus = cks.parameters().message_modulus().0 as u64;

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
            let tmp = sks.block_mul_parallelized(&res, &ctxt_2, 0);
            res = sks.block_mul_parallelized(&res, &ctxt_2, 0);
            assert!(res.block_carries_are_empty());
            assert_eq!(res, tmp);
            clear = (clear * clear2) % modulus;
        }
        let dec: u64 = cks.decrypt(&res);

        clear = (clear * clear2) % modulus;

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_smart_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let param: PBSParameters = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

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

fn integer_default_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

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
            let tmp = sks.mul_parallelized(&res, &ctxt_2);
            res = sks.mul_parallelized(&res, &ctxt_2);
            assert!(res.block_carries_are_empty());
            assert_eq!(res, tmp);
            clear = (clear * clear2) % modulus;
        }
        let dec: u64 = cks.decrypt(&res);

        clear = (clear * clear2) % modulus;

        // Check the correctness
        assert_eq!(clear, dec);
    }

    {
        // test x * y and y * x
        // where y encrypts a boolean value
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen_range(0u64..=1);

        let ctxt_1 = cks.encrypt(clear1);
        let ctxt_2: RadixCiphertext = sks.create_trivial_radix(clear2, ctxt_1.blocks.len());
        assert!(ctxt_2.holds_boolean_value());

        let res = sks.mul_parallelized(&ctxt_1, &ctxt_2);
        let dec: u64 = cks.decrypt(&res);
        assert_eq!(dec, clear1 * clear2);

        let res = sks.mul_parallelized(&ctxt_2, &ctxt_1);
        let dec: u64 = cks.decrypt(&res);
        assert_eq!(dec, clear1 * clear2);
    }
}

fn integer_smart_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    // generate the server-client key set
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    // RNG
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

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

fn integer_default_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    // generate the server-client key set
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    // RNG
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        let mut ct_res = sks.scalar_add_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());

        clear = (clear_0 + clear_1) % modulus;

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        //add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            let tmp = sks.scalar_add_parallelized(&ct_res, clear_1);
            ct_res = sks.scalar_add_parallelized(&ct_res, clear_1);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear = (clear + clear_1) % modulus;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_smart_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    // generate the server-client key set
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    // RNG
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

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

fn integer_default_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    // generate the server-client key set
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    let mut clear;

    // RNG
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        let mut ct_res = sks.scalar_sub_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());

        clear = (clear_0.wrapping_sub(clear_1)) % modulus;

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        //add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            let tmp = sks.scalar_sub_parallelized(&ct_res, clear_1);
            ct_res = sks.scalar_sub_parallelized(&ct_res, clear_1);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear = (clear.wrapping_sub(clear_1)) % modulus;

            // decryption of ct_res
            let dec_res: u64 = cks.decrypt(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

#[test]
fn test_non_regression_clone_from() {
    // Issue: https://github.com/zama-ai/tfhe-rs/issues/410
    let (client_key, server_key) = KEY_CACHE.get_from_params(PARAM_MESSAGE_2_CARRY_2);
    const NUM_BLOCK: usize = 4;
    let a: u8 = 248;
    let b: u8 = 249;
    let c: u8 = 250;
    let d: u8 = 251;

    let enc_a = client_key.encrypt_radix(a, NUM_BLOCK);
    let enc_b = client_key.encrypt_radix(b, NUM_BLOCK);
    let enc_c = client_key.encrypt_radix(c, NUM_BLOCK);
    let enc_d = client_key.encrypt_radix(d, NUM_BLOCK);

    let (mut q1, mut r1) = server_key.div_rem_parallelized(&enc_b, &enc_a);
    let (mut q2, mut r2) = server_key.div_rem_parallelized(&enc_d, &enc_c);

    assert_eq!(client_key.decrypt_radix::<u8>(&r1), 1);
    assert_eq!(client_key.decrypt_radix::<u8>(&r2), 1);
    assert_eq!(client_key.decrypt_radix::<u8>(&q1), 1);
    assert_eq!(client_key.decrypt_radix::<u8>(&q2), 1);

    // The consequence of the bug was that r1r2 would be 0 instead of one
    let r1r2 = server_key.smart_mul_parallelized(&mut r1, &mut r2);
    assert_eq!(client_key.decrypt_radix::<u8>(&r1r2), 1);
    let q1q2 = server_key.smart_mul_parallelized(&mut q1, &mut q2);
    assert_eq!(client_key.decrypt_radix::<u8>(&q1q2), 1);
}

fn integer_smart_if_then_else<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;
        let clear_condition = rng.gen_range(0u64..1);

        let mut ctxt_0 = cks.encrypt(clear_0);
        let mut ctxt_1 = cks.encrypt(clear_1);
        // cks.encrypt returns a ciphertext which does not look like
        // (when looking at the degree) it encrypts a boolean value.
        // So we 'force' having a boolean encrypting ciphertext by using eq (==)
        let mut ctxt_condition = sks.scalar_eq_parallelized(&cks.encrypt(clear_condition), 1);
        assert!(ctxt_condition.holds_boolean_value());

        let ct_res =
            sks.smart_if_then_else_parallelized(&mut ctxt_condition, &mut ctxt_0, &mut ctxt_1);

        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(
            dec_res,
            if clear_condition == 1 {
                clear_0
            } else {
                clear_1
            }
        );

        let clear_2 = rng.gen::<u64>() % modulus;
        let clear_3 = rng.gen::<u64>() % modulus;

        let ctxt_2 = cks.encrypt(clear_2);
        let ctxt_3 = cks.encrypt(clear_3);

        // Add to have non empty carries
        sks.unchecked_add_assign(&mut ctxt_0, &ctxt_2);
        sks.unchecked_add_assign(&mut ctxt_1, &ctxt_3);
        assert!(!ctxt_0.block_carries_are_empty());
        assert!(!ctxt_1.block_carries_are_empty());

        let ct_res =
            sks.smart_if_then_else_parallelized(&mut ctxt_condition, &mut ctxt_0, &mut ctxt_1);
        assert!(ctxt_0.block_carries_are_empty());
        assert!(ctxt_1.block_carries_are_empty());

        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(
            dec_res,
            if clear_condition == 1 {
                (clear_0 + clear_2) % modulus
            } else {
                (clear_1 + clear_3) % modulus
            }
        );
    }
}

fn integer_default_if_then_else<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;
        let clear_condition = rng.gen_range(0u64..1);

        let mut ctxt_0 = cks.encrypt(clear_0);
        let mut ctxt_1 = cks.encrypt(clear_1);
        // cks.encrypt returns a ciphertext which does not look like
        // (when looking at the degree) it encrypts a boolean value.
        // So we 'force' having a boolean encrypting ciphertext by using eq (==)
        let ctxt_condition = sks.scalar_eq_parallelized(&cks.encrypt(clear_condition), 1);
        assert!(ctxt_condition.holds_boolean_value());

        let ct_res = sks.if_then_else_parallelized(&ctxt_condition, &ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());

        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(
            dec_res,
            if clear_condition == 1 {
                clear_0
            } else {
                clear_1
            }
        );

        let ct_res2 = sks.if_then_else_parallelized(&ctxt_condition, &ctxt_0, &ctxt_1);
        assert_eq!(ct_res, ct_res2, "Operation if not deterministic");

        let clear_2 = rng.gen::<u64>() % modulus;
        let clear_3 = rng.gen::<u64>() % modulus;

        let ctxt_2 = cks.encrypt(clear_2);
        let ctxt_3 = cks.encrypt(clear_3);

        // Add to have non empty carries
        sks.unchecked_add_assign(&mut ctxt_0, &ctxt_2);
        sks.unchecked_add_assign(&mut ctxt_1, &ctxt_3);
        assert!(!ctxt_0.block_carries_are_empty());
        assert!(!ctxt_1.block_carries_are_empty());

        let ct_res = sks.if_then_else_parallelized(&ctxt_condition, &ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());

        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(
            dec_res,
            if clear_condition == 1 {
                (clear_0 + clear_2) % modulus
            } else {
                (clear_1 + clear_3) % modulus
            }
        );
    }
}
