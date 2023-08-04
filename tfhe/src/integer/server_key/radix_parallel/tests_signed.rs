use crate::integer::keycache::KEY_CACHE;
use crate::integer::RadixClientKey;
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

create_parametrized_test!(integer_signed_encrypt_decrypt);
create_parametrized_test!(integer_signed_encrypt_decrypt_128_bits);

create_parametrized_test!(integer_signed_unchecked_add);
create_parametrized_test!(integer_signed_smart_add);
create_parametrized_test!(integer_signed_default_add);

create_parametrized_test!(integer_signed_default_scalar_add);

// Adds two signed number modulo the given modulus
//
// This is to 'simulate' i8, i16, ixy using i64 integers
//
// lhs and rhs must be in [-modulus..modulus[
fn signed_add_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    assert!(modulus > 0);
    let mut res = lhs + rhs;
    if res < -modulus {
        // rem_euclid(modulus) would also work
        res = modulus + (res - -modulus);
    } else if res > modulus - 1 {
        res = -modulus + (res - modulus);
    }
    res
}

fn integer_signed_encrypt_decrypt_128_bits(param: impl Into<PBSParameters>) {
    let (cks, _) = KEY_CACHE.get_from_params(param);

    let mut rng = rand::thread_rng();
    let num_block =
        (128f64 / (cks.parameters().message_modulus().0 as f64).log(2.0)).ceil() as usize;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<i128>();

        let ct = cks.encrypt_signed_radix(clear, num_block);

        let dec: i128 = cks.decrypt_signed_radix(&ct);
        assert_eq!(clear, dec);
    }
}

fn integer_signed_encrypt_decrypt(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TEST {
        let clear = rng.gen_range(i64::MIN..=0) % modulus;

        let ct = cks.encrypt_signed_radix(clear, NB_CTXT);
        let dec: i64 = cks.decrypt_signed_radix(&ct);
        assert_eq!(clear, dec);

        let trivial_ct = sks.create_trivial_radix(clear, NB_CTXT);
        let dec: i64 = cks.decrypt_signed_radix(&trivial_ct);
        assert_eq!(clear, dec);
    }

    for _ in 0..NB_TEST {
        let clear = rng.gen_range(0..=i64::MAX) % modulus;

        let ct = cks.encrypt_signed_radix(clear, NB_CTXT);
        let dec: i64 = cks.decrypt_signed_radix(&ct);
        assert_eq!(clear, dec);

        let trivial_ct = sks.create_trivial_radix(clear, NB_CTXT);
        let dec: i64 = cks.decrypt_signed_radix(&trivial_ct);
        assert_eq!(clear, dec);
    }
}

fn integer_signed_unchecked_add(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let ct_res = sks.unchecked_add_parallelized(&ctxt_0, &ctxt_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = signed_add_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_smart_add(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen_range(-modulus..modulus);
        let clear_1 = rng.gen_range(-modulus..modulus);

        let mut ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let mut ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let mut ct_res = sks.smart_add_parallelized(&mut ctxt_0, &mut ctxt_1);
        clear = signed_add_under_modulus(clear_0, clear_1, modulus);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        assert_eq!(clear, dec_res);

        // add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            ct_res = sks.smart_add_parallelized(&mut ct_res, &mut ctxt_0);
            clear = signed_add_under_modulus(clear, clear_0, modulus);

            let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_signed_default_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let mut clear;

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let mut ct_res = sks.add_parallelized(&ctxt_0, &ctxt_1);
        let tmp_ct = sks.add_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct);

        clear = signed_add_under_modulus(clear_0, clear_1, modulus);

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        // add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            ct_res = sks.add_parallelized(&ct_res, &ctxt_0);
            assert!(ct_res.block_carries_are_empty());
            clear = signed_add_under_modulus(clear, clear_0, modulus);

            let dec_res: i64 = cks.decrypt_signed(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            assert_eq!(clear, dec_res);
        }
    }
}
fn integer_signed_default_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let mut clear;

    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let mut ct_res = sks.scalar_add_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());

        clear = signed_add_under_modulus(clear_0, clear_1, modulus);

        // add multiple times to raise the degree
        for _ in 0..NB_TEST_SMALLER {
            let tmp = sks.scalar_add_parallelized(&ct_res, clear_1);
            ct_res = sks.scalar_add_parallelized(&ct_res, clear_1);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear = signed_add_under_modulus(clear, clear_1, modulus);

            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}
