// use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::parameters::parameters_compact_pk::*;
use crate::shortint::parameters::*;
use paste::paste;
use rand::Rng;

/// Number of assert in randomized tests
const NB_TEST: usize = 30;

// Macro to generate tests for all parameter sets
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
            PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS,
            PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_PBS_KS,
            PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_PBS_KS
        });
    };
}

create_parametrized_test!(shortint_compact_public_key_base_smart_add);

fn shortint_compact_public_key_base_smart_add(params: ClassicPBSParameters) {
    let (cks, sks) = crate::shortint::gen_keys(params);
    let pk = crate::shortint::CompactPublicKey::new(&cks);

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = pk.encrypt(clear_0);

        let ctxt_1 = pk.encrypt(clear_1);

        let d = cks.decrypt(&ctxt_0);
        assert_eq!(d, clear_0);
        let d = cks.decrypt(&ctxt_1);
        assert_eq!(d, clear_1);

        let mut ct_res = sks.unchecked_add(&ctxt_0, &ctxt_1);
        let mut clear = clear_0 + clear_1;
        let d = cks.decrypt(&ct_res);
        assert_eq!(d, clear % modulus);

        //add multiple times to raise the degree and test the smart operation
        for _ in 0..40 {
            sks.smart_add_assign(&mut ct_res, &mut ctxt_0);
            clear += clear_0;

            // decryption of ct_res
            let dec_res = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear % modulus, dec_res);
        }
    }
}

create_parametrized_test!(shortint_compact_public_key_base_list_smart_sub);

fn shortint_compact_public_key_base_list_smart_sub(params: ClassicPBSParameters) {
    let (cks, sks) = crate::shortint::gen_keys(params);
    let pk = crate::shortint::CompactPublicKey::new(&cks);

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    const MAX_CT: usize = 5;

    let mut first_clear_vec = Vec::with_capacity(MAX_CT);
    let mut second_clear_vec = Vec::with_capacity(MAX_CT);

    for _ in 0..(NB_TEST / 2).min(5) {
        let num_ct_for_this_iter = rng.gen_range(1..=MAX_CT);
        first_clear_vec.truncate(0);
        second_clear_vec.truncate(0);
        for _ in 0..num_ct_for_this_iter {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            first_clear_vec.push(clear_0);
            second_clear_vec.push(clear_1);
        }

        let first_compact_list = pk.encrypt_slice(&first_clear_vec);
        let second_compact_list = pk.encrypt_slice(&second_clear_vec);

        let mut first_expanded_vec = first_compact_list.expand();
        let mut second_expanded_vec = second_compact_list.expand();

        // decryption check
        for i in 0..num_ct_for_this_iter {
            let decrypted_0 = cks.decrypt(&first_expanded_vec[i]);
            let decrypted_1 = cks.decrypt(&second_expanded_vec[i]);

            assert_eq!(decrypted_0, first_clear_vec[i]);
            assert_eq!(decrypted_1, second_clear_vec[i]);
        }

        for _ in 0..10 {
            for i in 0..num_ct_for_this_iter {
                sks.smart_sub_assign(&mut first_expanded_vec[i], &mut second_expanded_vec[i]);
                first_clear_vec[i] = first_clear_vec[i].wrapping_sub(second_clear_vec[i]);

                let decrypted_0 = cks.decrypt(&first_expanded_vec[i]);
                let decrypted_1 = cks.decrypt(&second_expanded_vec[i]);

                assert_eq!(decrypted_0, first_clear_vec[i] % modulus);
                assert_eq!(decrypted_1, second_clear_vec[i] % modulus);
            }
        }
    }
}
