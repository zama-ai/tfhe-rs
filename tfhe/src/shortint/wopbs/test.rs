use crate::shortint::keycache::KEY_CACHE_WOPBS;
use crate::shortint::parameters::parameters_wopbs_message_carry::*;
use crate::shortint::parameters::{
    MessageModulus, PARAM_MESSAGE_1_CARRY_1_KS_PBS, PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS, PARAM_MESSAGE_4_CARRY_4_KS_PBS,
};
use crate::shortint::wopbs::WopbsKey;
use crate::shortint::{gen_keys, ClassicPBSParameters, WopbsParameters};
use paste::paste;
use rand::Rng;

const NB_TEST: usize = 1;

macro_rules! create_parametrized_test{
    ($name:ident { $( ($sks_param:ident, $wopbs_param:ident) ),* }) => {
        paste! {
            $(
            #[test]
            fn [<test_ $name _ $wopbs_param:lower>]() {
                $name(($sks_param, $wopbs_param))
            }
            )*
        }
    };
     ($name:ident)=> {
        create_parametrized_test!($name
        {
            (PARAM_MESSAGE_1_CARRY_1_KS_PBS, WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS),
            (PARAM_MESSAGE_2_CARRY_2_KS_PBS, WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS),
            (PARAM_MESSAGE_3_CARRY_3_KS_PBS, WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS),
            (PARAM_MESSAGE_4_CARRY_4_KS_PBS, WOPBS_PARAM_MESSAGE_4_CARRY_4_KS_PBS)
        });
    };
}

create_parametrized_test!(generate_lut);
create_parametrized_test!(generate_lut_modulus);
create_parametrized_test!(generate_lut_modulus_not_power_of_two);

fn generate_lut(params: (ClassicPBSParameters, WopbsParameters)) {
    let keys = KEY_CACHE_WOPBS.get_from_param(params);
    let (cks, sks, wopbs_key) = (keys.client_key(), keys.server_key(), keys.wopbs_key());
    let mut rng = rand::thread_rng();

    let mut tmp = 0;
    for _ in 0..NB_TEST {
        let message_modulus = params.0.message_modulus.0;
        let m = rng.gen::<usize>() % message_modulus;
        let ct = cks.encrypt(m as u64);
        let lut = wopbs_key.generate_lut(&ct, |x| x % message_modulus as u64);
        let ct_res = wopbs_key.programmable_bootstrapping(sks, &ct, &lut);

        let res = cks.decrypt(&ct_res);
        if res != (m % message_modulus) as u64 {
            tmp += 1;
        }
    }
    if 0 != tmp {
        println!("______");
        println!("failure rate {tmp:?}/{NB_TEST:?}");
        println!("______");
    }
    assert_eq!(0, tmp);
}

fn generate_lut_modulus(params: (ClassicPBSParameters, WopbsParameters)) {
    let keys = KEY_CACHE_WOPBS.get_from_param(params);
    let (cks, sks, wopbs_key) = (keys.client_key(), keys.server_key(), keys.wopbs_key());
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST {
        let message_modulus = MessageModulus(params.0.message_modulus.0 - 1);
        let m = rng.gen::<usize>() % message_modulus.0;

        let ct = cks.encrypt_with_message_modulus(m as u64, message_modulus);

        let ct = wopbs_key.keyswitch_to_wopbs_params(sks, &ct);
        let lut = wopbs_key.generate_lut(&ct, |x| (x * x) % message_modulus.0 as u64);
        let ct_res = wopbs_key.wopbs(&ct, &lut);
        let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);

        let res = cks.decrypt(&ct_res);
        assert_eq!(res as usize, (m * m) % message_modulus.0);
    }
}

fn generate_lut_modulus_not_power_of_two(params: (ClassicPBSParameters, WopbsParameters)) {
    let (cks, sks) = gen_keys(params.1);
    let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);
    // let keys = KEY_CACHE_WOPBS.get_from_param((WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_2_KS_PBS,
    // WOPBS_PRIME_PARAM_MESSAGE_2_NORM2_2_KS_PBS)); let (cks, _, wopbs_key) = (keys.client_key(),
    // keys.server_key(), keys.wopbs_key());
    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST {
        let message_modulus = MessageModulus(params.0.message_modulus.0 - 1);

        let m = rng.gen::<usize>() % message_modulus.0;
        let mut ct = cks.encrypt_native_crt(m as u64, message_modulus.0 as u8);
        let lut = wopbs_key.generate_lut_native_crt(&ct, |x| (x * x) % message_modulus.0 as u64);

        let ct_res = wopbs_key.programmable_bootstrapping_native_crt(&mut ct, &lut);
        let res = cks.decrypt_message_native_crt(&ct_res, message_modulus.0 as u8);
        assert_eq!(res as usize, (m * m) % message_modulus.0);
    }
}
