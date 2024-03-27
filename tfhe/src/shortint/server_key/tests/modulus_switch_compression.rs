use super::NB_TESTS;
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::parameters::*;
use crate::shortint::server_key::tests::parametrized_test::create_parametrized_test;
use rand::Rng;

// Remove multi bit PBS parameters as
// modulus switch compression and multi bit PBS are currently not compatible
create_parametrized_test!(shortint_modulus_switch_compression {
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_1_CARRY_2_KS_PBS,
    PARAM_MESSAGE_1_CARRY_3_KS_PBS,
    PARAM_MESSAGE_1_CARRY_4_KS_PBS,
    PARAM_MESSAGE_1_CARRY_5_KS_PBS,
    PARAM_MESSAGE_1_CARRY_6_KS_PBS,
    PARAM_MESSAGE_1_CARRY_7_KS_PBS,
    PARAM_MESSAGE_2_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    PARAM_MESSAGE_2_CARRY_4_KS_PBS,
    PARAM_MESSAGE_2_CARRY_5_KS_PBS,
    PARAM_MESSAGE_2_CARRY_6_KS_PBS,
    PARAM_MESSAGE_3_CARRY_1_KS_PBS,
    PARAM_MESSAGE_3_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_3_CARRY_4_KS_PBS,
    PARAM_MESSAGE_3_CARRY_5_KS_PBS,
    PARAM_MESSAGE_4_CARRY_1_KS_PBS,
    PARAM_MESSAGE_4_CARRY_2_KS_PBS,
    PARAM_MESSAGE_4_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MESSAGE_5_CARRY_1_KS_PBS,
    PARAM_MESSAGE_5_CARRY_2_KS_PBS,
    PARAM_MESSAGE_5_CARRY_3_KS_PBS,
    PARAM_MESSAGE_6_CARRY_1_KS_PBS,
    PARAM_MESSAGE_6_CARRY_2_KS_PBS,
    PARAM_MESSAGE_7_CARRY_1_KS_PBS
});

fn shortint_modulus_switch_compression<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus_sup =
        (cks.parameters.message_modulus().0 * cks.parameters.carry_modulus().0) as u64;

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % modulus_sup;

        let ctxt = cks.unchecked_encrypt(clear);

        let compressed_ct = sks.switch_modulus_and_compress(&ctxt);

        {
            let decompressed_ct = sks.decompress(&compressed_ct);

            let dec = cks.decrypt_message_and_carry(&decompressed_ct);

            assert_eq!(clear, dec);

            assert_eq!(ctxt.degree, decompressed_ct.degree);
            assert_eq!(decompressed_ct.noise_level, NoiseLevel::NOMINAL);
            assert_eq!(ctxt.message_modulus, decompressed_ct.message_modulus);
            assert_eq!(ctxt.carry_modulus, decompressed_ct.carry_modulus);
            assert_eq!(ctxt.pbs_order, decompressed_ct.pbs_order);
        }
        {
            let lookup_table = sks.generate_msg_lookup_table(|a| a + 1, ctxt.message_modulus);

            let decompressed_ct =
                sks.decompress_and_apply_lookup_table(&compressed_ct, &lookup_table);

            let dec = cks.decrypt(&decompressed_ct);

            assert_eq!((clear + 1) % modulus, dec % modulus);

            assert_eq!(decompressed_ct.noise_level, NoiseLevel::NOMINAL);
            assert_eq!(ctxt.message_modulus, decompressed_ct.message_modulus);
            assert_eq!(ctxt.carry_modulus, decompressed_ct.carry_modulus);
            assert_eq!(ctxt.pbs_order, decompressed_ct.pbs_order);
        }
    }
}
