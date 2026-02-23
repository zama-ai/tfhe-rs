use super::NB_TESTS;
use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::NoiseLevel;
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
use rand::Rng;

create_parameterized_test!(shortint_modulus_switch_compression);

fn shortint_modulus_switch_compression<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::rng();

    let modulus_sup = cks.parameters().message_modulus().0 * cks.parameters().carry_modulus().0;

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % modulus_sup;

        let ctxt = cks.unchecked_encrypt(clear);

        let compressed_ct = sks.switch_modulus_and_compress(&ctxt);

        {
            let decompressed_ct = sks.decompress(&compressed_ct);

            let dec = cks.decrypt_message_and_carry(&decompressed_ct);

            assert_eq!(clear, dec);

            assert_eq!(ctxt.degree, decompressed_ct.degree);
            assert_eq!(decompressed_ct.noise_level(), NoiseLevel::NOMINAL);
            assert_eq!(ctxt.message_modulus, decompressed_ct.message_modulus);
            assert_eq!(ctxt.carry_modulus, decompressed_ct.carry_modulus);
            assert_eq!(ctxt.atomic_pattern, decompressed_ct.atomic_pattern);
        }
        {
            let lookup_table = sks.generate_msg_lookup_table(|a| a + 1, ctxt.message_modulus);

            let decompressed_ct =
                sks.decompress_and_apply_lookup_table(&compressed_ct, &lookup_table);

            let dec = cks.decrypt(&decompressed_ct);

            assert_eq!((clear + 1) % modulus, dec % modulus);

            assert_eq!(decompressed_ct.noise_level(), NoiseLevel::NOMINAL);
            assert_eq!(ctxt.message_modulus, decompressed_ct.message_modulus);
            assert_eq!(ctxt.carry_modulus, decompressed_ct.carry_modulus);
            assert_eq!(ctxt.atomic_pattern, decompressed_ct.atomic_pattern);
        }
    }
}
