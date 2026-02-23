use crate::integer::gen_keys_radix;
use crate::integer::tests::create_parameterized_test;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;

const NB_TESTS: usize = 10;

create_parameterized_test!(modulus_switch_compression_signed);

fn modulus_switch_compression_signed<P>(param: P)
where
    P: Into<TestParameters>,
{
    let size = 4;
    let (cks, sks) = gen_keys_radix(param, size);

    let mut rng = rand::rng();

    for _ in 0..NB_TESTS {
        let bound = sks.message_modulus().0.pow(size as u32) as i64 / 2;

        let clear: i64 = rng.gen_range(-bound..bound);

        let ctxt = cks.encrypt_signed(clear);

        let compressed_ct = sks.switch_modulus_and_compress_signed_parallelized(&ctxt);

        let decompressed_ct = sks.decompress_signed_parallelized(&compressed_ct);

        let dec: i64 = cks.decrypt_signed(&decompressed_ct);

        assert_eq!(clear, dec);
    }
}
