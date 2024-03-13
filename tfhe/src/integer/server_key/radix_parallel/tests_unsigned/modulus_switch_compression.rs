use crate::integer::gen_keys_radix;
use crate::integer::tests::create_parametrized_test_classical_params;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use rand::Rng;

const NB_TESTS: usize = 10;

// Remove multi bit PBS parameters as
// modulus switch compression and multi bit PBS are currently not compatible
create_parametrized_test_classical_params!(modulus_switch_compression);

fn modulus_switch_compression<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let size = 4;
    let (cks, sks) = gen_keys_radix(param, size);

    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let bound = sks.message_modulus().0.pow(size as u32) as u64;

        let clear: u64 = rng.gen_range(0..bound);

        let ctxt = cks.encrypt(clear);

        let compressed_ct = sks.switch_modulus_and_compress_parallelized(&ctxt);

        let decompressed_ct = sks.decompress_parallelized(&compressed_ct);

        let dec: u64 = cks.decrypt(&decompressed_ct);

        assert_eq!(clear, dec);
    }
}
