use crate::core_crypto::commons::crypto::encoding::{
    Cleartext, Encoder, Plaintext, RealEncoder,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::test_tools::{any_uint, random_uint_between};

fn test_encoding_decoding<T: UnsignedTorus>() {
    //! Encodes and decodes random messages
    let n_tests = 1000;
    for _i in 0..n_tests {
        // the real interval is [int_o,int_beta]
        let mut int_o: T = any_uint();
        let mut int_beta: T = any_uint();

        // if int_o > int_beta, we swap them
        if int_beta < int_o {
            std::mem::swap(&mut int_beta, &mut int_o);
        }

        // converts int_o and int_delta into f64
        let offset: f64 = int_o.cast_into();
        let delta: f64 = (int_beta - int_o).cast_into();

        // generates a random message
        let int_m: T = random_uint_between(int_o..int_beta);
        let m: f64 = int_m.cast_into();

        // encodes and decodes
        let encoder = RealEncoder { offset, delta };
        let encoding: Plaintext<T> = encoder.encode(Cleartext(m));
        let decoding = encoder.decode(encoding);

        // test
        if T::BITS == 32 {
            assert_delta_scalar!(m, decoding.0, 1);
        } else {
            assert_delta_scalar!(m, decoding.0, 1 << 11);
        }
    }
}

#[test]
fn test_encoding_decoding_u32() {
    test_encoding_decoding::<u32>()
}

#[test]
fn test_encoding_decoding_u64() {
    test_encoding_decoding::<u64>()
}
