use tfhe::core_crypto::fft_impl::fft64::math::fft::{
    setup_custom_fft_plan, FftAlgo, Method, Plan, PolynomialSize,
};
use tfhe::prelude::*;
use tfhe::{set_server_key, ClientKey, ConfigBuilder, FheUint64, ServerKey};

pub fn main() {
    let n = PolynomialSize(2048);
    let fourier_polynomial_size = n.to_fourier_polynomial_size();
    let my_plan = Plan::new(
        fourier_polynomial_size.0,
        Method::UserProvided {
            // User responsibility to choose an algorithm compatible with their n
            // Both for the algorithm and the base_n
            base_algo: FftAlgo::Dif4,
            base_n: fourier_polynomial_size.0,
        },
    );

    setup_custom_fft_plan(my_plan);

    let config = ConfigBuilder::default().build();
    let cks = ClientKey::generate(config);
    let sks = ServerKey::new(&cks);

    let msg_a: u64 = 42;
    let msg_b: u64 = 69;

    let a = FheUint64::encrypt(msg_a, &cks);
    let b = FheUint64::encrypt(msg_b, &cks);

    set_server_key(sks);

    let c = &a * &b;

    let res: u64 = c.decrypt(&cks);

    assert_eq!(res, msg_a.wrapping_mul(msg_b));
}
