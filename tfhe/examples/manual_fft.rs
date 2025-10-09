use tfhe::core_crypto::fft_impl::fft64::math::fft::{setup_custom_fft_plan, FftAlgo, Method, Plan};
use tfhe::prelude::*;
use tfhe::{set_server_key, ClientKey, ConfigBuilder, FheUint64, ServerKey};

pub fn main() {
    let n = 2048;
    let my_plan = Plan::new(
        // n / 2 is due to how TFHE-rs handles ffts
        n / 2,
        Method::UserProvided {
            // User responsibility to choose an algorithm compatible with their n
            // Both for the algorithm and the base_n
            base_algo: FftAlgo::Dif4,
            base_n: n / 2,
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
