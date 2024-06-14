use tfhe::prelude::*;
use tfhe::shortint::parameters::DynamicDistribution;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut my_params = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    // DISCLAIMER: This is not guaranteed to be secure, thorough noise and security analysis are
    // required by the end user
    // This is only to demonstrate that one can use custom noise distribution if they want to
    my_params.lwe_noise_distribution = DynamicDistribution::new_t_uniform(20);
    my_params.glwe_noise_distribution = DynamicDistribution::new_t_uniform(10);

    let config = ConfigBuilder::default()
        .use_custom_parameters(my_params, None, None)
        .build();

    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    let clear_a = 673u32;
    let clear_b = 6u32;
    let a = FheUint32::try_encrypt(clear_a, &keys)?;
    let b = FheUint32::try_encrypt(clear_b, &keys)?;

    let c = &a >> &b;
    let decrypted: u32 = c.decrypt(&keys);
    assert_eq!(decrypted, clear_a >> clear_b);

    println!("decrypted = {decrypted} = {clear_a} >>  {clear_b}");

    Ok(())
}
