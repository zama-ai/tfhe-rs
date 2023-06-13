use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

pub type StringCiphertext = Vec<RadixCiphertext>;

pub fn encrypt_str(
    client_key: &RadixClientKey,
    s: &str,
) -> Result<StringCiphertext, Box<dyn std::error::Error>> {
    if !s.is_ascii() {
        return Err("content contains non-ascii characters".into());
    }
    Ok(s.as_bytes()
        .iter()
        .map(|byte| client_key.encrypt(*byte as u64))
        .collect())
}

pub fn gen_keys() -> (RadixClientKey, ServerKey) {
    let num_block = 4;
    gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block)
}
