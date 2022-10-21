# The programmable bootstrapping

In `concrete-shortint`, the user can evaluate any function on an encrypted ciphertext. To do so the user must first
create a look-up table through the `generate_accumulator` method and use its output together with the ciphertext 
as parameters for the `programmable bootstrapping`.

```rust
use concrete_shortint::gen_keys;
use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main() {
    // Generate the client key and the server key:
    let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

    let msg: u64 = 1;
    let ct = cks.encrypt(msg);
    let modulus = cks.parameters.message_modulus.0 as u64;

    // Generate the accumulator for the function f: x -> x^3 mod 2^2
    let acc = sks.generate_accumulator(|x| (x * x * x) % modulus);
    let ct_res = sks.programmable_bootstrap_keyswitch(&ct, &acc);

    let dec = cks.decrypt(&ct_res);
    // 3^3 mod 4 = 3
    assert_eq!(dec, (msg * msg * msg) % modulus);
}
```