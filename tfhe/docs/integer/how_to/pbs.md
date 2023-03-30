# The tree programmable bootstrapping

In `integer`, the user can evaluate any function on an encrypted ciphertext. To do so the user must first
create a `treepbs key`, choose a function to evaluate and give them as parameters to the `tree programmable bootstrapping`.

Two versions of the tree pbs are implemented: the `standard` version that computes a result according to every encrypted
bit (message and carry), and the `base` version that only takes into account the message bits of each block.

{% hint style="warning" %}

The `tree pbs` is quite slow, therefore its use is currently restricted to two and three blocks integer ciphertexts.

{% endhint %}

```rust
use tfhe::integer::gen_keys_radix;
use tfhe::integer::wopbs::WopbsKey;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
use tfhe::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2;

fn main() {
    let num_block = 2;
    // Generate the client key and the server key:
    let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_block);

    let msg: u64 = 27;
    let ct = cks.encrypt(msg);
    
    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus.0.pow(num_block as u32) as u64;

    let wopbs_key = WopbsKey::new_wopbs_key(&cks.as_ref(), &sks, &WOPBS_PARAM_MESSAGE_2_CARRY_2);

    let f = |x: u64| x * x;

    // evaluate f
    let ct = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct);
    let lut = wopbs_key.generate_lut_radix(&ct, f);
    let ct_res = wopbs_key.wopbs(&ct, &lut);
    let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);

    // decryption
    let res: u64 = cks.decrypt(&ct_res);

    let clear = f(msg) % modulus;
    assert_eq!(res, clear);
}
```

# The WOP programmable bootstrapping

