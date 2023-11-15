# The tree programmable bootstrapping

In `concrete-integer`, the user can evaluate any function on an encrypted ciphertext. To do so the user must first
create a `treepbs key`, choose a function to evaluate and give them as parameters to the `tree programmable bootstrapping`.

Two versions of the tree pbs are implemented: the `standard` version that computes a result according to every encrypted
bit (message and carry), and the `base` version that only takes into account the message bits of each block.

{% hint style="warning" %}

The `tree pbs` is quite slow, therefore its use is currently restricted to two and three blocks integer ciphertexts.

{% endhint %}

```rust
use concrete_integer::gen_keys;
use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
use concrete_integer::treepbs::TreepbsKey;

fn main() {
    let num_block = 2;
    // Generate the client key and the server key:
    let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, num_block);

    let msg: u64 = 27;
    let ct = cks.encrypt(msg);
    
    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus.0.pow(2 as u32) as u64;

    let treepbs_key = TreepbsKey::new(&cks);

    let f = |x: u64| x * x;

    // evaluate f
    let vec_res = treepbs_key.two_block_pbs(&sks, &ct, f);

    // decryption
    let res = cks.decrypt(&vec_res);

    let clear = f(msg) % modulus;
    assert_eq!(res, clear);
}
```

# The WOP programmable bootstrapping

