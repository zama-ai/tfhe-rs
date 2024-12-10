# Debugging

This document explains a feature to facilitate debugging.

Starting from **TFHE-rs 0.5**, [trivial ciphertexts](../guides/trivial\_ciphertext.md) introduce a new feature to facilitate debugging. This feature supports a debugger, print statements, and faster execution, significantly reducing waiting time and enhancing the development pace of FHE applications.

{% hint style="warning" %}
Trivial ciphertexts are not secure. An application released/deployed in production must never receive trivial ciphertext from a client.
{% endhint %}

To use this feature, simply call your circuits/functions with trivially encrypted values that are created using `encrypt_trivial`(instead of real encryptions that are created using `encrypt`):

```rust
use tfhe::prelude::*;
use tfhe::{set_server_key, generate_keys, ConfigBuilder, FheUint128};


fn mul_all(a: &FheUint128, b: &FheUint128, c: &FheUint128) -> FheUint128 {
    // Use the debug format ('{:?}'), if you don't want to unwrap()
    // and panic if the value is not a trivial.
    println!(
        "a: {:?}, b: {:?}, c: {:?}", 
        a.try_decrypt_trivial::<u128>(),
        b.try_decrypt_trivial::<u128>(),
        c.try_decrypt_trivial::<u128>(),
    );
    let tmp = a * b;
    
    println!("a * b = {:?}", tmp.try_decrypt_trivial::<u128>());

    tmp * c
}


fn main() {
    let (cks, sks) = generate_keys(ConfigBuilder::default().build());
    
    set_server_key(sks);
    
    let a = FheUint128::encrypt_trivial(1234u128);
    let b = FheUint128::encrypt_trivial(4567u128);
    let c = FheUint128::encrypt_trivial(89101112u128);
    
    // since all inputs are trivially encrypted, this is going to be
    // much faster
    let result = mul_all(&a, &b, &c);
}
```

This example is going to print:

```console
a: Ok(1234), b: Ok(4567), c: Ok(89101112)
a * b = Ok(5635678)
```

If any input to `mul_all` is not a trivial ciphertexts, the computations will be done 100% in FHE, and the program will output:

```console
a: Err(NotTrivialCiphertextError), b: Err(NotTrivialCiphertextError), c: Err(NotTrivialCiphertextError)
a * b = Err(NotTrivialCiphertextError)
```

Using trivial encryptions as input, the example runs in **980 ms** on a standard 12-core laptop, compared to **7.5 seconds** on a 128-core machine using real encryptions.
