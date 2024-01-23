# Debugging FHE Code

Since tfhe-rs 0.5, [trivial ciphertexts](./trivial_ciphertext.md) have another application.
They can be used to allow debugging via a debugger or print statements as well as speeding-up execution time
so that you won't have to spend minutes waiting for execution to progress.

This can greatly improve the pace at which one develops FHE applications.

{% hint style="warning" %}
Keep in mind that trivial ciphertexts are not secure at all, thus an application released/deployed in production
must never receive trivial ciphertext from a client.
{% endhint %}


## Example

To use this feature, simply call your circuits/functions with trivially encrypted values (made using `encrypt_trivial`)
instead of real encryptions (made using `encrypt`)

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

This example is going to print.
```text
a: Ok(1234), b: Ok(4567), c: Ok(89101112)
a * b = Ok(5635678)
```

If any input to `mul_all` is not a trivial ciphertexts, the computations would be done 100% in FHE, and the program
would output:

```text
a: Err(NotTrivialCiphertextError), b: Err(NotTrivialCiphertextError), c: Err(NotTrivialCiphertextError)
a * b = Err(NotTrivialCiphertextError)
```

Using trivial encryptions as input, the example runs in **980 ms** on a standard 12 cores laptop, using real encryptions
it would run in **7.5 seconds** on a 128-core machine.
