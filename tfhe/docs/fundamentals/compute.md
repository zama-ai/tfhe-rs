# Compute on encrypted data

This document describes how to perform computation on encrypted data.

With **TFHE-rs,** the program can be as straightforward as conventional Rust coding by using operator overloading.

The following example illustrates the complete process of encryption, computation using Rust’s built-in operators, and decryption:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

fn main() {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let clear_a = 35u8;
    let clear_b = 7u8;

    // Encryption
    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);

    // Take a reference to avoid moving data when doing the computation
    let a = &a;
    let b = &b;

    // Computation using Rust's built-in operators
    let add = a + b;
    let sub = a - b;
    let mul = a * b;
    let div = a / b;
    let rem = a % b;
    let and = a & b;
    let or = a | b;
    let xor = a ^ b;
    let neg = -a;
    let not = !a;
    let shl = a << b;
    let shr = a >> b;

    // Comparison operations need to use specific functions as the definition of the operators in
    // rust require to return a boolean which we cannot do in FHE
    let eq = a.eq(b);
    let ne = a.ne(b);
    let gt = a.gt(b);
    let lt = a.lt(b);

    // Decryption and verification of proper execution
    let decrypted_add: u8 = add.decrypt(&client_key);

    let clear_add = clear_a + clear_b;
    assert_eq!(decrypted_add, clear_add);

    let decrypted_sub: u8 = sub.decrypt(&client_key);

    let clear_sub = clear_a - clear_b;
    assert_eq!(decrypted_sub, clear_sub);

    let decrypted_mul: u8 = mul.decrypt(&client_key);

    let clear_mul = clear_a * clear_b;
    assert_eq!(decrypted_mul, clear_mul);

    let decrypted_div: u8 = div.decrypt(&client_key);

    let clear_div = clear_a / clear_b;
    assert_eq!(decrypted_div, clear_div);

    let decrypted_rem: u8 = rem.decrypt(&client_key);

    let clear_rem = clear_a % clear_b;
    assert_eq!(decrypted_rem, clear_rem);

    let decrypted_and: u8 = and.decrypt(&client_key);

    let clear_and = clear_a & clear_b;
    assert_eq!(decrypted_and, clear_and);

    let decrypted_or: u8 = or.decrypt(&client_key);

    let clear_or = clear_a | clear_b;
    assert_eq!(decrypted_or, clear_or);

    let decrypted_xor: u8 = xor.decrypt(&client_key);

    let clear_xor = clear_a ^ clear_b;
    assert_eq!(decrypted_xor, clear_xor);

    let decrypted_neg: u8 = neg.decrypt(&client_key);

    let clear_neg = clear_a.wrapping_neg();
    assert_eq!(decrypted_neg, clear_neg);

    let decrypted_not: u8 = not.decrypt(&client_key);

    let clear_not = !clear_a;
    assert_eq!(decrypted_not, clear_not);

    let decrypted_shl: u8 = shl.decrypt(&client_key);

    let clear_shl = clear_a << clear_b;
    assert_eq!(decrypted_shl, clear_shl);

    let decrypted_shr: u8 = shr.decrypt(&client_key);

    let clear_shr = clear_a >> clear_b;
    assert_eq!(decrypted_shr, clear_shr);

    let decrypted_eq = eq.decrypt(&client_key);

    let eq = clear_a == clear_b;
    assert_eq!(decrypted_eq, eq);

    let decrypted_ne = ne.decrypt(&client_key);

    let ne = clear_a != clear_b;
    assert_eq!(decrypted_ne, ne);

    let decrypted_gt = gt.decrypt(&client_key);

    let gt = clear_a > clear_b;
    assert_eq!(decrypted_gt, gt);

    let decrypted_lt = lt.decrypt(&client_key);

    let lt = clear_a < clear_b;
    assert_eq!(decrypted_lt, lt);
}
```
