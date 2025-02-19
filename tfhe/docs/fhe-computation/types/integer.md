# Integer

This document describes the main integer types of encrypted data in **TFHE-rs** and explains how to specify bit sizes for encryption.

**TFHE-rs** supports two main types of encrypted data:

* `FheUint`: homomorphic equivalent of Rust unsigned integers `u8, u16, ...`
* `FheInt`: homomorphic equivalent of Rust signed integers `i8, i16, ...`

**TFHE-rs** uses integers to encrypt all messages which are larger than 4 bits.

Similar to Rust integers, you need to specify the bit size of data when declaring a variable:

```Rust
    // let clear_a: u64 = 7;
    let mut a = FheUint64::try_encrypt(clear_a, &keys)?;

    // let clear_b: i8 = 3;
    let mut b = FheInt8::try_encrypt(clear_b, &keys)?;

    // let clear_c: u128 = 2;
    let mut c = FheUint128::try_encrypt(clear_c, &keys)?;
```
