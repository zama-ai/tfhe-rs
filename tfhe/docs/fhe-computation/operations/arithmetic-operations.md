# Arithmetic operations

This document details the arithmetic operations supported by **TFHE-rs**.

Homomorphic integer types (`FheUint` and `FheInt`) support the following arithmetic operations:

| name                                                      | symbol | type   |
| --------------------------------------------------------- | ------ | ------ |
| [Neg](https://doc.rust-lang.org/std/ops/trait.Neg.html)   | `-`    | Unary  |
| [Add](https://doc.rust-lang.org/std/ops/trait.Add.html)   | `+`    | Binary |
| [Sub](https://doc.rust-lang.org/std/ops/trait.Sub.html)   | `-`    | Binary |
| [Mul](https://doc.rust-lang.org/std/ops/trait.Mul.html)   | `*`    | Binary |
| [Div](https://doc.rust-lang.org/std/ops/trait.Div.html)\* | `/`    | Binary |
| [Rem](https://doc.rust-lang.org/std/ops/trait.Rem.html)\* | `%`    | Binary |

Specifications for operations with zero:

* **Division by zero**: returns modulus - 1.
  * Example: for FheUint8 (modulus = $$2^8=256$$), dividing by zero returns an encryption of 255.
* **Remainder operator**: returns the first input unchanged.
  * Example: if `ct1 = FheUint8(63)` and `ct2 = FheUint8(0)`, then ct1 % ct2 returns FheUint8(63).

The following example shows how to perform arithmetic operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt8, FheUint8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    let clear_a = 15_u64;
    let clear_b = 27_u64;
    let clear_c = 43_u64;
    let clear_d = -87_i64;

    let mut a = FheUint8::try_encrypt(clear_a, &keys)?;
    let mut b = FheUint8::try_encrypt(clear_b, &keys)?;
    let c = FheUint8::try_encrypt(clear_c, &keys)?;
    let mut d = FheInt8::try_encrypt(clear_d, &keys)?;


    a *= &b;     // Clear equivalent computations: 15 * 27 mod 256 = 149
    b = &b + &c;    // Clear equivalent computations: 27 + 43 mod 256 = 70
    b -= 76u8;   // Clear equivalent computations: 70 - 76 mod 256 = 250
    d -= 13i8;   // Clear equivalent computations: -87 - 13 = 100 in [-128, 128[

    let dec_a: u8 = a.decrypt(&keys);
    let dec_b: u8 = b.decrypt(&keys);
    let dec_d: i8 = d.decrypt(&keys);

    assert_eq!(dec_a, ((clear_a * clear_b) % 256_u64) as u8);
    assert_eq!(dec_b, (((clear_b  + clear_c).wrapping_sub(76_u64)) % 256_u64) as u8);
    assert_eq!(dec_d, (clear_d - 13) as i8);

    Ok(())
}
```
