# Comparison operations

This document details the comparison operations supported by **TFHE-rs**.

Homomorphic integers support comparison operations. However, due to Rust's limitations, you cannot overload comparison symbols. This is because Rust requires Boolean outputs from such operations, but homomorphic types return ciphertexts. Therefore, you should use the following methods, which conform to the naming conventions of Rust’s standard traits:

* [PartialOrd](https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html)
* [PartialEq](https://doc.rust-lang.org/std/cmp/trait.PartialEq.html)

Supported operations:

| name                                                                        | symbol | type   |
| --------------------------------------------------------------------------- | ------ | ------ |
| [Equal](https://doc.rust-lang.org/std/cmp/trait.PartialEq.html)             | `eq`   | Binary |
| [Not Equal](https://doc.rust-lang.org/std/cmp/trait.PartialEq.html)         | `ne`   | Binary |
| [Greater Than](https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html)     | `gt`   | Binary |
| [Greater or Equal](https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html) | `ge`   | Binary |
| [Lower](https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html)            | `lt`   | Binary |
| [Lower or Equal](https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html)   | `le`   | Binary |

The following example shows how to perform comparison operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    let clear_a: i8 = -121;
    let clear_b: i8 = 87;

    let a = FheInt8::try_encrypt(clear_a, &keys)?;
    let b = FheInt8::try_encrypt(clear_b, &keys)?;

    let greater = a.gt(&b);
    let greater_or_equal = a.ge(&b);
    let lower = a.lt(&b);
    let lower_or_equal = a.le(&b);
    let equal = a.eq(&b);

    let dec_gt = greater.decrypt(&keys);
    let dec_ge = greater_or_equal.decrypt(&keys);
    let dec_lt = lower.decrypt(&keys);
    let dec_le = lower_or_equal.decrypt(&keys);
    let dec_eq = equal.decrypt(&keys);

    assert_eq!(dec_gt, clear_a > clear_b);
    assert_eq!(dec_ge, clear_a >= clear_b);
    assert_eq!(dec_lt, clear_a < clear_b);
    assert_eq!(dec_le, clear_a <= clear_b);
    assert_eq!(dec_eq, clear_a == clear_b);

    Ok(())
}
```
