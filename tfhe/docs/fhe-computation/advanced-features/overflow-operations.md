# Overflow detection

This document explains how **TFHE-rs** implements specific operations to detect overflows in computations.

The mechanism of detecting overflow consists in returning an encrypted flag with a specific ciphertext that reflects the state of the computation. When an overflow occurs, this flag is set to true. Since the server is not able to evaluate this encrypted value, the client has to check the flag value when decrypting to determine if an overflow has happened.

These operations might be slower than their non-overflow-detecting equivalent, so they are not enabled by default. To use them, you must explicitly call specific operators. At the moment, only additions, subtractions, and multiplications are supported. We plan to add more operations in future releases.

Here's the list of operations supported along with their symbol:

| name                                                    | symbol         | type   |
| ------------------------------------------------------- | -------------- | ------ |
| [Add](https://doc.rust-lang.org/std/ops/trait.Add.html) | `overflow_add` | Binary |
| [Sub](https://doc.rust-lang.org/std/ops/trait.Sub.html) | `overflow_sub` | Binary |
| [Mul](https://doc.rust-lang.org/std/ops/trait.Mul.html) | `overflow_mul` | Binary |

The usage of these operations is similar to the standard ones. The key difference is in the decryption process, as shown in following example:

```rust
// Adds two [FheUint] and returns a boolean indicating overflow.
//
// * The operation is modular, i.e on overflow the result wraps around.
// * On overflow the [FheBool] is true, otherwise false

use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};

let (client_key, server_key) = generate_keys(ConfigBuilder::default());
set_server_key(server_key);

let a = FheUint16::encrypt(u16::MAX, &client_key);
let b = FheUint16::encrypt(1u16, &client_key);

let (result, overflowed) = (&a).overflowing_add(&b);
let result: u16 = result.decrypt(&client_key);
assert_eq!(result, u16::MAX.wrapping_add(1u16));
assert_eq!(
    overflowed.decrypt(&client_key),
    u16::MAX.overflowing_add(1u16).1
);
assert!(overflowed.decrypt(&client_key));
```
