# Overflow Detection

TFHE-rs includes a list of specific operations to detect overflows. The overall idea is to have a specific ciphertext encrypting a flag reflecting the status of the computations. When an overflow occurs, this flag is set to true. Since the server is not able to evaluate this value (since it is encrypted), the client has to check the flag value when decrypting to determine if an overflow has happened. These operations might be slower than their equivalent which do not detect overflow, so they are not enabled by default (see the table below). In order to use them, specific operators must be called. 
At the moment, only  additions, subtractions, multiplications are supported. Missing operations will be added soon.

The list of operations along with their symbol is:
| name                                                     | symbol         | type   |
|----------------------------------------------------------|----------------|--------|
| [Add](https://doc.rust-lang.org/std/ops/trait.Add.html)  | `overflow_add` | Binary |
| [Sub](https://doc.rust-lang.org/std/ops/trait.Sub.html)  | `overflow_sub` | Binary |
| [Mul](https://doc.rust-lang.org/std/ops/trait.Mul.html)  | `overflow_mul` | Binary |

These operations are then used exactly in the same way than the usual ones. The only difference lies into the decryption, as shown in following example:

```rust
/// Adds two [FheUint] and returns a boolean indicating overflow.
///
/// * The operation is modular, i.e on overflow the result wraps around.
/// * On overflow the [FheBool] is true, otherwise false

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
assert_eq!(overflowed.decrypt(&client_key), true);
```

The current benchmarks are given in the following tables (the first one for unsigned homomorphic integers and the second one for the signed integers):

| Operation\Size           | FheUint8  | FheUint16 | FheUint32 | FheUint64 | FheUint128 | FheUint256 |
|--------------------------|-----------|-----------|-----------|-----------|------------|------------|
| unsigned_overflowing_add | 63.67 ms  | 84.11 ms  | 107.95 ms | 120.8 ms  | 147.38 ms  | 191.28 ms  |
| unsigned_overflowing_sub | 68.89 ms  | 81.83 ms  | 107.63 ms | 120.38 ms | 150.21 ms  | 190.39 ms  |
| unsigned_overflowing_mul | 140.76 ms | 191.85 ms | 272.65 ms | 510.61 ms | 1.34 s     | 4.51 s     |


| Operation\Size         | FheInt8   | FheInt16  | FheInt32  | FheInt64  | FheInt128 | FheInt256 |
|------------------------|-----------|-----------|-----------|-----------|-----------|-----------|
| signed_overflowing_add | 76.54 ms  | 84.78 ms  | 104.23 ms | 134.38 ms | 162.99 ms | 202.56 ms |
| signed_overflowing_sub | 82.46 ms  | 86.92 ms  | 104.41 ms | 132.21 ms | 168.06 ms | 201.17 ms |
| signed_overflowing_mul | 277.91 ms | 365.67 ms | 571.22 ms | 1.21 s    | 3.57 s    | 12.84 s   |
