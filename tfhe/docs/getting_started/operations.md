# Types & Operations

This document explains the encryption types and operations supported by **TFHE-rs.**

## Types

**TFHE-rs** supports two main types of encrypted data:

* `FheUint`: homomorphic equivalent of Rust unsigned integers `u8, u16, ...`
* `FheInt`: homomorphic equivalent of Rust signed integers `i8, i16, ...`

### Integer

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

## Operations

**TFHE-rs** supports various operations on encrypted integers (`Enc`) of any size between 1 and 256 bits. These operations can also work between encrypted integers and clear integers (`Int`).

| name                  | symbol      | `Enc`/`Enc`          | `Enc`/ `Int`               |
| --------------------- |-------------| -------------------- | -------------------------- |
| Neg                   | `-`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Add                   | `+`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Sub                   | `-`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Mul                   | `*`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Div                   | `/`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Rem                   | `%`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Not                   | `!`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| BitAnd                | `&`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| BitOr                 | `\|`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| BitXor                | `^`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Shr                   | `>>`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Shl                   | `<<`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Min                   | `min`       | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Max                   | `max`       | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Greater than          | `gt`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Greater or equal than | `ge`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Less than             | `lt`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Less or equal than    | `le`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Equal                 | `eq`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Cast (into dest type) | `cast_into` | :heavy\_check\_mark: | :heavy\_multiplication\_x: |
| Cast (from src type)  | `cast_from` | :heavy\_check\_mark: | :heavy\_multiplication\_x: |
| Ternary operator      | `select`    | :heavy\_check\_mark: | :heavy\_multiplication\_x: |

### Arithmetic operations

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
  * Example: for FheUint8 (modulus = $$2^8=256$$), dividing by zero returns an ecryption of 255.
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

### Bitwise operations

Homomorphic integer types support the following bitwise operations:

| name                                                                                  | symbol         | type   |
| ------------------------------------------------------------------------------------- | -------------- | ------ |
| [Not](https://doc.rust-lang.org/std/ops/trait.Not.html)                               | `!`            | Unary  |
| [BitAnd](https://doc.rust-lang.org/std/ops/trait.BitAnd.html)                         | `&`            | Binary |
| [BitOr](https://doc.rust-lang.org/std/ops/trait.BitOr.html)                           | `\|`           | Binary |
| [BitXor](https://doc.rust-lang.org/std/ops/trait.BitXor.html)                         | `^`            | Binary |
| [Shr](https://doc.rust-lang.org/std/ops/trait.Shr.html)                               | `>>`           | Binary |
| [Shl](https://doc.rust-lang.org/std/ops/trait.Shl.html)                               | `<<`           | Binary |
| [Rotate Right](https://doc.rust-lang.org/std/primitive.u32.html#method.rotate\_right) | `rotate_right` | Binary |
| [Rotate Left](https://doc.rust-lang.org/std/primitive.u32.html#method.rotate\_left)   | `rotate_left`  | Binary |

The following example shows how to perform bitwise operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    let clear_a = 164;
    let clear_b = 212;

    let mut a = FheUint8::try_encrypt(clear_a, &keys)?;
    let mut b = FheUint8::try_encrypt(clear_b, &keys)?;

    a ^= &b;
    b ^= &a;
    a ^= &b;

    let dec_a: u8 = a.decrypt(&keys);
    let dec_b: u8 = b.decrypt(&keys);

    // We homomorphically swapped values using bitwise operations
    assert_eq!(dec_a, clear_b);
    assert_eq!(dec_b, clear_a);

    Ok(())
}
```

### Comparison operations

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

### Min/Max operations

Homomorphic integers support the min/max operations:

| name | symbol | type   |
| ---- | ------ | ------ |
| Min  | `min`  | Binary |
| Max  | `max`  | Binary |

The following example shows how to perform min/max operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    let clear_a:u8 = 164;
    let clear_b:u8 = 212;

    let a = FheUint8::try_encrypt(clear_a, &keys)?;
    let b = FheUint8::try_encrypt(clear_b, &keys)?;

    let min = a.min(&b);
    let max = a.max(&b);

    let dec_min : u8 = min.decrypt(&keys);
    let dec_max : u8 = max.decrypt(&keys);

    assert_eq!(dec_min, u8::min(clear_a, clear_b));
    assert_eq!(dec_max, u8::max(clear_a, clear_b));

    Ok(())
}
```

### Ternary conditional operations

The ternary conditional operator execute conditional instructions in the form `if cond { choice_if_true } else { choice_if_false }`.

| name             | symbol   | type    |
| ---------------- |----------| ------- |
| Ternary operator | `select` | Ternary |

The syntax is `encrypted_condition.select(encrypted_choice_if_true, encrypted_choice_if_false)`. The valid `encrypted_condition` must be an encryption of 0 or 1.

The following example shows how to perform ternary conditional operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic configuration to use homomorphic integers
    let config = ConfigBuilder::default().build();

    // Key generation
    let (client_key, server_keys) = generate_keys(config);
    
    let clear_a = 32i32;
    let clear_b = -45i32;
    
    // Encrypting the input data using the (private) client_key
    // FheInt32: Encrypted equivalent to i32
    let encrypted_a = FheInt32::try_encrypt(clear_a, &client_key)?;
    let encrypted_b = FheInt32::try_encrypt(clear_b, &client_key)?;
    
    // On the server side:
    set_server_key(server_keys);
    
    // Clear equivalent computations: 32 > -45
    let encrypted_comp = &encrypted_a.gt(&encrypted_b);
    let clear_res = encrypted_comp.decrypt(&client_key);
    assert_eq!(clear_res, clear_a > clear_b);
    
    // `encrypted_comp` is a FheBool, thus it encrypts a boolean value.
    // This acts as a condition on which the
    // `select` function can be applied on.
    // Clear equivalent computations:
    // if 32 > -45 {result = 32} else {result = -45}
    let encrypted_res = &encrypted_comp.select(&encrypted_a, &encrypted_b);
    
    let clear_res: i32 = encrypted_res.decrypt(&client_key);
    assert_eq!(clear_res, clear_a);
    
    Ok(())
}
```

### Casting operations

You can cast between integer types using either the `cast_from` associated function or the `cast_into` method.

The following example shows how to perform casting operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt16, FheUint8, FheUint32, FheUint16};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    // Casting requires server_key to set
    // (encryptions/decryptions do not need server_key to be set)
    set_server_key(server_key);

    {
        let clear = 12_837u16;
        let a = FheUint16::encrypt(clear, &client_key);

        // Downcasting
        let a: FheUint8 = a.cast_into();
        let da: u8 = a.decrypt(&client_key);
        assert_eq!(da, clear as u8);

        // Upcasting
        let a: FheUint32 = a.cast_into();
        let da: u32 = a.decrypt(&client_key);
        assert_eq!(da, (clear as u8) as u32);
    }

    {
        let clear = 12_837u16;
        let a = FheUint16::encrypt(clear, &client_key);

        // Upcasting
        let a = FheUint32::cast_from(a);
        let da: u32 = a.decrypt(&client_key);
        assert_eq!(da, clear as u32);

        // Downcasting
        let a = FheUint8::cast_from(a);
        let da: u8 = a.decrypt(&client_key);
        assert_eq!(da, (clear as u32) as u8);
    }

    {
        let clear = 12_837i16;
        let a = FheInt16::encrypt(clear, &client_key);

        // Casting from FheInt16 to FheUint16
        let a = FheUint16::cast_from(a);
        let da: u16 = a.decrypt(&client_key);
        assert_eq!(da, clear as u16);
    }

    Ok(())
}
```

### Boolean Operations

Native homomorphic Booleans support the following common Boolean operations:

| name                                                          | symbol | type   |
| ------------------------------------------------------------- | ------ | ------ |
| [BitAnd](https://doc.rust-lang.org/std/ops/trait.BitAnd.html) | `&`    | Binary |
| [BitOr](https://doc.rust-lang.org/std/ops/trait.BitOr.html)   | `\|`   | Binary |
| [BitXor](https://doc.rust-lang.org/std/ops/trait.BitXor.html) | `^`    | Binary |
| [Not](https://doc.rust-lang.org/std/ops/trait.Not.html)       | `!`    | Unary  |
