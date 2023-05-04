# Operations

The structure and operations related to all types (ì.e., Booleans, shortint and integer) are described in this section.

## Booleans

Native homomorphic Booleans support common Boolean operations.

The list of supported operations is:

| name                                                          | symbol | type   |
| ------------------------------------------------------------- | ------ | ------ |
| [BitAnd](https://doc.rust-lang.org/std/ops/trait.BitAnd.html) | `&`    | Binary |
| [BitOr](https://doc.rust-lang.org/std/ops/trait.BitOr.html)   | `\|`   | Binary |
| [BitXor](https://doc.rust-lang.org/std/ops/trait.BitXor.html) | `^`    | Binary |
| [Neg](https://doc.rust-lang.org/std/ops/trait.Neg.html)       | `!`    | Unary  |

## ShortInt

Native small homomorphic integer types (e.g., FheUint3 or FheUint4) easily compute various operations. In general, computing over encrypted data is as easy as computing over clear data, since the same operation symbol is used. The addition between two ciphertexts is done using the symbol `+` between two FheUint. Many operations can be computed between a clear value (i.e. a scalar) and a ciphertext.

In Rust native types, any operation is modular. In Rust, `u8`, computations are done modulus 2^8. The similar idea is applied for FheUintX, where operations are done modulus 2^X. In the type FheUint3, operations are done modulo 8.

### Arithmetic operations.

Small homomorphic integer types support all common arithmetic operations, meaning `+`, `-`, `x`, `/`, `mod`.

The division operation implements a subtlety: since data is encrypted, it might be possible to compute a division by 0. In this case, the division is tweaked so that dividing by 0 returns 0.

The list of supported operations is:

| name                                                    | symbol | type   |
| ------------------------------------------------------- | ------ | ------ |
| [Add](https://doc.rust-lang.org/std/ops/trait.Add.html) | `+`    | Binary |
| [Sub](https://doc.rust-lang.org/std/ops/trait.Sub.html) | `-`    | Binary |
| [Mul](https://doc.rust-lang.org/std/ops/trait.Mul.html) | `*`    | Binary |
| [Div](https://doc.rust-lang.org/std/ops/trait.Div.html) | `/`    | Binary |
| [Rem](https://doc.rust-lang.org/std/ops/trait.Rem.html) | `%`    | Binary |
| [Neg](https://doc.rust-lang.org/std/ops/trait.Neg.html) | `!`    | Unary  |

A simple example on how to use these operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint3};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled().enable_default_uint3().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);
    
    let clear_a = 7;
    let clear_b = 3;
    let clear_c = 2;

    let mut a = FheUint3::try_encrypt(clear_a, &keys)?;
    let mut b = FheUint3::try_encrypt(clear_b, &keys)?;
    let mut c = FheUint3::try_encrypt(clear_c, &keys)?;


    a = a * &b;  // Clear equivalent computations: 7 * 3 mod 8 = 5
    b = &b + &c; // Clear equivalent computations: 3 + 2 mod 8 = 5
    b = b - 5;   // Clear equivalent computations: 5 - 5 mod 8 = 0
    
    let dec_a = a.decrypt(&keys);
    let dec_b = b.decrypt(&keys);
    
    // We homomorphically swapped values using bitwise operations
    assert_eq!(dec_a, (clear_a * clear_b) % 8);
    assert_eq!(dec_b, ((clear_b + clear_c) - 5) % 8);

    Ok(())
}
```

### Bitwise operations.

Small homomorphic integer types support some bitwise operations.

The list of supported operations is:

| name                                                          | symbol | type   |
| ------------------------------------------------------------- | ------ | ------ |
| [BitAnd](https://doc.rust-lang.org/std/ops/trait.BitAnd.html) | `&`    | Binary |
| [BitOr](https://doc.rust-lang.org/std/ops/trait.BitOr.html)   | `\|`   | Binary |
| [BitXor](https://doc.rust-lang.org/std/ops/trait.BitXor.html) | `^`    | Binary |
| [Shr](https://doc.rust-lang.org/std/ops/trait.Shr.html)       | `>>`   | Binary |
| [Shl](https://doc.rust-lang.org/std/ops/trait.Shl.html)       | `<<`   | Binary |

A simple example on how to use these operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint3};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled().enable_default_uint3().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);
    
    let clear_a = 7;
    let clear_b = 3;
    
    let mut a = FheUint3::try_encrypt(clear_a, &keys)?;
    let mut b = FheUint3::try_encrypt(clear_b, &keys)?;
    
    a = a ^ &b;
    b = b ^ &a;
    a = a ^ &b;
    
    let dec_a = a.decrypt(&keys);
    let dec_b = b.decrypt(&keys);
    
    // We homomorphically swapped values using bitwise operations
    assert_eq!(dec_a, clear_b);
    assert_eq!(dec_b, clear_a);

    Ok(())
}
```

### Comparisons.

Small homomorphic integer types support comparison operations.

Due to some Rust limitations, it is not possible to overload the comparison symbols because of the inner definition of the operations. Rust expects to have a Boolean as an output, whereas a ciphertext encrypted result is returned when using homomorphic types.

You will need to use the different methods instead of using symbols for the comparisons. These methods follow the same naming conventions as the two standard Rust traits:

* [PartialOrd](https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html)
* [PartialEq](https://doc.rust-lang.org/std/cmp/trait.PartialEq.html)

A simple example on how to use these operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint3};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled().enable_default_uint3().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);
    
    let clear_a = 7;
    let clear_b = 3;
    
    let mut a = FheUint3::try_encrypt(clear_a, &keys)?;
    let mut b = FheUint3::try_encrypt(clear_b, &keys)?;
    
    assert_eq!(a.gt(&b).decrypt(&keys) != 0, true);
    assert_eq!(b.le(&a).decrypt(&keys) != 0, true);

    Ok(())
}
```

### Univariate function evaluations.

The shortint type also supports the computation of univariate functions, which deep down uses TFHE's _programmable bootstrapping_.

A simple example on how to use these operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint4};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled().enable_default_uint4().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    let pow_5 = |value: u64| {
        value.pow(5) % FheUint4::MODULUS as u64
    };

    let clear_a = 12;
    let a = FheUint4::try_encrypt(12, &keys)?;

    let c = a.map(pow_5);
    let decrypted = c.decrypt(&keys);
    assert_eq!(decrypted, pow_5(clear_a) as u8);

    Ok(())
}
```

### Bivariate function evaluations.

Using the shortint type allows you to evaluate bivariate functions (i.e., functions that takes two ciphertexts as input).

A simple code example:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint2};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled().enable_default_uint2().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);
    
    let clear_a = 1;
    let clear_b = 3;
    let a = FheUint2::try_encrypt(clear_a, &keys)?;
    let b = FheUint2::try_encrypt(clear_b, &keys)?;

    
    let c = a.bivariate_function(&b, std::cmp::max);
    let decrypted = c.decrypt(&keys);
    assert_eq!(decrypted, std::cmp::max(clear_a, clear_b) as u8);

    Ok(())
}
```

## Integer

In TFHE-rs, integers are used to encrypt any messages larger than 4 bits. All supported operations are listed below.

### Arithmetic operations.

Homomorphic integer types support arithmetic operations.

The list of supported operations is:

| name                                                    | symbol | type   |
| ------------------------------------------------------- | ------ | ------ |
| [Add](https://doc.rust-lang.org/std/ops/trait.Add.html) | `+`    | Binary |
| [Sub](https://doc.rust-lang.org/std/ops/trait.Sub.html) | `-`    | Binary |
| [Mul](https://doc.rust-lang.org/std/ops/trait.Mul.html) | `*`    | Binary |
| [Neg](https://doc.rust-lang.org/std/ops/trait.Neg.html) | `!`    | Unary  |

A simple example on how to use these operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled().enable_default_integers().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);
    
    let clear_a = 15_u64;
    let clear_b = 27_u64;
    let clear_c = 43_u64;

    let mut a = FheUint8::try_encrypt(clear_a, &keys)?;
    let mut b = FheUint8::try_encrypt(clear_b, &keys)?;
    let mut c = FheUint8::try_encrypt(clear_c, &keys)?;


    a = a * &b;  // Clear equivalent computations: 15 * 27 mod 256 = 149
    b = &b + &c; // Clear equivalent computations: 27 + 43 mod 256 = 70
    b = b - 76u8;   // Clear equivalent computations: 70 - 76 mod 256 = 250
    
    let dec_a: u8 = a.decrypt(&keys);
    let dec_b: u8 = b.decrypt(&keys);
    
    assert_eq!(dec_a, ((clear_a * clear_b) % 256_u64) as u8);
    assert_eq!(dec_b, (((clear_b  + clear_c).wrapping_sub(76_u64)) % 256_u64) as u8);

    Ok(())
}
```

### Bitwise operations.

Homomorphic integer types support some bitwise operations.

The list of supported operations is:

| name                                                          | symbol | type   |
| ------------------------------------------------------------- | ------ | ------ |
| [BitAnd](https://doc.rust-lang.org/std/ops/trait.BitAnd.html) | `&`    | Binary |
| [BitOr](https://doc.rust-lang.org/std/ops/trait.BitOr.html)   | `\|`   | Binary |
| [BitXor](https://doc.rust-lang.org/std/ops/trait.BitXor.html) | `^`    | Binary |
| [Shr](https://doc.rust-lang.org/std/ops/trait.Shr.html)       | `>>`   | Binary |
| [Shl](https://doc.rust-lang.org/std/ops/trait.Shl.html)       | `<<`   | Binary |

A simple example on how to use these operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled().enable_default_integers().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);
    
    let clear_a = 164;
    let clear_b = 212;

    let mut a = FheUint8::try_encrypt(clear_a, &keys)?;
    let mut b = FheUint8::try_encrypt(clear_b, &keys)?;

    a = a ^ &b;
    b = b ^ &a;
    a = a ^ &b;

    let dec_a: u8 = a.decrypt(&keys);
    let dec_b: u8 = b.decrypt(&keys);

    // We homomorphically swapped values using bitwise operations
    assert_eq!(dec_a, clear_b);
    assert_eq!(dec_b, clear_a);

    Ok(())
}
```

### Comparisons.

Homomorphic integers support comparison operations. Since Rust does not allow the overloading of these operations, a simple function has been associated to each one.

The list of supported operations is:

| name                  | symbol | type   |
| --------------------- | ------ | ------ |
| Greater than          | `gt`   | Binary |
| Greater or equal than | `ge`   | Binary |
| Lower than            | `lt`   | Binary |
| Lower or equal than   | `le`   | Binary |
| Equal                 | `eq`   | Binary |

A simple example on how to use these operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled().enable_default_integers().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    let clear_a:u8 = 164;
    let clear_b:u8 = 212;

    let mut a = FheUint8::try_encrypt(clear_a, &keys)?;
    let mut b = FheUint8::try_encrypt(clear_b, &keys)?;

    let greater = a.gt(&b);
    let greater_or_equal = a.ge(&b);
    let lower = a.lt(&b);
    let lower_or_equal = a.le(&b);
    let equal = a.eq(&b);

    let dec_gt : u8 = greater.decrypt(&keys);
    let dec_ge : u8 = greater_or_equal.decrypt(&keys);
    let dec_lt : u8 = lower.decrypt(&keys);
    let dec_le : u8 = lower_or_equal.decrypt(&keys);
    let dec_eq : u8 = equal.decrypt(&keys);

    // We homomorphically swapped values using bitwise operations
    assert_eq!(dec_gt, (clear_a > clear_b ) as u8);
    assert_eq!(dec_ge, (clear_a >= clear_b) as u8);
    assert_eq!(dec_lt, (clear_a < clear_b ) as u8);
    assert_eq!(dec_le, (clear_a <= clear_b) as u8);
    assert_eq!(dec_eq, (clear_a == clear_b) as u8);

    Ok(())
}
```

### Min/Max.

Homomorphic integers support the min/max operations.

| name | symbol | type   |
| ---- | ------ | ------ |
| Min  | `min`  | Binary |
| Max  | `max`  | Binary |

A simple example on how to use these operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled().enable_default_integers().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    let clear_a:u8 = 164;
    let clear_b:u8 = 212;

    let mut a = FheUint8::try_encrypt(clear_a, &keys)?;
    let mut b = FheUint8::try_encrypt(clear_b, &keys)?;

    let min = a.min(&b);
    let max = a.max(&b);

    let dec_min : u8 = min.decrypt(&keys);
    let dec_max : u8 = max.decrypt(&keys);

    // We homomorphically swapped values using bitwise operations
    assert_eq!(dec_min, u8::min(clear_a, clear_b));
    assert_eq!(dec_max, u8::max(clear_a, clear_b));

    Ok(())
}
```
