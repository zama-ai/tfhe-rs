# Operations and simple examples

## Booleans

Native homomorphic booleans support common boolean operations. 

The list of supported operations is:

| name                                                          | symbol | type   |
| ------------------------------------------------------------- | ------ | ------ |
| [BitAnd](https://doc.rust-lang.org/std/ops/trait.BitAnd.html) | `&`    | Binary |
| [BitOr](https://doc.rust-lang.org/std/ops/trait.BitOr.html)   | `\|`   | Binary |
| [BitXor](https://doc.rust-lang.org/std/ops/trait.BitXor.html) | `^`    | Binary |
| [Neg](https://doc.rust-lang.org/std/ops/trait.Neg.html)       | `!`    | Unary  |



## ShortInt

Native small homomorphic integer types (e.g., FheUint3 or FheUint4) allow to easily
compute various operations. In general, computing over encrypted data
is as easy as computing over clear data, since the same operation symbol is
used. For instance, the addition between two ciphertexts is done using the
symbol `+` between two FheUint. Similarly, many operations can be computed
between a clear value (i.e. a scalar) and a ciphertext.

In Rust native types, any operation is modular. In Rust, `u8`, computations are
done modulus 2^8. The similar idea is applied for FheUintX, where operations are
done modulus 2^X. For instance, in the type FheUint3, operations are done
modulus 8.

### Arithmetic operations

Small homomorphic integer types support all common arithmetic operations, meaning `+`, `-`, `x`, `/`, `mod`.

The division operation implements a subtlety: since data is encrypted, it might be possible to 
compute a division by 0. In this case, the division is tweaked so that dividing by 0 returns 0. 

The list of supported operations is:

| name                                                          | symbol | type   |
| ------------------------------------------------------------- | ------ | ------ |
| [Add](https://doc.rust-lang.org/std/ops/trait.Add.html)       | `+`    | Binary |
| [Sub](https://doc.rust-lang.org/std/ops/trait.Sub.html)       | `-`    | Binary |
| [Mul](https://doc.rust-lang.org/std/ops/trait.Mul.html)       | `*`    | Binary |
| [Div](https://doc.rust-lang.org/std/ops/trait.Div.html)       | `/`    | Binary |
| [Rem](https://doc.rust-lang.org/std/ops/trait.Rem.html)       | `%`    | Binary |
| [Neg](https://doc.rust-lang.org/std/ops/trait.Neg.html)       | `!`    | Unary  |


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

### Bitwise operations

Small homomorphic integer types support some bitwise operations. 

The list of supported operations is:

| name                                                          | symbol  | type   |
| ------------------------------------------------------------- | ------  | ------ |
| [BitAnd](https://doc.rust-lang.org/std/ops/trait.BitAnd.html) | `&`     | Binary |
| [BitOr](https://doc.rust-lang.org/std/ops/trait.BitOr.html)   | `\|`    | Binary |
| [BitXor](https://doc.rust-lang.org/std/ops/trait.BitXor.html) | `^`     | Binary |
| [Shr](https://doc.rust-lang.org/std/ops/trait.Shr.html)       | `>>`    | Binary |
| [Shl](https://doc.rust-lang.org/std/ops/trait.Shl.html)       | `<<`    | Binary |


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

### Comparisons

Small homomorphic integer types support comparison operations. 

However, due to some Rust limitations, this is not possible to overload the comparison symbols 
because of the inner  definition of the operations.
To be precise, Rust expects to have a boolean as output, 
whereas a ciphertext encrypted the result is returned when using homomorphic types. 

So instead of using symbols for the comparisons, you will need to use
the different methods. These methods follow the same naming that the 2 standard Rust trait

- [PartialOrd](https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html)
- [PartialEq](https://doc.rust-lang.org/std/cmp/trait.PartialEq.html)

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


### Univariate function evaluations

Shortints type also support the computation of univariate functions,
which deep down uses TFHE's _programmable bootstrapping_.

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

### Bivariate function evaluations

Using the shortint types offers the possibility to evaluate bivariate functions, i.e.,
functions that takes two ciphertexts as input. 

In what follows, a simple code example:

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


## Integer.

In the same vein, native homomorphic types supports modular operations. At the moment, integers 
are more limited than shortint, but operations will be added soon. 


### Arithmetic operations

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
    let config = ConfigBuilder::all_disabled().enable_default_uint8().build();
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

### Bitwise operations

Homomorphic integer types support some bitwise operations.

The list of supported operations is:

| name                                                          | symbol  | type   |
| ------------------------------------------------------------- | ------  | ------ |
| [BitAnd](https://doc.rust-lang.org/std/ops/trait.BitAnd.html) | `&`     | Binary |
| [BitOr](https://doc.rust-lang.org/std/ops/trait.BitOr.html)   | `\|`    | Binary |
| [BitXor](https://doc.rust-lang.org/std/ops/trait.BitXor.html) | `^`     | Binary |
| [Shr](https://doc.rust-lang.org/std/ops/trait.Shr.html)       | `>>`    | Binary |
| [Shl](https://doc.rust-lang.org/std/ops/trait.Shl.html)       | `<<`    | Binary |


A simple example on how to use these operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled().enable_default_uint8().build();
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

### Univariate function evaluations

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled().enable_default_uint8().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    let pow_5 = |value: u64| value.pow(2) as u64 % 256;

    let clear_a = 12u64;
    let a = FheUint8::try_encrypt(clear_a, &keys)?;

    let c = a.map(pow_5);
    let decrypted: u8 = c.decrypt(&keys);
    assert_eq!(decrypted, pow_5(clear_a) as u8);

    Ok(())
}
```

