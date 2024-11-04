# Homomorphic case changing on Ascii string

This tutorial demonstrates how to build a data type that represents an ASCII string in Fully Homomorphic Encryption (FHE) by implementing to\_lower and to\_upper functions.

An ASCII character is stored in 7 bits. To store an encrypted ASCII, we use the `FheUint8`:

* The uppercase letters are in the range \[65, 90]
* The lowercase letters are in the range \[97, 122]

The relationship between uppercase and lowercase letters is defined as follows:

* `lower_case` = `upper_case` + `UP_LOW_DISTANCE`
* `upper_case` = `lower_case` - `UP_LOW_DISTANCE`

Where `UP_LOW_DISTANCE = 32`

## Types and methods

This type stores the encrypted characters as a `Vec<FheUint8>` to implement case conversion functions.

To use the `FheUint8` type, enable the `integer` feature:

```toml
# Cargo.toml

[dependencies]
# Default configuration for x86 Unix machines:
tfhe = { version = "0.10.0", features = ["integer", "x86_64-unix"] }
```

Refer to the [installation guide](../getting\_started/installation.md) for other configurations.

The `FheAsciiString::encrypt` function performs data validation to ensure the input string contains only ASCII characters.

In FHE operations, direct branching on encrypted values is not possible. However, you can evaluate a boolean condition to obtain the desired outcome. Here is an example to check and convert the 'char' to a lowercase without using a branch:

```rust
#![allow(dead_code)]

const UP_LOW_DISTANCE: u8 = 32;

fn to_lower(c: u8) -> u8 {
    if c > 64 && c < 91 {
        c + UP_LOW_DISTANCE
    } else {
        c
    }
}
```

You can remove the branch this way:

```rust
#![allow(dead_code)]

const UP_LOW_DISTANCE: u8 = 32;

fn to_lower(c: u8) -> u8 {
    c + ((c > 64) as u8 & (c < 91) as u8) * UP_LOW_DISTANCE
}
```

This method can adapt to operations on homomorphic integers:

```rust
#![allow(dead_code)]

use tfhe::prelude::*;
use tfhe::FheUint8;

const UP_LOW_DISTANCE: u8 = 32;

fn to_lower(c: &FheUint8) -> FheUint8 {
    c + FheUint8::cast_from(c.gt(64) & c.lt(91)) * UP_LOW_DISTANCE
}
```

Full example:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheUint8};

const UP_LOW_DISTANCE: u8 = 32;

struct FheAsciiString {
    bytes: Vec<FheUint8>,
}

fn to_upper(c: &FheUint8) -> FheUint8 {
    c - FheUint8::cast_from(c.gt(96) & c.lt(123)) * UP_LOW_DISTANCE
}

fn to_lower(c: &FheUint8) -> FheUint8 {
    c + FheUint8::cast_from(c.gt(64) & c.lt(91)) * UP_LOW_DISTANCE
}

impl FheAsciiString {
    fn encrypt(string: &str, client_key: &ClientKey) -> Self {
        assert!(
            string.is_ascii(),
            "The input string must only contain ascii letters"
        );

        let fhe_bytes: Vec<FheUint8> = string
            .bytes()
            .map(|b| FheUint8::encrypt(b, client_key))
            .collect();

        Self { bytes: fhe_bytes }
    }

    fn decrypt(&self, client_key: &ClientKey) -> String {
        let ascii_bytes: Vec<u8> = self
            .bytes
            .iter()
            .map(|fhe_b| fhe_b.decrypt(client_key))
            .collect();
        String::from_utf8(ascii_bytes).unwrap()
    }

    fn to_upper(&self) -> Self {
        Self {
            bytes: self.bytes.iter().map(to_upper).collect(),
        }
    }

    fn to_lower(&self) -> Self {
        Self {
            bytes: self.bytes.iter().map(to_lower).collect(),
        }
    }
}

fn main() {
    let config = ConfigBuilder::default()
        .build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let my_string = FheAsciiString::encrypt("Hello Zama, how is it going?", &client_key);
    let verif_string = my_string.decrypt(&client_key);
    println!("Start string: {verif_string}");

    let my_string_upper = my_string.to_upper();
    let verif_string = my_string_upper.decrypt(&client_key);
    println!("Upper string: {verif_string}");
    assert_eq!(verif_string, "HELLO ZAMA, HOW IS IT GOING?");

    let my_string_lower = my_string_upper.to_lower();
    let verif_string = my_string_lower.decrypt(&client_key);
    println!("Lower string: {verif_string}");
    assert_eq!(verif_string, "hello zama, how is it going?");
}
```
