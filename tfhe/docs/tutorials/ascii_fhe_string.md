# A first complete example: FheAsciiString (Integer)

The goal of this tutorial is to build a data type that represents a ASCII string in FHE while implementing the `to_lower` and `to_upper` functions.

An ASCII character is stored in 7 bits.
To store an encrypted ASCII we use the `FheUint8`.

* The uppercase letters are in the range \[65, 90]
* The lowercase letters are in the range \[97, 122]

`lower_case = upper_case + UP_LOW_DISTANCE` <=> `upper_case = lower_case - UP_LOW_DISTANCE`

Where `UP_LOW_DISTANCE = 32`


## Types and methods.

This type will hold the encrypted characters as a `Vec<FheUint8>` to implement the functions that change the case.

To use the `FheUint8` type, the `integer` feature must be activated:

```toml
# Cargo.toml

[dependencies]
# Default configuration for x86 Unix machines:
tfhe = { version = "0.5.0", features = ["integer", "x86_64-unix"]}
```

Other configurations can be found [here](../getting_started/installation.md).



In the `FheAsciiString::encrypt` function, some data validation is done:

* The input string can only contain ascii characters.

It is not possible to branch on an encrypted value, however it is possible to evaluate a boolean condition and use it to get the desired result.
Checking if the 'char' is an uppercase letter to modify it to a lowercase can be done without using a branch, like this:

```rust
pub const UP_LOW_DISTANCE: u8 = 32;

fn to_lower(c: u8) -> u8 {
    if c > 64 && c < 91 {
        c + UP_LOW_DISTANCE
    } else {
        c
    }
}
```

We can remove the branch this way:

```rust
pub const UP_LOW_DISTANCE: u8 = 32;

fn to_lower(c: u8) -> u8 {
    c + ((c > 64) as u8 & (c < 91) as u8) * UP_LOW_DISTANCE
}
```

On an homomorphic integer, this gives

```rust
use tfhe::prelude::*;
use tfhe::FheUint8;

pub const UP_LOW_DISTANCE: u8 = 32;

fn to_lower(c: &FheUint8) -> FheUint8 {
    c + FheUint8::cast_from(c.gt(64) & c.lt(91)) * UP_LOW_DISTANCE
}
```

The whole code is:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheUint8};

pub const UP_LOW_DISTANCE: u8 = 32;

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
            string.chars().all(|char| char.is_ascii()),
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
