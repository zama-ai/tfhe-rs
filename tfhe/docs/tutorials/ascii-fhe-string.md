# Homomorphic case changing on Ascii string

This tutorial demonstrates how to build your own data type that represents an ASCII string in Fully Homomorphic Encryption (FHE) by implementing to\_lower and to\_upper functions.

{% hint style="info" %}
Since version 0.11, **TFHE-rs** has introduced the `strings` feature, which provides an easy to use FHE strings API. See the [fhe strings guide](../fhe-computation/types/strings.md) for more information.
{% endhint %}

An ASCII character is stored in 7 bits. In this tutorial, we use the `FheUint8` to store an encrypted ASCII:

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
tfhe = { version = "~1.5.3", features = ["integer"] }
```

The `MyFheString::encrypt` function performs data validation to ensure the input string contains only ASCII characters.

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

struct MyFheString {
    bytes: Vec<FheUint8>,
}

fn to_upper(c: &FheUint8) -> FheUint8 {
    c - FheUint8::cast_from(c.gt(96) & c.lt(123)) * UP_LOW_DISTANCE
}

fn to_lower(c: &FheUint8) -> FheUint8 {
    c + FheUint8::cast_from(c.gt(64) & c.lt(91)) * UP_LOW_DISTANCE
}

impl MyFheString {
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

    let my_string = MyFheString::encrypt("Hello Zama, how is it going?", &client_key);
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

## Using **TFHE-rs** strings feature

This code can be greatly simplified by using the `strings` feature from **TFHE-rs**.

First, add the feature in your `Cargo.toml`

```toml
# Cargo.toml

[dependencies]
tfhe = { version = "~1.5.3", features = ["strings"] }
```

The `FheAsciiString` type allows to simply do homomorphic case changing of encrypted strings (and much more!):

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheAsciiString};

fn main() {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let my_string =
        FheAsciiString::try_encrypt("Hello Zama, how is it going?", &client_key).unwrap();
    let verif_string = my_string.decrypt(&client_key);
    println!("Start string: {verif_string}");

    let my_string_upper = my_string.to_uppercase();
    let verif_string = my_string_upper.decrypt(&client_key);
    println!("Upper string: {verif_string}");
    assert_eq!(verif_string, "HELLO ZAMA, HOW IS IT GOING?");

    let my_string_lower = my_string_upper.to_lowercase();
    let verif_string = my_string_lower.decrypt(&client_key);
    println!("Lower string: {verif_string}");
    assert_eq!(verif_string, "hello zama, how is it going?");
}
```

You can read more about this in the [FHE strings documentation](../fhe-computation/types/strings.md)
