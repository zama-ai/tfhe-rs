# A first complete example: FheLatinString (Integer)

The goal of this tutorial is to build a data type that represents a Latin string in FHE while implementing the `to_lower` and `to_upper` functions.

The allowed characters in a Latin string are:

* Uppercase letters: `A B C D E F G H I J K L M N O P Q R S T U V W X Y Z`
* Lowercase letters: `a b c d e f g h i j k l m n o p q r s t u v w x y z`

For the code point of the letters,`ascii` codes are used:

* The uppercase letters are in the range \[65, 90]
* The lowercase letters are in the range \[97, 122]

`lower_case` = `upper_case` + 32 <=> `upper_case` = `lower_case` - 32

For this type, the `FheUint8` type is used.

## Types and methods.

This type will hold the encrypted characters as a `Vec<FheUint8>`, as well as the encrypted constant `32` to implement the functions that change the case.

In the `FheLatinString::encrypt` function, some data validation is done:

* The input string can only contain ascii letters (no digit, no special characters).
* The input string cannot mix lower and upper case letters.

These two points are to work around a limitation of FHE. It is not possible to create branches, meaning the function cannot use conditional statements. Checking if the 'char' is an uppercase letter to modify it to a lowercase one cannot be done, like in the example below.

```rust
fn to_lower(string: &String) -> String {
    let mut result = String::with_capacity(string.len());
    for char in string.chars() {
        if char.is_uppercase() {
            result.extend(char.to_lowercase().to_string().chars())
        }
    }
    result
}
```

With these preconditions checked, implementing `to_lower` and `to_upper` is rather simple.

To use the `FheUint8` type, the `integer` feature must be activated:

```toml
# Cargo.toml

[dependencies]
# Default configuration for x86 Unix machines:
tfhe = { version = "0.3.0", features = ["integer", "x86_64-unix"]}
```

Other configurations can be found [here](../getting_started/installation.md).


```rust
use tfhe::{FheUint8, ConfigBuilder, generate_keys, set_server_key, ClientKey};
use tfhe::prelude::*;

struct FheLatinString{
    bytes: Vec<FheUint8>,
    // Constant used to switch lower case <=> upper case
    cst: FheUint8,
}

impl FheLatinString {
    fn encrypt(string: &str, client_key: &ClientKey) -> Self {
        assert!(
            string.chars().all(|char| char.is_ascii_alphabetic()),
            "The input string must only contain ascii letters"
        );

        let has_mixed_case = string.as_bytes().windows(2).any(|window| {
            let first = char::from(*window.first().unwrap());
            let second = char::from(*window.last().unwrap());

            (first.is_ascii_lowercase() && second.is_ascii_uppercase())
                || (first.is_ascii_uppercase() && second.is_ascii_lowercase())
        });

        assert!(
            !has_mixed_case,
            "The input string cannot mix lower case and upper case letters"
        );

        let fhe_bytes = string
            .bytes()
            .map(|b| FheUint8::encrypt(b, client_key))
            .collect::<Vec<FheUint8>>();
        let cst = FheUint8::encrypt(32u8, client_key);

        Self {
            bytes: fhe_bytes,
            cst,
        }
    }

    fn decrypt(&self, client_key: &ClientKey) -> String {
        let ascii_bytes = self
            .bytes
            .iter()
            .map(|fhe_b| fhe_b.decrypt(client_key))
            .collect::<Vec<u8>>();
        String::from_utf8(ascii_bytes).unwrap()
    }

    fn to_upper(&self) -> Self {
        Self {
            bytes: self
                .bytes
                .iter()
                .map(|b| b - &self.cst)
                .collect::<Vec<FheUint8>>(),
            cst: self.cst.clone(),
        }
    }

    fn to_lower(&self) -> Self {
        Self {
            bytes: self
                .bytes
                .iter()
                .map(|b| b + &self.cst)
                .collect::<Vec<FheUint8>>(),
            cst: self.cst.clone(),
        }
    }
}


fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let my_string = FheLatinString::encrypt("zama", &client_key);
    let verif_string = my_string.decrypt(&client_key);
    println!("{}", verif_string);

    let my_string_upper = my_string.to_upper();
    let verif_string = my_string_upper.decrypt(&client_key);
    println!("{}", verif_string);
    assert_eq!(verif_string, "ZAMA");

    let my_string_lower = my_string_upper.to_lower();
    let verif_string = my_string_lower.decrypt(&client_key);
    println!("{}", verif_string);
    assert_eq!(verif_string, "zama");
}
```
