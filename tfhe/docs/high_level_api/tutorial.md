# Tutorial

## Quick Start

The basic steps for using the high-level API of TFHE-rs are:

1. Importing TFHE-rs prelude;
2. Client-side: Configuring and creating keys;
3. Client-side: Encrypting data;
4. Server-side: Setting the server key;
5. Server-side: Computing over encrypted data;
6. Client-side: Decrypting data.

Here is the full example (mixing client and server parts):

```rust
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8};
use tfhe::prelude::*;

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_uint8()
        .build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);

    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);

    //Server-side
    set_server_key(server_key);
    let result = a + b;

    //Client-side
    let decrypted_result: u8 = result.decrypt(&client_key);

    let clear_result = clear_a + clear_b;

    assert_eq!(decrypted_result, clear_result);
}
```

Default configuration for x86 Unix machines:
```toml
tfhe = { version = "0.2.3", features = ["integer", "x86_64-unix"]}
```

Other configurations can be found [here](../getting_started/installation.md).

### Imports.

`tfhe` uses `traits` to have a consistent API for creating FHE types and enable users to write generic functions. To be able to use associated functions and methods of a trait, the trait has to be in scope.

To make it easier, the `prelude` 'pattern' is used. All `tfhe` important traits are in a `prelude` module that you **glob import**. With this, there is no need to remember or know the traits to import.

```rust
use tfhe::prelude::*;
```

### 1. Configuring and creating keys.

The first step is the creation of the configuration. The configuration is used to declare which type you will use or not use, as well as enabling you to use custom crypto-parameters for these types for more advanced usage / testing.

Creating a configuration is done using the ConfigBuilder type.

In this example, 8-bit unsigned integers with default parameters are used. The `integers` 
feature must also be enabled, as per the table on the [Getting Started page](../getting_started/installation.md).

The config is done by first creating a builder with all types deactivated. Then, the `uint8` type with default parameters is activated.

```rust
use tfhe::{ConfigBuilder, generate_keys};

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_uint8()
        .build();

    let (client_key, server_key) = generate_keys(config);
}
```

The `generate_keys` command returns a client key and a server key.

The `client_key` is meant to stay private and not leave the client whereas the `server_key` can be made public and sent to a server for it to enable FHE computations.

### 2. Setting the server key.

The next step is to call `set_server_key`

This function will **move** the server key to an internal state of the crate and manage the details to give a simpler interface.

```rust
use tfhe::{ConfigBuilder, generate_keys, set_server_key};

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_uint8()
        .build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);
}
```

### 3. Encrypting data.

Encrypting data is done via the `encrypt` associated function of the \[FheEncrypt] trait.

Types exposed by this crate implement at least one of \[FheEncrypt] or \[FheTryEncrypt] to allow enryption.

```Rust
let clear_a = 27u8;
let clear_b = 128u8;

let a = FheUint8::encrypt(clear_a, &client_key);
let b = FheUint8::encrypt(clear_b, &client_key);
```

### 4. Computation and decryption.

Computations should be as easy as normal Rust to write, thanks to operator overloading.

```Rust
let result = a + b;
```

The decryption is done by using the `decrypt` method, which comes from the \[FheDecrypt] trait.

```Rust
let decrypted_result: u8 = result.decrypt(&client_key);

let clear_result = clear_a + clear_b;

assert_eq!(decrypted_result, clear_result);
```

## A first complete example: FheLatinString (Integer)

The goal of this tutorial is to build a data type that represents a Latin string in FHE while implementing the `to_lower` and `to_upper` functions.

The allowed characters in a Latin string are:

* Uppercase letters: `A B C D E F G H I J K L M N O P Q R S T U V W X Y Z`
* Lowercase letters: `a b c d e f g h i j k l m n o p q r s t u v w x y z`

For the code point of the letters,`ascii` codes are used:

* The uppercase letters are in the range \[65, 90]
* The lowercase letters are in the range \[97, 122]

`lower_case` = `upper_case` + 32 <=> `upper_case` = `lower_case` - 32

For this type, the `FheUint8` type is used.

### Types and methods.

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
tfhe = { version = "0.2.3", features = ["integer", "x86_64-unix"]}
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
        let cst = FheUint8::encrypt(32, client_key);

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
        .enable_default_uint8()
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

## A more complex example: Parity Bit (Boolean)

This example is dedicated to the building of a small function that homomorphically computes a parity bit.

First, a non-generic function is written. Then, generics are used to handle the case where the function inputs are both `FheBool`s and clear `bool`s.

The parity bit function takes as input two parameters:

* A slice of Boolean
* A mode (`Odd` or `Even`)

This function returns a Boolean that will be either `true` or `false` so that the sum of Booleans (in the input and the returned one) is either an `Odd` or `Even` number, depending on the requested mode.

***

### Non-generic version.

To use Booleans, the `booleans` feature in our Cargo.toml must be enabled:

```toml
# Cargo.toml

# Default configuration for x86 Unix machines:
tfhe = { version = "0.2.3", features = ["boolean", "x86_64-unix"]}
```

Other configurations can be found [here](../getting_started/installation.md).


#### function definition

First, the verification function is defined.

The way to find the parity bit is to initialize it to `false, then` `XOR` it with all the bits, one after the other, adding negation depending on the requested mode.

A validation function is also defined to sum together the number of the bit set within the input with the computed parity bit and check that the sum is an even or odd number, depending on the mode.

```rust
use tfhe::FheBool;
use tfhe::prelude::*;

#[derive(Copy, Clone, Debug)]
enum ParityMode {
    // The sum bits of message + parity bit must an odd number
    Odd,
    // The sum bits of message + parity bit must an even number
    Even,
}

fn compute_parity_bit(fhe_bits: &[FheBool], mode: ParityMode) -> FheBool {
    let mut parity_bit = fhe_bits[0].clone();
    for fhe_bit in &fhe_bits[1..] {
        parity_bit = fhe_bit ^ parity_bit
    }

    match mode {
        ParityMode::Odd => !parity_bit,
        ParityMode::Even => parity_bit,
    }
}

fn is_even(n: u8) -> bool {
    (n & 1) == 0
}

fn is_odd(n: u8) -> bool {
    !is_even(n)
}

fn check_parity_bit_validity(bits: &[bool], mode: ParityMode, parity_bit: bool) -> bool {
    let num_bit_set = bits
        .iter()
        .map(|bit| *bit as u8)
        .fold(parity_bit as u8, |acc, bit| acc + bit);

    match mode {
        ParityMode::Even => is_even(num_bit_set),
        ParityMode::Odd => is_odd(num_bit_set),
    }
}
```

#### final code

After the mandatory configuration steps, the function is called:

```rust
use tfhe::{FheBool, ConfigBuilder, generate_keys, set_server_key};
use tfhe::prelude::*;

#[derive(Copy, Clone, Debug)]
enum ParityMode {
    // The sum bits of message + parity bit must an odd number
    Odd,
    // The sum bits of message + parity bit must an even number
    Even,
}

fn compute_parity_bit(fhe_bits: &[FheBool], mode: ParityMode) -> FheBool {
    let mut parity_bit = fhe_bits[0].clone();
    for fhe_bit in &fhe_bits[1..] {
        parity_bit = fhe_bit ^ parity_bit
    }

    match mode {
        ParityMode::Odd => !parity_bit,
        ParityMode::Even => parity_bit,
    }
}

fn is_even(n: u8) -> bool {
    (n & 1) == 0
}

fn is_odd(n: u8) -> bool {
    !is_even(n)
}

fn check_parity_bit_validity(bits: &[bool], mode: ParityMode, parity_bit: bool) -> bool {
    let num_bit_set = bits
        .iter()
        .map(|bit| *bit as u8)
        .fold(parity_bit as u8, |acc, bit| acc + bit);

    match mode {
        ParityMode::Even => is_even(num_bit_set),
        ParityMode::Odd => is_odd(num_bit_set),
    }
}

fn main() {
    let config = ConfigBuilder::all_disabled().enable_default_bool().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let clear_bits = [0, 1, 0, 0, 0, 1, 1].map(|b| (b != 0) as bool);

    let fhe_bits = clear_bits
        .iter()
        .map(|bit| FheBool::encrypt(*bit, &client_key))
        .collect::<Vec<FheBool>>();

    let mode = ParityMode::Odd;
    let fhe_parity_bit = compute_parity_bit(&fhe_bits, mode);
    let decrypted_parity_bit = fhe_parity_bit.decrypt(&client_key);
    let is_parity_bit_valid = check_parity_bit_validity(&clear_bits, mode, decrypted_parity_bit);
    println!("Parity bit is set: {} for mode: {:?}", decrypted_parity_bit, mode);
    assert!(is_parity_bit_valid);

    let mode = ParityMode::Even;
    let fhe_parity_bit = compute_parity_bit(&fhe_bits, mode);
    let decrypted_parity_bit = fhe_parity_bit.decrypt(&client_key);
    let is_parity_bit_valid = check_parity_bit_validity(&clear_bits, mode, decrypted_parity_bit);
    println!("Parity bit is set: {} for mode: {:?}", decrypted_parity_bit, mode);
    assert!(is_parity_bit_valid);
}
```

***

### Generic version.

To make the `compute_parity_bit` function compatible with both `FheBool` and `bool`, generics have to be used.

Writing a generic function that accepts `FHE` types as well as clear types can help test the function to see if it is correct. If the function is generic, it can run with clear data, allowing the use of print-debugging or a debugger to spot errors.

Writing generic functions that use operator overloading for our FHE types can be trickier than normal, since `FHE` types are not copy. So using the reference `&` is mandatory, even though this is not the case when using native types, which are all `Copy`.

This will make the generic bounds trickier at first.

#### writing the correct trait bounds

The function has the following signature:

```Rust
fn check_parity_bit_validity(
    fhe_bits: &[FheBool],
    mode: ParityMode,
) -> bool
```

To make it generic, the first step is:

```Rust
fn compute_parity_bit<BoolType>(
    fhe_bits: &[BoolType],
    mode: ParityMode,
) -> BoolType
```

Next, the generic bounds have to be defined with the `where` clause.

In the function, the following operators are used:

* `!` (trait: `Not`)
* `^` (trait: `BitXor`)

By adding them to `where`, this gives:

```Rust
where
    BoolType: Clone + Not<Output = BoolType>,
    BoolType: BitXor<BoolType, Output=BoolType>,
```

However, the compiler will complain:

```text
---- src/user_doc_tests.rs - user_doc_tests (line 199) stdout ----
error[E0369]: no implementation for `&BoolType ^ BoolType`
--> src/user_doc_tests.rs:218:30
    |
21  | parity_bit = fhe_bit ^ parity_bit
    |              ------- ^ ---------- BoolType
    |             |
    |             &BoolType
    |
help: consider extending the `where` bound, but there might be an alternative better way to express this requirement
    |
17  | BoolType: BitXor<BoolType, Output=BoolType>, &BoolType: BitXor<BoolType>
    |                                                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
error: aborting due to previous error
```

`fhe_bit` is a reference to a `BoolType` (`&BoolType`) since it is borrowed from the `fhe_bits` slice when iterating over its elements. The first try is to change the `BitXor` bounds to what the Compiler suggests by requiring `&BoolType` to implement `BitXor` and not `BoolType`.

```Rust
where
    BoolType: Clone + Not<Output = BoolType>,
    &BoolType: BitXor<BoolType, Output=BoolType>,
```

The Compiler is still not happy:

```text
---- src/user_doc_tests.rs - user_doc_tests (line 236) stdout ----
error[E0637]: `&` without an explicit lifetime name cannot be used here
  --> src/user_doc_tests.rs:251:5
   |
17 |     &BoolType: BitXor<BoolType, Output=BoolType>,
   |     ^ explicit lifetime name needed here

error[E0310]: the parameter type `BoolType` may not live long enough
  --> src/user_doc_tests.rs:251:16
   |
17 |     &BoolType: BitXor<BoolType, Output=BoolType>,
   |                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ...so that the reference type `&'static BoolType` does not outlive the data it points at
   |
help: consider adding an explicit lifetime bound...
   |
15 |     BoolType: Clone + Not<Output = BoolType> + 'static,
   |
```

The way to fix this is to use `Higher-Rank Trait Bounds`:

```Rust
where
    BoolType: Clone + Not<Output = BoolType>,
    for<'a> &'a BoolType: BitXor<BoolType, Output = BoolType>,
```

The final code will look like this:

```rust
use std::ops::{Not, BitXor};

#[derive(Copy, Clone, Debug)]
enum ParityMode {
    // The sum bits of message + parity bit must an odd number
    Odd,
    // The sum bits of message + parity bit must an even number
    Even,
}

fn compute_parity_bit<BoolType>(fhe_bits: &[BoolType], mode: ParityMode) -> BoolType
where
    BoolType: Clone + Not<Output = BoolType>,
    for<'a> &'a BoolType: BitXor<BoolType, Output = BoolType>,
{
    let mut parity_bit = fhe_bits[0].clone();
    for fhe_bit in &fhe_bits[1..] {
        parity_bit = fhe_bit ^ parity_bit
    }

    match mode {
        ParityMode::Odd => !parity_bit,
        ParityMode::Even => parity_bit,
    }
}
```

#### final code

Here is a complete example that uses this function for both clear and FHE values:

```rust
use tfhe::{FheBool, ConfigBuilder, generate_keys, set_server_key};
use tfhe::prelude::*;

use std::ops::{Not, BitXor};

#[derive(Copy, Clone, Debug)]
enum ParityMode {
    // The sum bits of message + parity bit must an odd number
    Odd,
    // The sum bits of message + parity bit must an even number
    Even,
}

fn compute_parity_bit<BoolType>(fhe_bits: &[BoolType], mode: ParityMode) -> BoolType
    where
        BoolType: Clone + Not<Output=BoolType>,
        for<'a> &'a BoolType: BitXor<BoolType, Output=BoolType>,
{
    let mut parity_bit = fhe_bits[0].clone();
    for fhe_bit in &fhe_bits[1..] {
        parity_bit = fhe_bit ^ parity_bit
    }

    match mode {
        ParityMode::Odd => !parity_bit,
        ParityMode::Even => parity_bit,
    }
}

fn is_even(n: u8) -> bool {
    (n & 1) == 0
}

fn is_odd(n: u8) -> bool {
    !is_even(n)
}

fn check_parity_bit_validity(bits: &[bool], mode: ParityMode, parity_bit: bool) -> bool {
    let num_bit_set = bits
        .iter()
        .map(|bit| *bit as u8)
        .fold(parity_bit as u8, |acc, bit| acc + bit);

    match mode {
        ParityMode::Even => is_even(num_bit_set),
        ParityMode::Odd => is_odd(num_bit_set),
    }
}

fn main() {
    let config = ConfigBuilder::all_disabled().enable_default_bool().build();

    let ( client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let clear_bits = [0, 1, 0, 0, 0, 1, 1].map(|b| (b != 0) as bool);

    let fhe_bits = clear_bits
        .iter()
        .map(|bit| FheBool::encrypt(*bit, &client_key))
        .collect::<Vec<FheBool>>();

    let mode = ParityMode::Odd;
    let clear_parity_bit = compute_parity_bit(&clear_bits, mode);
    let fhe_parity_bit = compute_parity_bit(&fhe_bits, mode);
    let decrypted_parity_bit = fhe_parity_bit.decrypt(&client_key);
    let is_parity_bit_valid = check_parity_bit_validity(&clear_bits, mode, decrypted_parity_bit);
    println!("Parity bit is set: {} for mode: {:?}", decrypted_parity_bit, mode);
    assert!(is_parity_bit_valid);
    assert_eq!(decrypted_parity_bit, clear_parity_bit);

    let mode = ParityMode::Even;
    let clear_parity_bit = compute_parity_bit(&clear_bits, mode);
    let fhe_parity_bit = compute_parity_bit(&fhe_bits, mode);
    let decrypted_parity_bit = fhe_parity_bit.decrypt(&client_key);
    let is_parity_bit_valid = check_parity_bit_validity(&clear_bits, mode, decrypted_parity_bit);
    println!("Parity bit is set: {} for mode: {:?}", decrypted_parity_bit, mode);
    assert!(is_parity_bit_valid);
    assert_eq!(decrypted_parity_bit, clear_parity_bit);
}
```
