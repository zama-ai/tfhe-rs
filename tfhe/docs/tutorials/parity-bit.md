# Homomorphic parity bit

This tutorial shows how to build a small function that homomorphically computes a parity bit in 2 steps:

1. Write a non-generic function
2. Use generics to handle the case where the function inputs are both `FheBool`s and clear `bool`s.

The parity bit function processes two parameters:

* A slice of Boolean
* A mode (`Odd` or `Even`)

This function returns a Boolean (`true` or `false`) so that the total count of `true` values across the input and the result matches with the specified parity mode (`Odd` or `Even`).

## Non-generic version

```toml
# Cargo.toml

tfhe = { version = "~1.5.3", features = ["integer"] }
```

First, define the verification function.

The function initializes the parity bit to `false`, then applies the `XOR` operation across all bits, adding negation based on the requested mode.

The validation function also adds the number of the bits set in the input to the computed parity bit and checks whether the sum is even or odd, depending on the mode.

```rust
#![allow(dead_code)]
use tfhe::FheBool;

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

After configurations, call the function:

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
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let clear_bits = [0, 1, 0, 0, 0, 1, 1].map(|b| b != 0);

    let fhe_bits = clear_bits
        .iter()
        .map(|bit| FheBool::encrypt(*bit, &client_key))
        .collect::<Vec<FheBool>>();

    let mode = ParityMode::Odd;
    let fhe_parity_bit = compute_parity_bit(&fhe_bits, mode);
    let decrypted_parity_bit = fhe_parity_bit.decrypt(&client_key);
    let is_parity_bit_valid = check_parity_bit_validity(&clear_bits, mode, decrypted_parity_bit);
    println!("Parity bit is set: {decrypted_parity_bit} for mode: {mode:?}");
    assert!(is_parity_bit_valid);

    let mode = ParityMode::Even;
    let fhe_parity_bit = compute_parity_bit(&fhe_bits, mode);
    let decrypted_parity_bit = fhe_parity_bit.decrypt(&client_key);
    let is_parity_bit_valid = check_parity_bit_validity(&clear_bits, mode, decrypted_parity_bit);
    println!("Parity bit is set: {decrypted_parity_bit} for mode: {mode:?}");
    assert!(is_parity_bit_valid);
}
```

## Generic version

To enable the `compute_parity_bit` function to operate with both encrypted `FheBool` and plain bool, we introduce generics. This approach allows for validation using clear data and facilitates debugging.

Writing generic functions that incorporate operator overloading for our Fully Homomorphic Encryption (FHE) types is more complex than usual because FHE types do not implement the `Copy` trait. Consequently, it is necessary to use references (&) with these types, unlike native types, which typically implement `Copy`.

This complicates generic bounds at first.

### Writing the correct trait bounds

The function has the following signature:

```Rust
fn check_parity_bit_validity(
    fhe_bits: &[FheBool],
    mode: ParityMode,
) -> bool
```

To make it generic, the first steps is:

```Rust
fn compute_parity_bit<BoolType>(
    fhe_bits: &[BoolType],
    mode: ParityMode,
) -> BoolType
```

Next, define the generic bounds with the `where` clause.

In the function, you can use the following operators:

* `!` (trait: `Not`)
* `^` (trait: `BitXor`)

Adding them to `where`, it gives:

```Rust
where
    BoolType: Clone + Not<Output = BoolType>,
    BoolType: BitXor<BoolType, Output=BoolType>,
```

However, the compiler will return an error:

```console
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

`fhe_bit` is a reference to a `BoolType` (`&BoolType`), because `BoolType` is borrowed from the `fhe_bits` slice during iteration. To fix the error, the first approach could be changing the `BitXor` bounds to what the Compiler suggests, by requiring `&BoolType` to implement `BitXor` rather than `BoolType`.

```Rust
where
    BoolType: Clone + Not<Output = BoolType>,
    &BoolType: BitXor<BoolType, Output=BoolType>,
```

However, this approach still leads to an error:

```console
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

To fix this error, use `Higher-Rank Trait Bounds`:

```Rust
where
    BoolType: Clone + Not<Output = BoolType>,
    for<'a> &'a BoolType: BitXor<BoolType, Output = BoolType>,
```

The final code is as follows:

```rust
#![allow(dead_code)]
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
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let clear_bits = [0, 1, 0, 0, 0, 1, 1].map(|b| b != 0);

    let fhe_bits = clear_bits
        .iter()
        .map(|bit| FheBool::encrypt(*bit, &client_key))
        .collect::<Vec<FheBool>>();

    let mode = ParityMode::Odd;
    let clear_parity_bit = compute_parity_bit(&clear_bits, mode);
    let fhe_parity_bit = compute_parity_bit(&fhe_bits, mode);
    let decrypted_parity_bit = fhe_parity_bit.decrypt(&client_key);
    let is_parity_bit_valid = check_parity_bit_validity(&clear_bits, mode, decrypted_parity_bit);
    println!("Parity bit is set: {decrypted_parity_bit} for mode: {mode:?}");
    assert!(is_parity_bit_valid);
    assert_eq!(decrypted_parity_bit, clear_parity_bit);

    let mode = ParityMode::Even;
    let clear_parity_bit = compute_parity_bit(&clear_bits, mode);
    let fhe_parity_bit = compute_parity_bit(&fhe_bits, mode);
    let decrypted_parity_bit = fhe_parity_bit.decrypt(&client_key);
    let is_parity_bit_valid = check_parity_bit_validity(&clear_bits, mode, decrypted_parity_bit);
    println!("Parity bit is set: {decrypted_parity_bit} for mode: {mode:?}");
    assert!(is_parity_bit_valid);
    assert_eq!(decrypted_parity_bit, clear_parity_bit);
}
```
