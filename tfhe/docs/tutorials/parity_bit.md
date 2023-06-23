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
tfhe = { version = "0.3.0", features = ["boolean", "x86_64-unix"]}
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
