# Parity Bit (Boolean)

In this example, we are going to build a small function that homomorphically computes a parity bit.

We will first write a non-generic function. Then, we will write it using generics to be able to use the function with both `FheBool`s and normal `bool`s.

Our function that computes the parity bit will take 2 parameters:

* A slice of boolean
* A mode (`Odd` or `Even`)

This function will return a boolean that will be either `true` or `false` so that the sum of booleans (in the input + the returned one) is either an `Odd` or `Even` number depending on the requested mode.

***

## Non-generic version

Since we are going to use booleans, we must enable the `booleans` feature in our Cargo.toml.

```toml
# Cargo.toml

[dependencies]
# ...
tfhe = { version = "0.2.0", features = ["booleans"]}
```

### Function definition.

First, we need to define the function as well as the verification function.

The way to find the parity bit is to first initialize it to `false, then` `XOR` it with all the bits, one after the other and add negation depending on the requested mode.

We also define a validation function, that simply sums together the number of the bit set within the input with the computed parity bit and checks that the sum is an even or odd number, depending on the mode.

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

### Final code.

We can now call it, but first we have to do the mandatory configuration steps:

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

## Generic version

Now we want to make our `compute_parity_bit` function generic so that we can use it with both `FheBool` and `bool`.

Writing a generic function that accepts `FHE` types as well as clear types can help test the function to see if it is correct.
If the function is generic, that means we can run it with clear data,
allowing the use of print-debugging or a debugger to spot errors.

However, writing generic functions that use operator overloading for our FHE types can be a bit trickier than normal,
since, as explained in our [Generic Bounds How To](../how\_to/generic\_bounds.md), `FHE` types are not copy.
Therefore, you will need to use the reference `&`,  even though you wouldn't normally use it when using native types, which are all `Copy`.

This will make the generic bounds a bit trickier at first.

### Writing the correct trait bounds.

Our function has the following signature:

```text
fn check_parity_bit_validity(
    fhe_bits: &[FheBool],
    mode: ParityMode,
) -> bool
```

To make it generic, we can start by doing:

```text
fn compute_parity_bit<BoolType>(
    fhe_bits: &[BoolType],
    mode: ParityMode,
) -> BoolType
```

We now have to write the generic bounds: the `where` clause.

In our function, we use the following operators:

* `!` (trait: `Not`)
* `^` (trait: `BitXor`)

We can add them to our `where`, which would look like:

```text
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

`fhe_bit` is a reference to a `BoolType` (`&BoolType`) since it is borrowed from the `fhe_bits` slice when we iterate over its elements. We can try to change the `BitXor` bounds to what the compiler suggests by requiring `&BoolType` to implement `BitXor` and not `BoolType`.

```text
where
    BoolType: Clone + Not<Output = BoolType>,
    &BoolType: BitXor<BoolType, Output=BoolType>,
```

The compiler is still not happy:

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

The way to fix this is to use `Higher-Rank Trait Bounds` as shown in the [Generic Bounds How To](../how\_to/generic\_bounds.md):

```text
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

***

### Final code.

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
