# Generic trait bounds

This document serves as a practical reference for implementing generic functions in Rust that use operators across mixed references and values. The following explanations help you to understand the trait [bounds](https://doc.rust-lang.org/rust-by-example/generics/bounds.html) necessary to handle such operations.

Operators such as `+`, `*`, `>>,` and so on are tied to traits in `std:::ops`. For instance, the `+` operator corresponds to `std::ops::Add`. When writing a generic function that uses the `+` operator, you need to specify `std::ops::Add` as a trait bound.

The trait bound varies slightly depending on whether the left-hand side / right-hand side is an owned value or a reference. The following table shows the different scenarios:

| operation   | trait bound                           |
| ----------- | ------------------------------------- |
| `T $op T`   | `T: $Op<T, Output=T>`                 |
| `T $op &T`  | `T: for<'a> $Op<&'a T, Output=T>`     |
| `&T $op T`  | `for<'a> &'a T: $Op<T, Output=T>`     |
| `&T $op &T` | `for<'a> &'a T: $Op<&'a T, Output=T>` |

{% hint style="info" %}
The `for<'a>` syntax refers to the [Higher-Rank Trait Bounds(HRTB)](https://doc.rust-lang.org/nomicon/hrtb.html).
{% endhint %}

{% hint style="info" %}
Using generic functions allows for clearer input handling, which simplifies the debugging.
{% endhint %}

## Example

```rust
use std::ops::{Add, Mul};
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint64};

pub fn ex1<'a, FheType, ClearType>(ct: &'a FheType, pt: ClearType) -> FheType
    where
        &'a FheType: Add<ClearType, Output = FheType>,
{
    ct + pt
}

pub fn ex2<'a, FheType, ClearType>(a: &'a FheType, b: &'a FheType, pt: ClearType) -> FheType
    where
        &'a FheType: Mul<&'a FheType, Output = FheType>,
        FheType: Add<ClearType, Output = FheType>,
{
    (a * b) + pt
}

pub fn ex3<FheType, ClearType>(a: FheType, b: FheType, pt: ClearType) -> FheType
    where
            for<'a> &'a FheType: Add<&'a FheType, Output = FheType>,
            FheType: Add<FheType, Output = FheType> + Add<ClearType, Output = FheType>,
{
    let tmp = (&a + &b) + (&a + &b);
    tmp + pt
}

pub fn ex4<FheType, ClearType>(a: FheType, b: FheType, pt: ClearType) -> FheType
    where
        FheType: Clone + Add<FheType, Output = FheType> + Add<ClearType, Output = FheType>,
{
    let tmp = (a.clone() + b.clone()) + (a.clone() + b.clone());
    tmp + pt
}

fn main() {
    let config = ConfigBuilder::default()
        .build();

    let (client_key, server_keys) = generate_keys(config);

    set_server_key(server_keys);

    // Use FheUint32
    {
        let clear_a = 46546u32;
        let clear_b = 6469u32;
        let clear_c = 64u32;

        let a = FheUint32::try_encrypt(clear_a, &client_key).unwrap();
        let b = FheUint32::try_encrypt(clear_b, &client_key).unwrap();
        assert_eq!(
            ex1(&clear_a, clear_c),
            ex1(&a, clear_c).decrypt(&client_key)
        );
        assert_eq!(
            ex2(&clear_a, &clear_b, clear_c),
            ex2(&a, &b, clear_c).decrypt(&client_key)
        );
        assert_eq!(
            ex3(clear_a, clear_b, clear_c),
            ex3(a.clone(), b.clone(), clear_c).decrypt(&client_key)
        );
        assert_eq!(
            ex4(clear_a, clear_b, clear_c),
            ex4(a, b, clear_c).decrypt(&client_key)
        );
    }

    // Use FheUint64
    {
        let clear_a = 46544866u64;
        let clear_b = 6469446677u64;
        let clear_c = 647897u64;

        let a = FheUint64::try_encrypt(clear_a, &client_key).unwrap();
        let b = FheUint64::try_encrypt(clear_b, &client_key).unwrap();
        assert_eq!(
            ex1(&clear_a, clear_c),
            ex1(&a, clear_c).decrypt(&client_key)
        );
        assert_eq!(
            ex2(&clear_a, &clear_b, clear_c),
            ex2(&a, &b, clear_c).decrypt(&client_key)
        );
        assert_eq!(
            ex3(clear_a, clear_b, clear_c),
            ex3(a.clone(), b.clone(), clear_c).decrypt(&client_key)
        );
        assert_eq!(
            ex4(clear_a, clear_b, clear_c),
            ex4(a, b, clear_c).decrypt(&client_key)
        );
    }
}
```
