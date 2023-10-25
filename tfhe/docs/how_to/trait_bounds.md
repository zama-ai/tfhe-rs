# Generic Bounds

If you wish to write generic functions which use operators with mixed reference and non-reference,
it might get tricky at first to specify the trait [bounds](https://doc.rust-lang.org/rust-by-example/generics/bounds.html). 
This page should serve as a _cookbook_ to help you.

Operators (+, *, >>, etc) are tied to traits in `std:::ops`, e.g. `+` is `std::ops::Add`,
so to write a generic function which uses the `+` operator, you need to use add `std::ops::Add`
as a trait bound.

Then, depending on if the left hand side / right hand side is an owned value or a reference, the trait bound
is slightly different. The table below shows the possibilities.

| operation   | trait bound                           |
| ----------- | ------------------------------------- |
| `T $op T`   | `T: $Op<T, Output=T>`                 |
| `T $op &T`  | `T: for<'a> $Op<&'a T, Output=T>`     |
| `&T $op T`  | `for<'a> &'a T: $Op<T, Output=T>`     |
| `&T $op &T` | `for<'a> &'a T: $Op<&'a T, Output=T>` |

{% hint style="info" %}
The `for<'a>` syntax is something called [Higher-Rank Trait Bounds](https://doc.rust-lang.org/nomicon/hrtb.html), often shortened as __HRTB__
{% endhint %}

{% hint style="info" %}
Writing generic functions will also allow you to call them using clear inputs,
only allowing easier debugging.
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
