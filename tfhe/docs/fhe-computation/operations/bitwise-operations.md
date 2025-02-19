# Bitwise operations

This document details the bitwise operations supported by **TFHE-rs**.

Homomorphic integer types support the following bitwise operations:

<table><thead><tr><th width="242">name</th><th>symbol</th><th>type</th></tr></thead><tbody><tr><td><a href="https://doc.rust-lang.org/std/ops/trait.Not.html">Not</a></td><td><code>!</code></td><td>Unary</td></tr><tr><td><a href="https://doc.rust-lang.org/std/ops/trait.BitAnd.html">BitAnd</a></td><td><code>&#x26;</code></td><td>Binary</td></tr><tr><td><a href="https://doc.rust-lang.org/std/ops/trait.BitOr.html">BitOr</a></td><td><code>|</code></td><td>Binary</td></tr><tr><td><a href="https://doc.rust-lang.org/std/ops/trait.BitXor.html">BitXor</a></td><td><code>^</code></td><td>Binary</td></tr><tr><td><a href="https://doc.rust-lang.org/std/ops/trait.Shr.html">Shr</a></td><td><code>>></code></td><td>Binary</td></tr><tr><td><a href="https://doc.rust-lang.org/std/ops/trait.Shl.html">Shl</a></td><td><code>&#x3C;&#x3C;</code></td><td>Binary</td></tr><tr><td><a href="https://doc.rust-lang.org/std/primitive.u32.html#method.rotate_right">Rotate Right</a></td><td><code>rotate_right</code></td><td>Binary</td></tr><tr><td><a href="https://doc.rust-lang.org/std/primitive.u32.html#method.rotate_left">Rotate Left</a></td><td><code>rotate_left</code></td><td>Binary</td></tr></tbody></table>

The following example shows how to perform bitwise operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    let clear_a = 164;
    let clear_b = 212;

    let mut a = FheUint8::try_encrypt(clear_a, &keys)?;
    let mut b = FheUint8::try_encrypt(clear_b, &keys)?;

    a ^= &b;
    b ^= &a;
    a ^= &b;

    let dec_a: u8 = a.decrypt(&keys);
    let dec_b: u8 = b.decrypt(&keys);

    // We homomorphically swapped values using bitwise operations
    assert_eq!(dec_a, clear_b);
    assert_eq!(dec_b, clear_a);

    Ok(())
}
```
