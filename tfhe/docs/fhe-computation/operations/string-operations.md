# String operations

This document details the string operations supported by **TFHE-rs**.

| clear name                                                                                                      | fhe name             | first input type | second input type                            | third input type
| --------------------------------------------------------------------------------------------------------------- | -------------------- | -------------- | ---------------------------------------------- | ------------------
| [eq](https://doc.rust-lang.org/stable/std/primitive.str.html#method.eq)                                         |eq                    | FheAsciiString | FheAsciiString or ClearString                  |
| [ne](https://doc.rust-lang.org/stable/std/primitive.str.html#method.ne)                                         |ne                    | FheAsciiString | FheAsciiString or ClearString                  |
| [le](https://doc.rust-lang.org/stable/std/primitive.str.html#method.le)                                         |le                    | FheAsciiString | FheAsciiString or ClearString                  |
| [ge](https://doc.rust-lang.org/stable/std/primitive.str.html#method.ge)                                         |ge                    | FheAsciiString | FheAsciiString or ClearString                  |
| [lt](https://doc.rust-lang.org/stable/std/primitive.str.html#method.lt)                                         |lt                    | FheAsciiString | FheAsciiString or ClearString                  |
| [gt](https://doc.rust-lang.org/stable/std/primitive.str.html#method.gt)                                         |gt                    | FheAsciiString | FheAsciiString or ClearString                  |
| [len](https://doc.rust-lang.org/stable/std/primitive.str.html#method.len)                                       |len                   | FheAsciiString |                                                |
| [is_empty](https://doc.rust-lang.org/stable/std/primitive.str.html#method.is_empty)                             |is_empty              | FheAsciiString |                                                |
| [eq_ignore_ascii_case](https://doc.rust-lang.org/stable/std/primitive.str.html#method.eq_ignore_ascii_case)     |eq_ignore_case        | FheAsciiString | FheAsciiString or ClearString                  |
| [to_lowercase](https://doc.rust-lang.org/stable/std/primitive.str.html#method.to_lowercase)                     |to_lowercase          | FheAsciiString |                                                |
| [to_uppercase](https://doc.rust-lang.org/stable/std/primitive.str.html#method.to_uppercase)                     |to_uppercase          | FheAsciiString |                                                |
| [contains](https://doc.rust-lang.org/stable/std/primitive.str.html#method.contains)                             |contains              | FheAsciiString | FheAsciiString or ClearString                  |
| [ends_with](https://doc.rust-lang.org/stable/std/primitive.str.html#method.ends_with)                           |ends_with             | FheAsciiString | FheAsciiString or ClearString                  |
| [starts_with](https://doc.rust-lang.org/stable/std/primitive.str.html#method.starts_with)                       |starts_with           | FheAsciiString | FheAsciiString or ClearString                  |
| [find](https://doc.rust-lang.org/stable/std/primitive.str.html#method.find)                                     |find                  | FheAsciiString | FheAsciiString or ClearString                  |
| [rfind](https://doc.rust-lang.org/stable/std/primitive.str.html#method.rfind)                                   |rfind                 | FheAsciiString | FheAsciiString or ClearString                  |
| [strip_prefix](https://doc.rust-lang.org/stable/std/primitive.str.html#method.strip_prefix)                     |strip_prefix          | FheAsciiString | FheAsciiString or ClearString                  |
| [strip_suffix](https://doc.rust-lang.org/stable/std/primitive.str.html#method.strip_suffix)                     |strip_suffix          | FheAsciiString | FheAsci---iString or ClearString               |
| [concat](https://doc.rust-lang.org/stable/std/primitive.str.html#method.concat)                                 |concat                | FheAsciiString | FheAsciiString                                 |
| [repeat](https://doc.rust-lang.org/stable/std/primitive.str.html#method.repeat)                                 |repeat                | FheAsciiString | u16 or u32 or i32 or usize or (FheUint16, u16) |
| [trim_end](https://doc.rust-lang.org/stable/std/primitive.str.html#method.trim_end)                             |trim_end              | FheAsciiString |                                                |
| [trim_start](https://doc.rust-lang.org/stable/std/primitive.str.html#method.trim_start)                         |trim_start            | FheAsciiString |                                                |
| [trim](https://doc.rust-lang.org/stable/std/primitive.str.html#method.trim)                                     |trim                  | FheAsciiString |                                                |
| [replace](https://doc.rust-lang.org/stable/std/primitive.str.html#method.replace)                               |replace               | FheAsciiString | FheAsciiString                                 |
| [replacen](https://doc.rust-lang.org/stable/std/primitive.str.html#method.replacen)                             |replacen              | FheAsciiString | FheAsciiString or ClearString                  | u16 or u32 or i32 or usize or (FheUint16, u16)

The following example shows how to perform string operations:

```rust
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheAsciiString,
};
    
fn main() -> Result<(), Box<dyn std::error::Error>> {
    
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);
    
    let string1 = FheAsciiString::try_encrypt("tfhe-RS", &client_key).unwrap();
    let string2 = FheAsciiString::try_encrypt("TFHE-rs", &client_key).unwrap();
    let is_eq = string1.eq_ignore_case(&string2);

    assert!(is_eq.decrypt(&client_key));

    Ok(())
}
```
