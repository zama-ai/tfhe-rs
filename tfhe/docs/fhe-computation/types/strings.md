# Strings

This document explains the FheAsciiString type for handling encrypted strings in TFHE-rs.

TFHE-rs has supports for ASCII strings with the type FheAsciiString.
You can enable this feature using the flag: --features=strings

{% hint style="warning" %}
Strings are not yet compatible with `CompactCiphertextList` and `CompressedCiphertextList`
{% endhint %}

## Supported Operations

A variety of common operations are supported for `FheAsciiString`. These include:

- **Comparisons**: `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `eq_ignore_case`
- **Case conversion**: `to_lowercase` / `to_uppercase`
- **String checks**: `starts_with` / `ends_with` / `contains`
- **Trimming**: `trim_start` / `trim_end` / `trim`
- **Prefix/suffix operations**: `strip_prefix` / `strip_suffix`
- **Search**:  `find` / `rfind`


When encrypting strings, you can add padding to hide the actual length of strings.
The null character (b'\0') is used as the padding.
Here is an example:

```toml
# Cargo.toml

[dependencies]
tfhe = { version = "~1.5.4", features = ["integer", "strings"] }
```

```rust
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheAsciiString, FheStringLen, ClearString};
use tfhe::prelude::*;
use tfhe::safe_serialization::safe_serialize;


fn main() {
    let config = ConfigBuilder::default().build();
    let (cks, sks) = generate_keys(config);

    set_server_key(sks);

    let r = FheAsciiString::try_encrypt("café is french for coffee", &cks);
    // As the input string is not strictly ASCII, it is not compatible
    assert!(r.is_err());

    let string = FheAsciiString::try_encrypt("tfhe-rs", &cks).unwrap();
    // This adds 3 chars of padding to the chars of the input string
    let padded_string = FheAsciiString::try_encrypt_with_padding("tfhe-rs", 3, &cks).unwrap();
    // This makes it so the string has 10 chars (adds padding or truncates input as necessary)
    let other_string = FheAsciiString::try_encrypt_with_fixed_sized("tfhe", 10, &cks).unwrap();

    let mut buffer1 = vec![];
    safe_serialize(&padded_string, &mut buffer1, 1 << 30).unwrap();
    let mut buffer2 = vec![];
    safe_serialize(&other_string, &mut buffer2, 1 << 30).unwrap();
    // The two strings created with padding, have the same
    // memory/disk footprint, even though the lengths are not the same
    assert_eq!(buffer1.len(), buffer2.len());

    // When a string has no padding, its length is known in clear
    let len = string.len();
    assert!(matches!(len, FheStringLen::NoPadding(7)));
    // When a string has padding, its length is only known as an encrypted value
    let FheStringLen::Padding(encrypted_len) = padded_string.len() else {
        panic!("Expected len to be encrypted");
    };
    let padded_string_len: u16 = encrypted_len.decrypt(&cks);
    assert_eq!(padded_string_len, 7); // Note padding chars are not counted
    // The enum resulting of a len() / is_empty() call can be transformed 
    // to a FheUint16 using `into_ciphertext`
    assert!(string.len().into_ciphertext().is_trivial());
    assert!(!padded_string.len().into_ciphertext().is_trivial());
    let other_string_len: u16 = other_string.len().into_ciphertext().decrypt(&cks);
    assert_eq!(other_string_len, 4);

    // Padded and un-padded strings are equal if the content is
    assert!(padded_string.eq(&string).decrypt(&cks));

    let prefix = ClearString::new("tfhe".to_string());
    let (stripped_string, has_been_stripped) = string.strip_prefix(&prefix);
    // Notice that stripping, makes the string as being considered as padded
    // as it is not possible to homomorphically remove chars
    let FheStringLen::Padding(encrypted_len) = stripped_string.len() else {
        panic!("Expected len to be encrypted");
    };
    let stripped_string_len: u16 = encrypted_len.decrypt(&cks);
    assert_eq!(stripped_string_len, 3);
    let decrypted = stripped_string.decrypt(&cks);
    assert_eq!(decrypted, "-rs");
    assert!(has_been_stripped.decrypt(&cks));
}
```
