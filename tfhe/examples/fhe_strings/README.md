# FHE Strings

This example contains the implementation of a str API in FHE, featuring 30 methods. This API allows the user to:
* Encrypt the `str` with or without padding nulls (i.e. encrypted `0u8`s at the end of the string), which serve to obfuscate the length but are ignored by algorithms
* Encrypt any kind of pattern (`pat`, `from`, `to`, `rhs`) with or without padding nulls
* Encrypt the number of repetitions `n`, allowing to provide a clear `max` to restrict the range of the encrypted `n`
* Provide a cleartext pattern when algorithms can run faster. Otherwise, it's possible to trivially encrypt the pattern with `FheString::trivial`

Encrypted strings contain a flag indicating whether they have padding nulls or not. Algorithms are optimized to differentiate between the two kind of strings. For instance, in some cases we can skip entirely the FHE computations if we know the true lengths of the string or pattern.

Just like the clear str API, any encrypted string returned by a function can be used as input to other functions. For instance when `trim_start` is executed, or a `Split` iterator instance is advanced with `next`, the result will only have nulls at the end. The decryption function `decrypt_ascii` will panic if it encounters with malformed encrypted strings, including padding inconsistencies.

### Example

```rust
let (ck, sk) = gen_keys();
let s = "Zama ";
let padding = Some(2);

let enc_s = FheString::new(&ck, &s, padding);
let clear_count = UIntArg::Clear(3);

// All the nulls are shifted to the right end
let result_repeat = sk.repeat(&enc_s, &clear_count);
let result_trim_end = sk.trim_end(&result_repeat);
let result_uppercase = sk.to_uppercase(&result_trim_end);

let clear = ck.decrypt_ascii(&result_uppercase);

assert_eq!(clear, "ZAMA ZAMA ZAMA");
```

## Technical Details

We have implemented conversions between encrypted strings (`FheString`) and UInts (`RadixCiphertext`). This is useful for:

- Speeding up comparisons and pattern matching: We perform a _single comparison_ between two numbers. This is more efficient than many u8 comparisons.
- Shifting by an encrypted number of characters: By treating the string as a `RadixCiphertext` we can use the tfhe-rs shifting operations, and then convert back to `FheString`.

Similarly, when a pattern is provided in the clear (`ClearString`) we convert it to `StaticUnsignedBigInt<N>`. This type requires a constant `N` for the u64 length of the clear UInt, and we have set it to 4, allowing for up to 32 characters in `ClearString`.

`N` can be increased in `main.rs` to enable longer clear patterns, or reduced to improve performance (if we know that we will work with smaller clear patterns).

## Test Cases

We have handled corner cases like empty strings and empty patterns (with and without padding), the number of repetitions `n` (clear and encrypted) being zero, etc. A complete list of tests can be found at `assert_functions/test_vectors.rs`.

## Usage
To run all the functions and see the comparison with the clear Rust API you can specify the following arguments:

```--str <"your str"> --pat <"your pattern"> --to <"argument used in replace"> --rhs <"used in comparisons and concat"> --n <number of repetitions> --max <clear max n>```

To optionally specify a number of padding nulls for any argument you can also use: ``--str_pad``, ``--pat_pad``, ``--to_pad`` and ``--rhs_pad``.
