# Array Types In High-level API

This document describes the array types provided by the High-level API.

This new encrypted types allow you to easily perform array and tensor operations on encrypted data, taking care of the iteration and shape logic for you.

It also implements efficient algorithms in some cases, like summing elements of an array.

The following example shows a complete workflow of working with encrypted arrays, including:
- Generating keys
- Encrypting arrays of integers
- Performing operations such as:
    - slicing arrays
    - computing on a sub array, adding encrypted data to it
    - computing on a sub array, adding clear data to it
- Decrypting the result, getting back a Rust `Vec` of decrypted values

```toml
# Cargo.toml

[dependencies]
tfhe = { version = "~1.5.3", features = ["integer"] }
```

```rust
use tfhe::{ConfigBuilder, generate_keys, set_server_key, CpuFheUint32Array, ClearArray};
use tfhe::prelude::*;

fn main() {
    let config = ConfigBuilder::default().build();
    let (cks, sks) = generate_keys(config);

    set_server_key(sks);

    let num_elems = 4 * 4;
    let clear_xs = (0..num_elems as u32).collect::<Vec<_>>();
    let clear_ys = vec![1u32; num_elems];

    // Encrypted 2D array with values
    // [[  0,  1,  2,  3]
    //  [  4,  5,  6,  7]
    //  [  8,  9, 10, 11]
    //  [ 12, 13, 14, 15]]
    let xs = CpuFheUint32Array::try_encrypt((clear_xs.as_slice(), vec![4, 4]), &cks).unwrap();
    // Encrypted 2D array with values
    // [[  1,  1,  1,  1]
    //  [  1,  1,  1,  1]
    //  [  1,  1,  1,  1]
    //  [  1,  1,  1,  1]]
    let ys = CpuFheUint32Array::try_encrypt((clear_ys.as_slice(), vec![4, 4]), &cks).unwrap();

    assert_eq!(xs.num_dim(), 2);
    assert_eq!(xs.shape(), &[4, 4]);
    assert_eq!(ys.num_dim(), 2);
    assert_eq!(ys.shape(), &[4, 4]);

    // Take a sub slice
    //  [[ 10, 11]
    //   [ 14, 15]]
    let xss = xs.slice(&[2..4, 2..4]);
    // Take a sub slice
    //  [[  1,  1]
    //   [  1,  1]]
    let yss = ys.slice(&[2..4, 2..4]);

    assert_eq!(xss.num_dim(), 2);
    assert_eq!(xss.shape(), &[2, 2]);
    assert_eq!(yss.num_dim(), 2);
    assert_eq!(yss.shape(), &[2, 2]);

    let r = &xss + &yss;

    // Result is
    //  [[ 11, 12]
    //   [ 15, 16]]
    let result: Vec<u32> = r.decrypt(&cks);
    assert_eq!(result, vec![11, 12, 15, 16]);

    // Clear 2D array with values
    //  [[  10,  20]
    //   [  30,  40]]
    let clear_array = ClearArray::new(vec![10u32, 20u32, 30u32, 40u32], vec![2, 2]);
    let r = &xss + &clear_array;

    // Result is
    //  [[ 20, 31]
    //   [ 44, 55]]
    let r: Vec<u32> = r.decrypt(&cks);
    assert_eq!(r, vec![20, 31, 44, 55]);
}
```
