# Array types
This document explains how to use array types on GPU, just as [on CPU](../../fhe-computation/types/array.md).

Array types perform array and tensor operations on encrypted data, encapsulating the logic for iteration over array elements and array shape logic.

## API elements discussed in this document

- [`GpuFheUint32Array`](https://docs.rs/tfhe/latest/tfhe/array/type.GpuFheUint32Array.html): an n-d array of Uint32 encrypted values. Variants are available for all supported integer types and booleans.

## Array types example

```rust
use tfhe::{ConfigBuilder, set_server_key, ClearArray, ClientKey, CompressedServerKey};
use tfhe::array::GpuFheUint32Array;
use tfhe::prelude::*;

fn main() {
    let config = ConfigBuilder::default().build();

    let cks = ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&cks);

    let gpu_key = compressed_server_key.decompress_to_gpu();
    set_server_key(gpu_key);

    let num_elems = 4 * 4;
    let clear_xs = (0..num_elems as u32).collect::<Vec<_>>();
    let clear_ys = vec![1u32; num_elems];

    // Encrypted 2D array with values
    // [[  0,  1,  2,  3]
    //  [  4,  5,  6,  7]
    //  [  8,  9, 10, 11]
    //  [ 12, 13, 14, 15]]
    let xs = GpuFheUint32Array::try_encrypt((clear_xs.as_slice(), vec![4, 4]), &cks).unwrap();
    // Encrypted 2D array with values
    // [[  1,  1,  1,  1]
    //  [  1,  1,  1,  1]
    //  [  1,  1,  1,  1]
    //  [  1,  1,  1,  1]]
    let ys = GpuFheUint32Array::try_encrypt((clear_ys.as_slice(), vec![4, 4]), &cks).unwrap();

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
