# Simple TFHE-rs program

The example shown in this section computes the sum of two integers using the GPU. It  contains code that can be split into a client-side and a server-side part, but for simplicity it is shown as a single snippet. Only the server-side benefits from GPU acceleration.  

This example shows how to use a single GPU to improve operation latency. It has the following structure:

1. _Client-side_: Generate client keys and GPU server keys. Encrypt two numbers 
2. _Server-side_: Move server keys to GPU and perform the addition
3. _Client-side_: Decrypt the result 

This example only performs an addition, but most FHE operations are supported on GPU. For a list see:

{% content-ref url="./gpu-operations.md" %} List of FHE operations on GPU {% endcontent-ref %}

## API elements discussed in this document

- [`tfhe::ConfigBuilder::default()`](https://doc.rust-lang.org/nightly/core/default/trait.Default.html#tymethod.default): Instantiates the default cryptographic parameters. When the `"gpu"` feature is activated, the default parameters are GPU specific, which achieves optimal performance on GPU
- [`tfhe::ServerKey::decompress_to_gpu`](https://docs.rs/tfhe/latest/tfhe/struct.CompressedServerKey.html#method.decompress_to_gpu):  decompresses a compressed ServerKey and copies it to all available GPUs
- [`tfhe::set_server_key`](https://docs.rs/tfhe/latest/tfhe/fn.set_server_key.html): sets the current server key. When this is a GPU key, this function activates execution of integer operations on all GPUs assigned to this key.  

## A simple TFHE-rs program 

```rust
use tfhe::{ConfigBuilder, set_server_key, FheUint8, ClientKey, CompressedServerKey};
use tfhe::prelude::*;

fn main() {

    let config = ConfigBuilder::default().build();

    let client_key= ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    let gpu_key = compressed_server_key.decompress_to_gpu();

    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);

    //Server-side

    set_server_key(gpu_key);
    let result = a + b;

    //Client-side
    let decrypted_result: u8 = result.decrypt(&client_key);

    let clear_result = clear_a + clear_b;

    assert_eq!(decrypted_result, clear_result);
}
```

When the `"gpu"` feature is activated, calling: `let config = ConfigBuilder::default().build();` instantiates [cryptographic parameters that are different from the CPU ones](run-on-gpu.md#gpu-tfhe-rs-features). 

## Breakdown of the GPU TFHE-rs program

### Key generation

Comparing to the [CPU example](../../getting-started/quick-start.md), in the code snippet above,
the server-side must call `decompress_to_gpu` to enable GPU-execution for the ensuing operations on ciphertexts. This function assigns all available GPUs to the server key. 
```Rust
    let gpu_key = compressed_server_key.decompress_to_gpu();
```
Once the key is decompressed to GPU and set with `set_server_key`, operations on ciphertexts execute on the GPU. In the example above:
- `compressed_server_key` is a [`CompressedServerKey`](https://docs.rs/tfhe/latest/tfhe/struct.CompressedServerKey.html), stored on CPU. The client-side should ensure this key is generated with [GPU cryptographic parameters](run-on-gpu.md#gpu-tfhe-rs-features).
- `gpu_key` is the [`CudaServerKey`](https://docs.rs/tfhe/latest/tfhe/struct.CudaServerKey.html) corresponding to `compressed_server_key` and is stored on the GPU assigned to it.
- [`set_server_key`](https://docs.rs/tfhe/latest/tfhe/fn.set_server_key.html) sets either a CPU or GPU key. In this example, `compressed_server_key` and `gpu_key` have GPU cryptographic parameters. A GPU server key can enable automatic parallelization on multiple GPUs.

### Encryption

On the client-side, the method to encrypt the data is exactly the same as the CPU one, as shown in the following example:

```Rust
    let clear_a = 27u8;
    let clear_b = 128u8;
    
    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);
```

### Server-side computation

The server first needs to set up its keys with `set_server_key(gpu_key)`. Then, homomorphic computations are performed using the same approach as the [CPU operations](../../fhe-computation/operations/README.md).

```Rust
    //Server-side
    set_server_key(gpu_key);
    let result = a + b;

    //Client-side
    let decrypted_result: u8 = result.decrypt(&client_key);

    let clear_result = clear_a + clear_b;

    assert_eq!(decrypted_result, clear_result);
```

### Decryption

Finally, the client decrypts the results using:

```Rust
    let decrypted_result: u8 = result.decrypt(&client_key);
```

## Optimizing for throughput

In order to improve operation throughput, you can use multiple GPUs with fine-grained GPU scheduling, as detailed on the following page:

{% content-ref url="./multi_gpu.md" %} Multi-GPU usage {% endcontent-ref %}
