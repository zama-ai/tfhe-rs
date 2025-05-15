# Multi-GPU support
This guide explains the multi GPU support of TFHE-rs, and walks through a practical example of performing a large batch of encrypted 64-bit additions using manual GPU 
dispatching to improve the performance.

## Multi-GPU support overview

TFHE-rs supports platforms with multiple GPUs. There is **nothing to change in the code to execute on such platforms**. To keep the API as user-friendly as possible, the configuration is automatically set, i.e., the user has no fine-grained control over the number of GPUs to be used.
However, you can decide to have operations be executed on a single GPU of your choice.
In many cases this provides better throughput than using all the available GPUs to perform the operation.
Indeed, except for integer precisions above 64 bits and for the multiplication, which involves many bootstrap computations in parallel, most operations on up to 64 bits do not necessitate the full power of a GPU.
You will then be able to maximize throughput on multiple GPUs with TFHE-rs.

## Improving throughput on multiple-GPUs

By default, when multiple GPUs are available on the machine, TFHE-rs automatically uses them all
to perform encrypted operations. Under the hood, it includes a hard-coded logic to dispatch work across all the GPUs and to copy essential data—like the server key—to each GPU.
This approach is efficient for operations that load the GPU extensively (e.g. the 64-bit multiplication),
but not so much for smaller operations like the encrypted addition or comparison on 64-bits.
To address this, TFHE-rs also provides a mechanism to manually select which GPU to operate on.

### Dispatch operations on the GPUs of your choice

When selecting a specific GPU to execute on, there are two essential requirements that are different from a default GPU execution:
- You must create a GPU server key on each GPU individually.
- The batch of operations must be distributed on all the GPUs manually.

#### Step 1: Decompress the server key to each GPU
Instead of a single server key being used across all GPUs automatically, you’ll need specifically decompress the server key to each GPU, so that the key is available in memory.
For example, by default, the GPU server key is decompressed and loaded onto all available GPUs automatically as follows:
```rust
use tfhe::{ConfigBuilder, set_server_key, ClientKey, CompressedServerKey};
use tfhe::prelude::*;
use rayon::prelude::*;
fn main() {
    let config = ConfigBuilder::default().build();

    let client_key = ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    let sks = compressed_server_key.decompress_to_gpu();
}
```

However, to use the multi-GPU selection feature, you can create a vector of server keys, each on a specific GPU:

```rust
use tfhe::{ConfigBuilder, set_server_key, ClientKey, CompressedServerKey, GpuIndex};
use tfhe::prelude::*;
use rayon::prelude::*;
use tfhe::core_crypto::gpu::get_number_of_gpus;
fn main() {
    let config = ConfigBuilder::default().build();

    let client_key = ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    let num_gpus = get_number_of_gpus();
    let sks_vec = (0..num_gpus)
        .map(|i| compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i)))
        .collect::<Vec<_>>();
}
```
#### Step 2: Define the inputs to operate on
We will be doing 100 additions in parallel on each GPU:
```rust
use tfhe::{ConfigBuilder, set_server_key, ClientKey, CompressedServerKey, FheUint64, GpuIndex};
use tfhe::prelude::*;
use rayon::prelude::*;
use tfhe::core_crypto::gpu::get_number_of_gpus;
use rand::{rng, Rng};
fn main() {
    let config = ConfigBuilder::default().build();

    let client_key = ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    let num_gpus = get_number_of_gpus();
    let sks_vec = (0..num_gpus)
        .map(|i| compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i)))
        .collect::<Vec<_>>();
    
    let batch_size = num_gpus * 100;

    let mut rng = rng();
    let left_inputs = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.random::<u64>(), &client_key))
        .collect::<Vec<_>>();
    let right_inputs = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.random::<u64>(), &client_key))
        .collect::<Vec<_>>();
}
```
At this stage, the left and right inputs reside on the CPU. They have not yet been copied to the GPU. 

#### Step3: Dispatch the workloads
Now you need to split the calculation into as many chunks as there are GPUs.
TFHE-rs allows you to execute additions in parallel across multiple GPUs by leveraging [CUDA streams](https://developer.nvidia.com/blog/gpu-pro-tip-cuda-7-streams-simplify-concurrency/). 
CUDA stream management is not explicit in the High-Level(HL) API of TFHE-rs: streams are implicitly 
created through calls to `set_server_key` in a CPU thread. 
As a result, when you use `.par_iter()` on encrypted data within the HL API, and that computation is dispatched to a GPU, it behaves as expected—executing in parallel using CUDA streams.
We’ll take advantage of this behavior to maximize throughput on a multi-GPU machine. In the following example, we split a large batch of encrypted 64-bit additions across multiple GPUs. Each GPU processes its own chunk of data in parallel, thanks to the creation of CUDA streams under the hood:
```rust
use tfhe::{ConfigBuilder, set_server_key, ClientKey, CompressedServerKey, FheUint64, GpuIndex};
use tfhe::prelude::*;
use rayon::prelude::*;
use tfhe::core_crypto::gpu::get_number_of_gpus;
use rand::{rng, Rng};
fn main() {
    let config = ConfigBuilder::default().build();

    let client_key = ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    let num_gpus = get_number_of_gpus();
    let sks_vec = (0..num_gpus)
        .map(|i| compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i)))
        .collect::<Vec<_>>();

    let batch_size = num_gpus * 100;

    let mut rng = rng();
    let left_inputs = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.random::<u64>(), &client_key))
        .collect::<Vec<_>>();
    let right_inputs = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.random::<u64>(), &client_key))
        .collect::<Vec<_>>();

    let chunk_size = (batch_size / num_gpus) as usize;
    left_inputs
        .par_chunks(chunk_size)
        .zip(
            right_inputs
                .par_chunks(chunk_size)
        )
        .enumerate()
        .for_each(
            |(i, (left_inputs_on_gpu_i, right_inputs_on_gpu_i))| {
                left_inputs_on_gpu_i
                    .par_iter()
                    .zip(right_inputs_on_gpu_i.par_iter())
                    .for_each(|(left_input, right_input)| {
                        set_server_key(sks_vec[i].clone());
                        let _ = left_input + right_input;
                    });
            },
        );
}
```
In this example, `par_chunks` divides the input vectors into `num_gpus` chunks—one per GPU. Each chunk is then processed in parallel using `.par_iter()`. Inside the inner loop, calling `set_server_key(sks_vec[i].clone())` sets the context for the GPU `i` and implicitly creates a new CUDA stream for GPU `i`. This enables parallel execution on each device.
It’s important to note that, in this example, when using the `+` operator on encrypted inputs, data is first transferred from the CPU to the GPU before computation, the result then resides on the GPU `i`.
You can learn more about how to inspect on which GPU a piece of data resides from the examples in this file: `tfhe/src/high_level_api/tests/gpu_selection.rs`.

### Going beyond: Restrict the number of CUDA streams

While the behavior of `.par_iter()` in TFHE-rs' HL API aligns with expectations and provides parallelism over encrypted data, it can become a performance bottleneck in some cases. This is due to the way CUDA streams are managed.
CUDA streams allow for parallel execution on the GPU, but when too many are created, scheduling becomes inefficient. Instead of running in parallel, operations may fall back to sequential execution. In practice, having more than 10 streams already starts to negatively impact throughput.
To address this, we can limit the number of streams used per GPU. The optimal number depends on the type of operation, but the general rule is: use as few streams as possible while still fully utilizing the GPU.
For example, in the case of 64-bit encrypted additions, using 4 streams per GPU offers a good balance. Each GPU processes inputs in chunks of 4 operations in parallel, repeating this in batches until all inputs are handled.
Here’s how this approach looks in code:
```rust
use tfhe::{ConfigBuilder, set_server_key, ClientKey, CompressedServerKey, FheUint64, GpuIndex};
use tfhe::prelude::*;
use rayon::prelude::*;
use tfhe::core_crypto::gpu::get_number_of_gpus;
use rand::{rng, Rng};

fn main() {

    let config = ConfigBuilder::default().build();

    let client_key= ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    let num_gpus = get_number_of_gpus();
    let sks_vec = (0..num_gpus)
        .map(|i| compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i)))
        .collect::<Vec<_>>();
    let batch_size = num_gpus * 100;

    let mut rng = rng();
    let left_inputs = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.random::<u64>(), &client_key))
        .collect::<Vec<_>>();
    let right_inputs = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.random::<u64>(), &client_key))
        .collect::<Vec<_>>();
    let amounts = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.random::<u64>(), &client_key))
        .collect::<Vec<_>>();

    let chunk_size = (batch_size / num_gpus) as usize;
    let num_streams_per_gpu = 4;
    left_inputs
        .par_chunks(chunk_size)
        .zip(
            right_inputs
                .par_chunks(chunk_size)
                .zip(amounts.par_chunks(chunk_size)),
        )
        .enumerate()
        .for_each(
            |(i, (left_inputs_gpu_i, (right_inputs_gpu_i, amount_gpu_i)))| {
                let stream_chunk_size = left_inputs_gpu_i.len() / num_streams_per_gpu;
                left_inputs_gpu_i
                    .par_chunks(stream_chunk_size)
                    .zip(right_inputs_gpu_i.par_chunks(stream_chunk_size))
                    .zip(amount_gpu_i.par_chunks(stream_chunk_size))
                    .for_each(
                        |((left_inputs_chunk, right_inputs_chunk), amount_chunk)| {
                            set_server_key(sks_vec[i].clone());
                            left_inputs_chunk
                                .iter()
                                .zip(right_inputs_chunk.iter().zip(amount_chunk.iter()))
                                .for_each(|(left_input, (right_input, amount))| {
                                    let _ = left_input + right_input;
                                });
                        },
                    );
            },
        );
}
```
In this version, we:
- Define a number of streams per GPU
- Split the load between the streams by calling `par_chunks()` on the batch assigned to each GPU.
This method provides a more fine-controlled form of parallelism, reaching an optimal performance on multiple GPUs with TFHE-rs.
