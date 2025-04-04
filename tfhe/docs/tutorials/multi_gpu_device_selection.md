# Improving throughput on multiple-GPUs

By default, when multiple GPUs are available on the machine TFHE-rs automatically uses them all
to perform encrypted operations. Under the hood, it has a hard-coded logic for how
to dispatch work onto all the GPUs, and it also automatically copies the necessary data (like the server key) to all GPUs.
This approach is efficient for operations that load the GPU extensively (e.g. the 64-bit multiplication),
but not so much for smaller operations like the encrypted addition or comparison on 64-bits.
This is why it is also possible to select which GPU to operate on.
In this tutorial, an example of execution of a large batch of additions of encrypted 64-bit integers is described.

## Dispatch operations on the GPUs of your choice

Compared to a default GPU execution with TFHE-rs, two things change when selecting a specific GPU to execute on:
- it is necessary to create a GPU server key on each GPU specifically,
- the batch of operations has to be distributed on all the GPUs manually.

Let's see this in practice. First of all, the GPU server key has to be specifically decompressed to each GPU, so that
it is available in memory on all of them. Normally, one would write: 

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

Instead, we can create a vector of server keys, each on a specific GPU:

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

Now, let's define some inputs to operate on. We will be doing 100 additions in parallel on each GPU:
```rust
use tfhe::{ConfigBuilder, set_server_key, ClientKey, CompressedServerKey, FheUint64, GpuIndex};
use tfhe::prelude::*;
use rayon::prelude::*;
use tfhe::core_crypto::gpu::get_number_of_gpus;
use rand::{thread_rng, Rng};
fn main() {
    let config = ConfigBuilder::default().build();

    let client_key = ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    let num_gpus = get_number_of_gpus();
    let sks_vec = (0..num_gpus)
        .map(|i| compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i)))
        .collect::<Vec<_>>();
    
    let batch_size = num_gpus * 100;

    let mut rng = thread_rng();
    let left_inputs = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.gen::<u64>(), &client_key))
        .collect::<Vec<_>>();
    let right_inputs = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.gen::<u64>(), &client_key))
        .collect::<Vec<_>>();
}
```
At this stage, the left and right inputs reside on the CPU. They have not yet been copied to the GPU. 
Now to the second stage: let's split the calculation into as many chunks as there are GPUs. 
It is possible to execute additions in parallel over each GPU, thanks to the use of 
[Cuda streams](https://developer.nvidia.com/blog/gpu-pro-tip-cuda-7-streams-simplify-concurrency/). 
The creation of Cuda streams is not explicit when using TFHE-rs' HL API, but it's hidden in the calls to 
`set_server_key`. In this way, when calling `par_iter()` on a variable in the HL API, if the execution happens on GPU
it has the behavior that one would expect from `par_iter()`.
This is what we'll use to get the best possible throughput on a multi-GPU machine. Here's the code to create chunks of
data to operate on for each GPU, then to call additions on each chunk in parallel, thanks to the (hidden) use of 
Cuda streams:
```rust
use tfhe::{ConfigBuilder, set_server_key, ClientKey, CompressedServerKey, FheUint64, GpuIndex};
use tfhe::prelude::*;
use rayon::prelude::*;
use tfhe::core_crypto::gpu::get_number_of_gpus;
use rand::{thread_rng, Rng};
fn main() {
    let config = ConfigBuilder::default().build();

    let client_key = ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    let num_gpus = get_number_of_gpus();
    let sks_vec = (0..num_gpus)
        .map(|i| compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i)))
        .collect::<Vec<_>>();

    let batch_size = num_gpus * 100;

    let mut rng = thread_rng();
    let left_inputs = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.gen::<u64>(), &client_key))
        .collect::<Vec<_>>();
    let right_inputs = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.gen::<u64>(), &client_key))
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
By using `par_chunks`, with a chunk size of `batch_size / num_gpus`, we split the calculation over the different GPUs.
Calling `par_iter` on each chunk allows to perform the addition in parallel on each GPU, thanks to the call to:
`set_server_key(sks_vec[i].clone())`. This function creates a new Cuda stream on the GPU `i`, in order to 
have parallel execution on that GPU. It is worth noting that in this example, when calling `+` on the encrypted inputs,
data is transferred from the CPU to the GPU before computation. The result is data residing on GPU `i`. 
You can check on which device data resides in TFHE-rs by following the examples in this file: 
`tfhe/src/high_level_api/tests/gpu_selection.rs`.

## Going beyond, by restricting the number of Cuda streams

The behavior of `par_iter()` in the HL API of TFHE-rs corresponds to what one expects,
but it actually has a downside for performance. Indeed, one limitation of the Cuda streams is that they become
hard to schedule when there are many of them, and calculations end up being done sequentially if there are too many.
Already with 100 streams per GPU this is restricting the throughput. Instead, we can go beyond the
example above by defining a number of streams to be used per GPU. This number depends on the functions to be 
executed, but generally speaking it is good to keep the number of streams as low as possible while loading the GPUs as 
much as possible. For the 64-bit addition, we can use 4 streams per GPU: this means that during the execution, on each GPU we 
will launch batches of 4 additions in parallel, as many times as necessary to treat all inputs. This can be written as follows:
```rust
use tfhe::{ConfigBuilder, set_server_key, ClientKey, CompressedServerKey, FheUint64, GpuIndex};
use tfhe::prelude::*;
use rayon::prelude::*;
use tfhe::core_crypto::gpu::get_number_of_gpus;
use rand::{thread_rng, Rng};

fn main() {

    let config = ConfigBuilder::default().build();

    let client_key= ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    let num_gpus = get_number_of_gpus();
    let sks_vec = (0..num_gpus)
        .map(|i| compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i)))
        .collect::<Vec<_>>();
    let batch_size = num_gpus * 100;

    let mut rng = thread_rng();
    let left_inputs = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.gen::<u64>(), &client_key))
        .collect::<Vec<_>>();
    let right_inputs = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.gen::<u64>(), &client_key))
        .collect::<Vec<_>>();
    let amounts = (0..batch_size)
        .map(|_| FheUint64::encrypt(rng.gen::<u64>(), &client_key))
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
Compared to the example of the previous section, here we define a number of streams per GPU, then
call `par_chunks()` of the batch of inputs of each GPU to split the load between the streams. In this way
it is possible to reach optimal performance on multiple GPUs with TFHE-rs.
