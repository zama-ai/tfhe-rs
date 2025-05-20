# HPU acceleration

This guide explains how to update your existing program to leverage HPU acceleration, or to start a new program using HPU.

**TFHE-rs** now supports a HPU backend based on FPGA implementation, enabling integer arithmetic operations on encrypted data.

## Prerequisites

* An [AMD/Xilinx V80 board](https://www.amd.com/en/products/accelerators/alveo/v80.html) installed on a server running Linux with kernel 5.15.0-\*
* A HPU bitstream that you can find (or build) in [HPU fpga repository](https://github.com/zama-ai/hpu_fpga) and load in V80 flash and FPGA using its [README](https://github.com/zama-ai/hpu_fpga/README.md)
* AMI linux device driver version from this [fork](https://github.com/zama-ai/AVED)
* QDMA linux device driver version from this [fork](https://github.com/zama-ai/dma_ip_drivers)
* Rust version - check this [page](../rust_configuration.md)

## Importing to your project

To use the **TFHE-rs** HPU backend in your project, add the following dependency in your `Cargo.toml`.

```toml
tfhe = { version = "~1.2.0", features = ["integer", "hpu-v80"] }
```

{% hint style="success" %}
For optimal performance when using **TFHE-rs**, run your code in release mode with the `--release` flag.
{% endhint %}

### Supported platforms

**TFHE-rs** HPU backend is supported on Linux (x86, aarch64).

| OS      | x86         | aarch64       |
| ------- | ----------- | ------------- |
| Linux   | Supported   | Unsupported   |
| macOS   | Unsupported | Unsupported   |
| Windows | Unsupported | Unsupported   |

## A first example

### Configuring and creating keys.

Comparing to the [CPU example](../../getting_started/quick_start.md), HPU set up differs in the key creation and device registration, as detailed [here](run\_on\_hpu.md#setting-the-hpu)

Here is a full example (combining the client and server parts):

```rust
use tfhe::{ConfigBuilder, set_server_key, FheUint8, ClientKey, CompressedServerKey};
use tfhe::prelude::*;
use tfhe::tfhe_hpu_backend::prelude::*;

fn main() {

    // Instantiate HpuDevice --------------------------------------------------
    // HPU configuration knobs are retrieved from a TOML configuration file. Prebuilt configurations could be find in `backends/tfhe-hpu-backend/config_store`
    // For ease of use a setup_hpu.sh script is available in repository root folder and it handle the required environment variables setup and driver initialisation
    // More details are available in `backends/tfhe-hpu-backend/README.md`
    let hpu_device = HpuDevice::from_config(ShellString::new("${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml".to_string()).expand().as_str());

    // Generate keys ----------------------------------------------------------
    let config = Config::from_hpu_device(&hpu_device);

    let client_key = ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);

    // Register HpuDevice and key as thread-local engine
    set_server_key((hpu_device, compressed_server_key));

    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);

    // Server-side computation
    let result = a + b;

    // Client-side
    let decrypted_result: u8 = result.decrypt(&client_key);

    let clear_result = clear_a + clear_b;

    assert_eq!(decrypted_result, clear_result);
}
```

### Setting the hpu

An HPU device is built for a given parameter set. At this point, because HPU is still a prototype, the software provided is retrieving this parameter set from an instantiated HpuDevice. Once retrieved, reading some HPU registers, this parameter set is used by the example applications to generate both client and compressed server keys.
Server key has then to be decompressed by the server to be converted into the right format and uploaded to the device.
Once decompressed, the operations between CPU and HPU are identical.

### Encryption

On the client-side, the method to encrypt the data is exactly the same than the CPU one, as shown in the following example:

```Rust
    let clear_a = 27u8;
    let clear_b = 128u8;
    
    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);
```

### Computation

The server first needs to set up its keys with `set_server_key((hpu_device, compressed_server_key))`.

Then, homomorphic computations are performed using the same approach as the [CPU operations](../../fhe-computation/operations/README.md).

``` rust
    // Server-side
    let result = a + b;

    //Client-side
    let decrypted_result: u8 = result.decrypt(&client_key);

    let clear_result = clear_a + clear_b;

    assert_eq!(decrypted_result, clear_result);
```

### Decryption

Finally, the client decrypts the result using:

```Rust
    let decrypted_result: u8 = result.decrypt(&client_key);
```

## List of available operations

The HPU backend includes the following operations for unsigned encrypted integers:

| name                  | symbol         | `Enc`/`Enc`                | `Enc`/ `Int`               |
| --------------------- | -------------- | -------------------------- | -------------------------- |
| Add                   | `+`            | :heavy\_check\_mark:       | :heavy\_check\_mark:       |
| Sub                   | `-`            | :heavy\_check\_mark:       | :heavy\_check\_mark:       |
| Mul                   | `*`            | :heavy\_check\_mark:       | :heavy\_check\_mark:       |
| BitAnd                | `&`            | :heavy\_check\_mark:       | :heavy\_check\_mark:       |
| BitOr                 | `\|`           | :heavy\_check\_mark:       | :heavy\_check\_mark:       |
| BitXor                | `^`            | :heavy\_check\_mark:       | :heavy\_check\_mark:       |
| Greater than          | `gt`           | :heavy\_check\_mark:       | :heavy\_check\_mark:       |
| Greater or equal than | `ge`           | :heavy\_check\_mark:       | :heavy\_check\_mark:       |
| Lower than            | `lt`           | :heavy\_check\_mark:       | :heavy\_check\_mark:       |
| Lower or equal than   | `le`           | :heavy\_check\_mark:       | :heavy\_check\_mark:       |
| Equal                 | `eq`           | :heavy\_check\_mark:       | :heavy\_check\_mark:       |
| Ternary operator      | `select`       | :heavy\_check\_mark:       | :heavy\_check\_mark:       |

{% hint style="info" %}
All operations follow the same syntax than the one described in [here](../../fhe-computation/operations/README.md).
{% endhint %}
