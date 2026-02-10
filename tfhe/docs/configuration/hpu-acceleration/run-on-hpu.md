# HPU acceleration

This guide explains how to update your existing program to leverage HPU acceleration, or to start a new program using HPU.

**TFHE-rs** now supports a HPU backend based on FPGA implementation, enabling integer arithmetic operations on encrypted data.

## Prerequisites

* An [AMD/Xilinx V80 board](https://www.amd.com/en/products/accelerators/alveo/v80.html) installed on a server running Linux with kernel 5.15.0-\*
* A HPU bitstream that you can find (or build) in [HPU fpga repository](https://github.com/zama-ai/hpu_fpga) and load in V80 flash and FPGA using its [README](https://github.com/zama-ai/hpu_fpga/blob/main/README.md)
* AMI linux device driver version from this [fork](https://github.com/zama-ai/AVED)
* QDMA linux device driver version from this [fork](https://github.com/zama-ai/dma_ip_drivers)
* Rust version - check this [page](../rust-configuration.md)

## Importing to your project

To use the **TFHE-rs** HPU backend in your project, add the following dependency in your `Cargo.toml`.

```toml
tfhe = { version = "~1.5.3", features = ["integer", "hpu-v80"] }
```

{% hint style="success" %}
For optimal performance when using **TFHE-rs**, run your code in release mode with the `--release` flag.
{% endhint %}

### Supported platforms

**TFHE-rs** HPU backend is only supported on Linux (x86).

| OS      | x86         | aarch64       |
| ------- | ----------- | ------------- |
| Linux   | Supported   | Unsupported   |
| macOS   | Unsupported | Unsupported   |
| Windows | Unsupported | Unsupported   |

## A first example

### Configuring and creating keys.

Comparing to the [CPU example](../../getting-started/quick-start.md), HPU set up differs in the key creation and device registration, as detailed [here](run-on-hpu.md#setting-the-hpu)

Here is a full example (combining the client and server parts):

```rust
use tfhe::{Config, set_server_key, FheUint8, ClientKey, CompressedServerKey};
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

``` Rust
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

| name                                                                                                                              | symbol          | `Enc`/`Enc`          | `Enc`/ `Int`               |
|-----------------------------------------------------------------------------------------------------------------------------------|-----------------|----------------------|----------------------------|
| [Add](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.add-1)                                                           | `+`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Sub](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.sub-1)                                                           | `-`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Mul](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.mul-1)                                                           | `*`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Div](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.div-1)                                                           | `/`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Rem](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.rem-1)                                                           | `%`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [BitAnd](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.bitand-1)                                                     | `&`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [BitOr](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.bitor-1)                                                       | `\|`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [BitXor](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.bitxor-1)                                                     | `^`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Shr](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.shr-1)                                                           | `>>`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Shl](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.shl-1)                                                           | `<<`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Rotate right](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.rotate_right-3)                                         | `rotate_right`  | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Rotate left](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.rotate_left-3)                                           | `rotate_left`   | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Min](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.min-1)                                                           | `min`           | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Max](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.max-1)                                                           | `max`           | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Greater than](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.gt-2)                                                   | `gt`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Greater or equal than](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.ge-2)                                          | `ge`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Lower than](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.lt-2)                                                     | `lt`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Lower or equal than](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.le-2)                                            | `le`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Equal](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.eq-2)                                                          | `eq`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Not Equal](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.ne-2)                                                      | `ne`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Ternary operator](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.select)                                             | `select`        | :heavy\_check\_mark: | :heavy\_multiplication\_x: |
| [Integer logarithm](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.ilog2)                                             | `ilog2`         | :heavy\_check\_mark: | N/A                        |
| [Count trailing/leading ones](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.leading_ones)                            | `leading_zeros` | :heavy\_check\_mark: | N/A                        |
| [Count trailing/leading zeros](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.leading_zeros)                          | `leading_ones`  | :heavy\_check\_mark: | N/A                        |

{% hint style="info" %}
All operations follow the same syntax than the one described in [here](../../fhe-computation/operations/README.md).
{% endhint %}
