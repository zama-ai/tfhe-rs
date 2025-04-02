# Tfhe-hpu-backend

## Brief
The `tfhe-hpu-backend` holds the code for the HPU acceleration of Zama's variant of TFHE.
It contains a `HpuDevice` abstraction that enables easy configuration and dispatching of TFHE operations on the HPU accelerator.

The user API exposes the following functions for hardware setup:
- `HpuDevice::new`, `HpuDevice::from_config`: Instantiate abstraction device from configuration file.
- `HpuDevice::init`: Configure and upload the required public material.
- `new_var_from`: Create a HPU ciphertext from `tfhe-rs` ciphertext.

HPU variables could also be created from a `high-level-api` object, with the help of the `hw-xfer` feature.
This implements a trait that enables `clone_on`, `mv_on` `FheUint` object on the HPU accelerator, and cast back `from` them.

These objects implement the `std::ops` trait and could be used to dispatch operations on HPU hardware.

### Backend structure
`tfhe-hpu-backend` is split in various modules:
- `entities`: Define structure handled by HPU accelerator. Conversion traits from/into those objects are implemented in `tfhe-rs`.
- `asm`: Describe assembly-like language for the HPU. It enables abstract HPU behavior and easily updates it through micro-code.
- `fw`: Abstraction to help the micro-code designer. Use a simple rust program for describing new HPU operations. Help with register/heap management.
- `interface`:
  + `device`: High-level structure that exposes the User API.
  + `backend`: Inner private structure that contains HPU modules
  + `variable`: Wrap HPU ciphertexts. It enables to hook an hardware object lifetime within the `rust` borrow-checker.
  + `memory`: Handle on-board memory allocation and synchronization
  + `config`: Help to configure HPU accelerator through a TOML configuration file
  + `cmd`: Translate operation over `variable` in concrete HPU commands
  + `regmap`: Communicate with the HPU internal register with ease.
  + `rtl`: Define concrete `rust` structure populated from HPU's status/configuration registers


Below is an overview of the internal structure of the Backend.
![HPU backend structure](./figures/tfhe-hpu-backend.excalidraw.png)

This picture depicts the internal modules of `tfhe-hpu-backend`, Device is the main entry point for the user. Its lifecycle is as follows:

1. Create HpuDevice, open link with the associated FPGA. Configure associated drivers and upload the bitstream. Read FPGA registers to extract supported configuration and features. Build Firmware conversion table (IOp -> DOps stream).

2. Allocate required memory chunks in the on-board memory. Upload public material required by TFHE computation.

3. Create HPU variables that handle TFHE Ciphertexts. It wraps TFHE Ciphertext with required internal resources and enforces the correct lifetime management. This abstraction enforces that during the variable lifecycle all required resources are valid.

4. Users could trigger HPU operation from the HPU variable.
  Variable abstraction enforces that required objects are correctly synced on the hardware and converts each operation in a concrete HPU command.
  When HPU operation is acknowledged by the hardware, the internal state of the associated variable is updated.
  This mechanism enables asynchronous operation and minimal amount of Host to/from HW memory transfer.
  This mechanism also enables offloading a computation graph to the HPU and requires a synchronization only on the final results.

## Example
### Configuration file
HPU configuration knobs are gathered in a TOML configuration file. This file describes the targeted FPGA with its associated configuration:
```toml
[fpga] # FPGA target
  # Register layout in the FPGA
  regmap="backends/tfhe-hpu-backend/config/hpu_regif_core.toml"
  polling_us=10
[fpga.ffi.Xrt] # Hardware properties
  id= 0 # ID of the used FPGA
  kernel= "hpu_3parts_1in3" # Name of the entry point kernel
  xclbin="backends/tfhe-hpu-backend/config/hpu_3parts.xclbin" # Path to the FPGA bitstream file

[rtl] # RTL option
  bpip_used = true # BPIP/IPIP mode
  bpip_timeout = 100_000 # BPIP timeout in clock `cycles`

[board] # Board configuration
  ct_bank = [4096, 0, 0, 4096] # Allocated Ciphertext in various bank
  ct_pc = [10, 11] # HBM pc connected to Ciphertext memory

  lut_bank = 256 # Number of LUT allocated
  lut_pc = 12 # HBM pc connected to LUT table

  fw_size= 65536 # Size in byte of the Firmware translation table
  fw_pc = 1 # HBM pc used by the firmware

  bsk_pc = [ 2, 3, 4, 5, 6, 7, 8, 9] # HBM pc used by the bootstrapping key
  ksk_pc = [24,25,26,27,28,29,30,31] # HBM pc used by the keyswitching key

[firmware] # Firmware properties
  integer_w=[16] # List of supported IOP width
  pbs_w=8 # PBS batch width used for firmware generation
  # List of custom IOP definition files
  custom_iop.CUST_0 = "backends/tfhe-hpu-backend/config/custom_iop/cust_0.asm"
  ```

### Device setup
Following code snippet shows how to instantiate and configure a `HpuDevice`:
```rust
    // Instantiate HpuDevice --------------------------------------------------
    let hpu_device = HpuDevice::from_config("backends/tfhe-hpu-backend/config/hpu_config.toml");

    // Extract pbs_configuration from Hpu and generate top-level config
    let pbs_params = tfhe::shortint::PBSParameters::PBS(hpu_device.params().into());
    let config = ConfigBuilder::default()
        .use_custom_parameters(pbs_params)
        .build();

    // Generate Keys
    let (cks, sks) = generate_keys(config);
    let sks_compressed = cks.generate_compressed_server_key();

    // Init cpu side server keys
    set_server_key(sks);

    // Init Hpu device with server key and firmware
    let (integer_sks_compressed, ..) = sks_compressed.into_raw_parts();
    tfhe::integer::hpu::init_device(&hpu_device, integer_sks_compressed);
```

### Clone CPU ciphertext on HPU
Following code snippet shows how to convert CPU ciphertext in HPU one:
``` rust
    // Draw random value as input
    let a = rand::thread_rng().gen_range(0..u8::MAX);

    // Encrypt them on Cpu side
    let a_fhe = FheUint8::encrypt(a, &cks);

    // Clone a ciphertext and move them in HpuWorld
    // NB: Data doesn't move over Pcie at this stage
    //     Data are only arranged in Hpu ordered an copy in the host internal buffer
    let a_hpu = a_fhe.clone_on(&hpu_device);
```

### Dispatch operation on HPU
HPU variables implement the `std::ops` trait. These functions dispatch the operation on the HPU device.
Following code snippets show how to start operation on HPU from Hpu variables:

``` rust
  // NB: a_hpu, b_hpu are HpuFheUint created from FheUint
  // Compute a * b on Hpu
  // Results are stored in `axb_hpu`. Result is kept on HPU, axb_hpu is only the image of the result (i.e. No PCIe xfer at this stage)
  let axb_hpu = a_hpu * b_hpu;

  // Dispatch operation with low-level interface
  // Enable to dispatch operation directly based on IOp name
  // For ct x constant operations
  let iop_imm_res = a_hpu.iop_imm(iop_name, b as usize);
  // For ct x ct operations
  let iop_imm_res = a_hpu.iop_ct(iop_name, b_hpu);
```

### Retrieved result in CPU world
The exposed API enables to only sync back the required value.
This enables the user to offload a sub-computation graph without the cost of syncing intermediate values.

Following code snippet starts two operation on HPU and shows how to sync only the required result:
```rust
  // NB: a_hpu, b_hpu, c_hpu are HpuFheUint created from FheUint
  let axb_hpu = a_hpu * b_hpu;
  let axb_c_hpu = axb_hpu ^ c_hpu;

  // Retrieved result in CPU world
  // Pay the xfer cost for last result only
  let axb_c_hpu = FheUint8::from(axb_c_hpu);
```

## Pre-made Examples
There are some example application already available in tfhe:
 * hpu_Xb: Benchmark application where `X` could be within [8,16,32,64]. Used to extract IOp performances
 * hpu_mixed: Showcase of mixing CPU/HPU operation with the help of HpuFheUint abstraction
 * hpu_gtv: Used with hpu_mockup to generate RTL stimulus. Multiple IOp width is backed in the same binary

In order to run those applications on hardware, user must build from the project root (i.e `tfhe-rs-internal`) with `hw-xrt` and `hpu-xfer` features:
```
cargo build --release --features="hpu-xfer,hw-xrt" --examples
./target/release/hpu_64b --iop MUL --iter 10
```

## Test framework
There is also a set of tests backed in tfhe-rs. One for each IOp width in [8,16,32,64].
Those tests have 3 sub-kind:
* `alu`: Run and check all ct x ct IOp
* `bitwise`: Run and check all bitwise IOp
* `cmp`: Run and check all comparison IOp

>NB: Like the premade examples, those tests must be run from the project root.

Snippets below give some example of command that could be used for testing:
```
# Run all sub-kind for 64b IOp
cargo test --release --features="hw-xrt,hpu-xfer" --test hpu_64b

# Run only `alu` sub-kind for 16b IOp
cargo test --release --features="hw-xrt,hpu-xfer" --test hpu_16 -- alu
```

