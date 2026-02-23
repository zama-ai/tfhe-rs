# TFHE-hpu-backend

## Brief
The `tfhe-hpu-backend` holds the code to interface with the HPU accelerator of TFHE.
It contains a `HpuDevice` abstraction that enables easy configuration and dispatching of TFHE operations on the HPU accelerator.

The user API exposes the following functions for hardware setup:
- `HpuDevice::new`, `HpuDevice::from_config`: Instantiates abstraction device from configuration file.
- `HpuDevice::init`: Configures and uploads the required public material.
- `new_var_from`: Creates a HPU ciphertext from `tfhe-rs` ciphertext.

HPU device could also be used from `integer` with the help of the following function:
- `tfhe::integer::hpu::init_device`: Init given HPU device with server key.
- `tfhe::integer::hpu::ciphertext::HpuRadixCiphertext::from_radix_ciphertext`: Convert a CpuRadixCiphertext in it's HPU counterpart.
 
HPU device could also be used seamlessly from `hl-api` by setting up a thread-local HPU server key:
- `tfhe::Config::from_hpu_device`: Extract hl-api configuration from HpuDevice.
- `tfhe::set_server_key`: Register the Hpu server key in the current thread.

HPU variables could also be created from a `high-level-api` object, with the help of the `hw-xfer` feature.
This implements a trait that enables `clone_on`, `mv_on` `FheUint` object on the HPU accelerator, and cast back `from` them.

These objects implement the `std::ops` trait and could be used to dispatch operations on HPU hardware.

### Backend structure
`tfhe-hpu-backend` is split in various modules:
- `entities`: Defines structure handled by HPU accelerator. Conversion traits from/into those objects are implemented in `tfhe-rs`.
- `asm`: Describes assembly-like language for the HPU. It enables abstract HPU behavior and easily updates it through micro-code.
- `fw`: Abstraction to help the micro-code designer. Uses a simple rust program for describing new HPU operations. Helps with register/heap management.
- `interface`:
  + `device`: High-level structure that exposes the User API.
  + `backend`: Inner private structure that contains HPU modules
  + `variable`: Wraps HPU ciphertexts. It enables to hook an hardware object lifetime within the `rust` borrow-checker.
  + `memory`: Handles on-board memory allocation and synchronization
  + `config`: Helps to configure HPU accelerator through a TOML configuration file
  + `cmd`: Translates operation over `variable` in concrete HPU commands
  + `regmap`: Communicates with the HPU internal register with ease.
  + `rtl`: Defines concrete `rust` structure populated from HPU's status/configuration registers


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
  regmap=["${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_regif_core_cfg_1in3.toml",
          "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_regif_core_cfg_3in3.toml",
          "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_regif_core_prc_1in3.toml",
          "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_regif_core_prc_3in3.toml"]
  polling_us=2
[fpga.ffi.V80] # Hardware properties
  id="${V80_PCIE_DEV}"
  board_sn="${V80_SERIAL_NUMBER}"
  hpu_path="${HPU_BACKEND_DIR}/config_store/v80_archives/psi64.hpu"
  ami_path="${AMI_PATH}/ami.ko"
  qdma_h2c="/dev/qdma${V80_PCIE_DEV}001-MM-0" # QDma host to card device
  qdma_c2h="/dev/qdma${V80_PCIE_DEV}001-MM-1" # QDma card to host device

[rtl] # RTL option
  bpip_used = true # BPIP/IPIP mode
  bpip_use_opportunism = false # Use strict flush paradigm
  bpip_timeout = 100_000 # BPIP timeout in clock `cycles`

[board] # Board configuration
  ct_mem = 32768 # Number of allocated ciphertext
  ct_pc = [ # Memory used for ciphertext
    {Hbm= {pc=32}},
    {Hbm= {pc=33}},
  ]
  heap_size = 16384 # Number of slots reserved for heap

  lut_mem = 256 # Number of allocated LUT table
  lut_pc = {Hbm={pc=34}} # Memory used for LUT

  fw_size= 16777216 # Size in byte of the Firmware translation table
  fw_pc = {Ddr= {offset= 0x3900_0000}} # Memory used for firmware translation table

  bsk_pc = [ # Memory used for Bootstrapping key
    {Hbm={pc=8}},
    {Hbm={pc=12}},
    {Hbm={pc=24}},
    {Hbm={pc=28}},
    {Hbm={pc=40}},
    {Hbm={pc=44}},
    {Hbm={pc=56}},
    {Hbm={pc=60}}
  ]

  ksk_pc = [ # Memory used for Keyswitching key
    {Hbm={pc=0}},
    {Hbm={pc=1}},
    {Hbm={pc=2}},
    {Hbm={pc=3}},
    {Hbm={pc=4}},
    {Hbm={pc=5}},
    {Hbm={pc=6}},
    {Hbm={pc=7}},
    {Hbm={pc=16}},
    {Hbm={pc=17}},
    {Hbm={pc=18}},
    {Hbm={pc=19}},
    {Hbm={pc=20}},
    {Hbm={pc=21}},
    {Hbm={pc=22}},
    {Hbm={pc=23}}
  ]

  trace_pc = {Hbm={pc=35}} # Memory used for trace log
  trace_depth = 32 # Size of Memory in MiB allocated for trace log

[firmware] # Firmware properties
  implementation = "Llt" # Firmware flavor to use
  integer_w=[4,6,8,10,12,14,16,32,64,128] # List of supported IOp width
  min_batch_size = 11 # Minimum batch size for maximum throughput
  kogge_cfg            = "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/kogge_cfg.toml"
  custom_iop.'IOP[0]'  = "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/custom_iop/cust_0.asm"

# Default firmware configuration. Could be edited on per-IOp basis
[firmware.op_cfg.default]
  fill_batch_fifo = true
  min_batch_size = false
  use_tiers = false
  flush_behaviour = "Patient"
  flush = true
  ```

### Device setup
Following code snippet shows how to instantiate and configure a `HpuDevice`:
```rust
    // Following code snippets used the HighLevelApi abstraction
    // Instantiate HpuDevice --------------------------------------------------
    let hpu_device = HpuDevice::from_config(&args.config.expand());

    // Generate keys ----------------------------------------------------------
    let config = Config::from_hpu_device(&hpu_device);

    let cks = ClientKey::generate(config);
    let csks = CompressedServerKey::new(&cks);

    // Register HpuDevice and key as thread-local engine
    set_server_key((hpu_device, csks));
```

### Clone CPU ciphertext on HPU
Following code snippet shows how to convert CPU ciphertext in HPU one:
``` rust
    // Draw random value as input
    let a = rand::rng().gen_range(0..u8::MAX);

    // Encrypt them on Cpu side
    let a_fhe = FheUint8::encrypt(a, &cks);

    // Clone a ciphertext and move them in HpuWorld
    // NB: Data doesn't move over Pcie at this stage
    //     Data are only arranged in Hpu ordered an copy in the host internal buffer
    let a_hpu = a_fhe.clone_on(&hpu_device);
```

### Dispatch operation on HPU
Once registered as thread-local engine, HighLevel FheUint are converted in Hpu format.
Following code snippets show how to start operation on HPU:

``` rust
  // Sum -------------------------------------------------------------
  // Generate random inputs value and compute expected result
  let in_a = rng.gen_range(0..u64::max_value());
  let in_b = rng.gen_range(0..u64::max_value());
  let clear_sum_ab = in_a.wrapping_add(in_b);

  // Encrypt input value
  let fhe_a = FheUint64::encrypt(in_a, cks);
  let fhe_b = FheUint64::encrypt(in_b, cks);

  // Triggered operation on HPU through hl_api
  let fhe_sum_ab = fhe_a+fhe_b;

  // Decrypt values
  let dec_sum_ab: u64 = fhe_sum_ab.decrypt(cks);
```

## Pre-made Examples
There are some example applications already available in `tfhe/examples/hpu`:
 * hpu_hlapi: Depict the used of HPU device through HighLevelApi.
 * hpu_bench: Depict the used of HPU device through Integer abstraction level.

In order to run those applications on hardware, user must build from the project root (i.e `tfhe-rs`) with `hpu-v80` features:

> NB: Running examples required to have correctly pulled the `.hpu` files. Those files, due to their size, are backed by git-lfs and disabled by default.
> In order to retrieve them, run the following command from **TFHE-rs** root folder:
> ```bash
> make pull_hpu_files
> ```

``` bash
$ cargo build --release --features="hpu-v80" --example hpu_hlapi --example hpu_bench
# Correctly setup environment with setup_hpu.sh script
$ source setup_hpu.sh --config v80 -p
# Source Xilinx environment (2024 or 2025 version)
$ source /opt/xilinx/Vivado/2024.2/settings64.sh
$ xsdb -eval "connect;puts [lsort -unique [regex -all -inline {( XFL[A-Z0-9]*)} [targets -target-properties]]]"
****** Xilinx hw_server v2024.2
  **** Build date : Oct 29 2024 at 10:16:47
    ** Copyright 1986-2022 Xilinx, Inc. All Rights Reserved.
    ** Copyright 2022-2024 Advanced Micro Devices, Inc. All Rights Reserved.

INFO: hw_server application started
INFO: Use Ctrl-C to exit hw_server application

INFO: To connect to this hw_server instance use url: TCP:127.0.0.1:3121

{ XFL12E5XJHWLA}
$ export V80_SERIAL_NUMBER=XFL12E5XJHWL
$ ./target/release/examples/hpu_bench --integer-w 64 --integer-w 32 --iop MUL --iter 10
$ ./target/release/examples/hpu_hlapi
```

> NB: Error that occurred when ".hpu" files weren't correctly fetch could be a bit enigmatic: `memory allocation of ... bytes failed`
> If you encountered this issue, you should run the following command:
> ```bash
> make pull_hpu_files
> ```

> NB: tfhe-hpu-backend can only use one V80 board at this time but if you have several boards on your server you can do
> ```bash
> $ . setup_hpu.sh --config v80 -p
> getopt: option requires an argument -- 'p'
> Please select a device in following list (1st two digits):
> 24:00.1 Processing accelerators: Xilinx Corporation Device 50b5
> 61:00.1 Processing accelerators: Xilinx Corporation Device 50b5
> $ . setup_hpu.sh --config v80 -p 61
> $ source /opt/xilinx/Vivado/2024.2/settings64.sh
> # if AMI driver is loaded and AMC version running is the expected one
> $ cat /sys/module/ami/drivers/pci\:ami/0000\:61\:00.0/board_serial
> XFL1UKRD42KW
> # list serial number available on USB JTAG
> $ xsdb -eval "connect;puts [lsort -unique [regex -all -inline {( XFL[A-Z0-9]*)} [targets -target-properties]]]"
> ...
> { XFL12E5XJHWLA} { XFL1UKRD42KWA}
> $ export V80_SERIAL_NUMBER=XFL1UKRD42KW
> $ ./target/release/examples/hpu_hlapi
> ```

> NB: By default setup_hpu.sh will set AMI_PATH to something like /opt/v80/ami/e55d02d where e55d02d is the git revision of AMI driver.
> To run properly, You need to either place a compiled ami.ko from this revision in this directory or set AMI_PATH to your AVED extraction:
> ```bash
> export AMI_PATH=/home/user/AVED/sw/AMI/driver/
> ```

## Test framework
There is also a set of tests backed in tfhe-rs. Tests are gather in testbundle over various integer width.
Those tests have 5 sub-kind:
* `alu`: Run and check all ct x ct IOp
* `alus`: Run and check all ct x scalar IOp
* `bitwise`: Run and check all bitwise IOp
* `cmp`: Run and check all comparison IOp
* `ternary`: Run and check ternary operation
* `algo`: Run and check IOp dedicated to offload small algorithms


Snippets below give some example of command that could be used for testing:
``` bash
# Correctly setup environment with setup_hpu.sh script
source setup_hpu.sh --config v80 -p

# Run all sub-kind for 64b integer width
cargo test --release --features="hpu-v80" --test hpu -- u64

# Run only `bitwise` sub-kind for all integer width IOp
cargo test --release --features="hpu-v80" --test hpu -- bitwise
```

## Benches framework
HPU is completely integrated in tfhe benchmark system. Performances results could be extracted from HighLevelApi or Integer Api.
Three benchmarks could be started, through the following Makefile target for simplicity:
``` bash
# Do not forget to correctly set environment before hand
source setup_hpu.sh --config v80 -p

# Run hlapi benches
make test_high_level_api_hpu

# Run hlapi erc20 benches
make bench_hlapi_erc20_hpu 

# Run integer level benches
make bench_integer_hpu
```

## Eager to start without real Hardware ?
You are still waiting your FPGA board and are frustrated by lead time ?
Don't worry, you have backed-up. A dedicated simulation infrastructure with accurate performance estimation is available in tfhe-rs.
You can use it on any linux/MacOs to test HPU integration within tfhe-rs and optimized your application for HPU target.
Simply through an eye to [Hpu mockup](../../mockups/tfhe-hpu-mockup/README.md), and follow the instruction.
