# Tfhe-hpu-mockup

## Brief 
Simulation _drop-in-replacement_ implementation of HPU Hardware.
This mockup implementation could be paired seamlessly with `tfhe-hpu-backend` compiled without any hardware support (i.e. `hpu-xrt`).
Indeed, without hardware support, `tfhe-hpu-backend` call to low-level FFI are replaced by IPC call and could be intercepted by this mockup implementation.

Objectives of this mockup are as follows:
* Transparent integration with User application:
> User must have nothing to change to his application code.
> Generated trace must match with the one obtained on the real hardware (except timestamp)

* Stimulus generation
> Obtain results must be bit-accurate in order to generate golden stimulus for RTL simulation
> RTL parameters must be fully configurable at runtime to easily generate stimulus for any configuration

* Firmware development
> Generate accurate performances estimation and tracing capabilities to help the development/optimization of HPU firmware

### Mockup structure
Without hardware support `tfhe-hpu-backend` fallback to a simulation FFI interface (i.e. `ffi-sim`). This interface bind to IPC channel and forward the FFI call over IPC with a simple Cmd/Payload message and Request/Ack protocol. The Mockup bind to those IPC and answer to request like the real hardware.

On his side, the mockup answer to backend IPC request and simulate the hardware behavior. 
The internal structure of the mockup is organized around modules to emulate the hardware behavior. It contains the following modules:
* `hbm`: Emulate HBM memory (only from a behavioral point of view). It enables to allocate/release chunk of memory. Those chunk could be read/write through the IPC with the same Sync mechanisms as the real hardware.
* `isc`: This module implements the `instruction_scheduler` behavior. It contains the performance model of the HPU. It reorders the DOp in a same manner as the RTL module and emulate HPU's processing element availability with a simple cost model. 
 + `pe`: Processing element cost model. Parameters are loaded from `.ron` file
 + `pool`: Emulate the behavior of the instruction_scheduler pool used to store the state of the in-flight instructions
 + `scheduler`: Used query in the `pool` and dispatch req to Processing-Element.
* `regmap`: Emulate the RTL register map. It converts concrete TFHE/RTL parameters into register value.
* `ucore`: Emulate the ucore behavior. It is in charge of reading the DOp stream from the HBM and patch the template operation in a same manner as the ucode embedded in the real hardware.

The Mockup is a standalone binary that must be run before the User application code.
The use of Two binary enable to:
* Expose a wide range of mockup configuration without impacting the User application
* Have to distinct stream of log: One for the mockup and one for the User application. By this way the trace log of the User application is unchanged compared to the real Hardware.

Below an overview of the internal structure of the Mockup.
![HPU Mockup](./figures/tfhe-hpu-mockup.excalidraw.png)

After the Mockup start, it registers an IPC configuration channel in a file that could be read by the `ffi-sim` to establish a connection.
Once done, the following steps occurred:

> NB: Used filename is set in the TOML configuration file in FFI section.
> ```toml
> [fpga.ffi.Sim]
> ipc_name="/tmp/hpu_mockup_ipc"
> ```

1. Use configuration channel to exchange a set of IPC endpoints: 1 for registers access and one for memory management. Those channel implement a simple Cmd/Payload message and Request/Ack protocol.
2. `tfhe-hpu-backend` read registers through the associated IPC channel and retrieved the associated mockup parameters.
3. `tfhe-hpu-backend` allocate required on-board memory. It then uploads the firmware translation table (Use to expand IOp in a stream of DOps), and the set of TFHE server keys. Then, it uploads the input ciphertext.
4. Once all input data is synced on the mockup, `tfhe-hpu-backend` triggered IOp execution by pushing operation in the `WorkQ`.
 4.1 HPU behavioral model retrieved the associated DOps stream from the HBM memory. For this purpose it uses the `ucore` module. This module read the memory and patch the obtain stream to have concrete DOp to execute (The firmware translation table have some templated DOp that must be translated to concrete one before execution)
 4.2 DOp stream is then injected in the `instruction scheduler` to obtain the real execution order and the performance estimation.
 4.3 HPU behavioral model retrieve key material in the memory (i.e. in HPU format) and convert them back in Cpu format.
 4.4 HPU execute the DOp with the help of `tfhe-rs` operation. 
 4.5 When needed execution model read the ciphertext from the `regfile`. 
 > NB: Ciphertext are stored in the `regfile` in HPU format and translate back to CPU format before execution.
5. When IOp execution is finish the Mockup notify the `tfhe-hpu-backend` through the `AckQ`.
6. `tfhe-hpu-backend` retrieved the results from the HBM with the help of IPC channels.


### Mockup CLI and configuration
The mockup application is configured two files:
1. Configuration (i.e. `--config` CLI knob)
It's the same as the one used by the `tfhe-hpu-backend`. It's used by the mockup application to retrieved the `ffi-sim` configuration, the register map as well as the expected memory layout of the on-board memory.

2. Parameters (i.e. `--params` CLI knob)
This file is used to retrieved the inner RTL parameters such as:
* TFHE parameters set
* NTT internal structure
* Instruction scheduler properties
* Pc configuration for each HBM connection

This file also includes a description of the available processing-element alongside with their associated performances.

Other optional configuration knobs are available:
* `--freq-hz`, `--register`, `isc-depth`, `--pe-cfg`: These knobs are used to override some parameters on the flight. They are useful for quick exploration.
* `--dump-out`, `--dump-reg`: Use for RTL stimulus generation and debug
* `--report-out`, `report-trace`: Use for detailed analyses of the performances report

On top of that `tfhe-hpu-mockup` could generate a detailed set of trace point at runtime to help during the debug/exploration phase (e.g. When writing new Hpu firmware).
Those trace points rely on `tokio-tracing` and could be activated on a path::verbosity based through the `RUST_LOG` environment variable.
For example the following value will enable the info trace for all the design and the debug one for the instruction scheduler submodule:
`RUST_LOG=info,hpu_sim::modules::isc=debug`.


## Example
The following section explain how to run the `hpu_8b` benchmark on the mockup backend.
> NB: The use of the mockup instead of the real hardware is transparent for the user application.
> Only change in the configuration file is required, and no hardware support should be activated during compilation (i.e. features like `hw-xrt`).


### HPU configuration selection
Select the desired configuration in `setup_hpu.sh` (Cf. HPU_CONFIG). 
For convenience a simulation configuration is available `sim_pem2`.

```bash
source setup_hpu.sh
```

> NB: For convenience, a Justfile is provided with different target to build and start User/Mockup application.
> Open two terminals and for example
> Start `just mockup_fast` in the first one and start `just hpu_8b` in the second one.
> For list of available target use `just`

### Start mockup application
Two parameters files are provided for convenience:
* `mockups/tfhe-hpu-mockup/params/tfhers_64b.ron`: 
> Use real 64b Hardware parameters set. Simulation is slow, but it enables to generate bit-accurate results. Useful for RTL stimulus generation.

 * `mockups/tfhe-hpu-mockup/params/tfhers_64b_fast.ron`: 
 > Use a fake 64b parameters set. Simulation is fast. Useful for debug and test

```bash
cargo build --release --bin hpu_mockup
./target/release/hpu_mockup \
  --params mockups/tfhe-hpu-mockup/params/tfhers_64b_fast.ron \
  [--freq-hz --register --isc-depth --pe-cfg]
  [--dump-out mockup_out/ --dump-reg]\
  [--report-out mockup_rpt/ --report-trace]
```

### Start user application
In the snippets below, `hpu_8b` benchmark is selected but any application using HPU hardware could be used.

```
cargo build --release --features="hpu-xfer" --example hpu_8b
./target/release/examples/hpu_8b --iop MUL --src-a 8 --src-b 36
```


