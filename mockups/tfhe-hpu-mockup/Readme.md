# Tfhe-hpu-mockup


## Brief 
Simulation _drop-in-replacemen_ implementation of Hpu Hardware.
This mockup implementation could be paired seamlesly with `tfhe-hpu-backend` compiled without any hardware support (i.e. `hpu-xrt`).
Indeed, without hardware support, `tfhe-hpu-backend` call to low-level ffi are replaced by IPC call and could be intercepted by this mockup implementation.

Objectives of this mockup are as follow:
* Transparent integration with User application:
> User must have nothing to change to his application code.
> Generated trace must match with the one obtained on the real hardware (except timestamp)

* Stimulus generation
> Obtain results must be bit-accurate in order to generate golden stimulus for RTL simulation
> Rtl parameters must be fully configurable at runtime to easily generate stimulus for any configuration

* Fw development
> Generate accurate performances estimation and tracing capabilities to help the development/optimization of Hpu firmware

### Mockup structure
Without hardware support `tfhe-hpu-backend` fallback to a simulation ffi interface (i.e. `ffi-sim`). This interface bind to IPC channel and forward the ffi call over IPC with a simple Cmd/Payload message and Request/Ack protocol.
The Mockup bind to those IPC and answer to request like the real hardware.
On his side, the mockup answer to backend IPC request and simulate the hardware behavior. 
The internal structure of the mockup is  organize around modules to emulate the hardware behavior. It contains the following modules:
* `hbm`: Emulate HBM memory (only from a behavioral point of view). It enable to allocate/deallocate chunk of memory. Those chunk could be read/write through the IPC with the same Sync mechanisms as the real hardware.
* `isc`: This module implement the `instruction_scheduler` behavior. It contains the performance model of the HPU. It reorder the DOp in a same manner as the RTL module and emulate Hpu's processing element availability with a simple cost model. + `pe`: Processing element cost model. Parameters are loaded from `.ron` file
 + `pool`: Emulate the behavior of the instruction_scheduler pool used to store the state of the inflight instructions
 + `scheduler`: Used query in the `pool` and dispatch req to Pe.
* `regmap`: Emulate the Rtl register map. It convert concrete Tfhe/Rtl parameters into register value.
* `ucore`: Emulate the ucore behavior. It is in charge of reading the DOp stream from the HBM and patch the template operation in a same manner as the ucode embedded in the real hardware.


TODO add picture

## HowTo
The Mockup is a standalone binary that must be run before the User application code.
The use of Two binary enable to:
* Expose a wide range of mockup configuration without impacting the User application
* Have to distinct stream of log: One for the mockup and one for the User application. By this way the trace log of the User application is unchanged compared to the real Hardware.

### Mockup CLI and configuration
The mockup application is configured through two toml files:
1. Configuration (i.e. `--config` CLI knob)
It's the same as the one used by the `tfhe-hpu-backend`. It's used by the mockup application to retrived the `ffi-sim` configuration, the register map  as well as the expected memory layout of the on-board memory.

2. Parameters (i.e. `--params` CLI knob)
This file is used to retrived the inner RTL parameters such as:
* Tfhe parameters set
* Ntt internal structure
* Instruction scheduler properties
* Pc configuration for each HBM connection

This file also include a description of the available processing-element alongside with their associated performances.

Other optional configuration knobs are available:
* `--freq-hz`, `--register`, `isc-depth`, `--pe-cfg`: These knobs are used to override some parameters on the flight. They are usefull for quick exploration.
* `--dump-out`, `--dump-reg`: Use for RTL stimulus generation and debug
* `--report-out`, `report-trace`:  Use for detailed analyses of the performances report

On top of that `tfhe-hpu-mockup` could generated a details set of trace point at runtime to help during the debug/exploration phase (e.g. When writing new Hpu-firmware).
Those trace points rely on `tokio-tracing` and could be activated on a path::verbosity based through the `RUST_LOG` environnement variable.
For example the following value will enable the info trace for all the design and the debug one for the instruction scheduler model:
`RUST_LOG=info,tfhe-hpu-backend::isc=debug`. (TODO: check the syntax)


## User Application
The use of the mockup instead of the real hardware must be transparent for the user code.
All the change belong to the configuration file. Instead of specifying the `ffi-xrt` section in the configuration file, user must select
he `ffi-sim`.


## Example
The following section explain how to run the `hpu_8b` benchmark on the mockup backend.

1. Select the HPU configuration
Select the desired configuration in `setup_hpu.sh` (Cf. HPU_CONFIG). 
For convenience a simulation configuration is available `sim_pem2`.

```bash
source setup_hpu.sh
```

1. Start the mockup application
Two parameters file are provided for convenience:
* `mockups/tfhe-hpu-mockup/params/tfhers_64b.ron`: 
 -> Use real 64b Hw parameters set. Simulation is slow but it enable to generate bit-accurate results. Usefull for RTL stimulus generation

 * `mockups/tfhe-hpu-mockup/params/tfhers_64b_fast.ron`: 
 -> Use a fake 64b parameters set. Simulation is fast. Usefull for debug and test

```bash
cargo build --release --bin hpu_mockup
./target/release/hpu_mockup \
  --params mockups/tfhe-hpu-mockup/params/tfhers_64b_fast.ron \
  [--freq-hz --register --isc-depth --pe-cfg]
  [--dump-out mockup_out/ --dump-reg]\
  [--report-out mockup_rpt/ --report-trace]
```

2. Start the User application
```
cargo build --release --features="hpu-xfer" --example hpu_8b
./target/release/examples/hpu_8b --iop MUL --src-a 8 --src-b 36
```


