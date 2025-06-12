# Hpu archives

This folder contains a set of custom archive used to reload the FPGA.
This archives contains pdi files and other metadata.
A tool `pdi_mgmt` is provided to create/expand archives.



## How to build `pdi_mgmt`
Simply go in tfhe-hpu-backend folder and use cargo:
```
cargo build --release --features hw-v80,utils
```


## How to unpack an archive for inspection
For this purpose use `pdi_mgmt`:
```
./target/devo/pdi_mgmt unpack backends/tfhe-hpu-backend/config_store/v80_pdi/psi64.hpu backends/tfhe-hpu-backend/config_store/v80_pdi/psi64
```


## How to pack an archive after update
For example, if you have previously unpack the psi64.hpu, you can use the following command to pack it back:

```
./target/devo/pdi_mgmt pack backends/tfhe-hpu-backend/config_store/v80_pdi/psi64 backends/tfhe-hpu-backend/config_store/v80_pdi/psi64.hpu
```
