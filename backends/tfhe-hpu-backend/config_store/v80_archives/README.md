# Hpu archives

This folder contains a set of custom archives used to reload the FPGA.
These archives contains pdi files and other metadata.
A tool `hpu_archive_mgmt` is provided to create/expand archives.



## How to build `hpu_archive_mgmt`
Simply go into the tfhe-hpu-backend folder and use cargo:
```
cargo build --release --features hw-v80,utils
```


## How to unpack an archive for inspection
For this purpose use `hpu_archive_mgmt`:
```
./target/release/hpu_archive_mgmt unpack backends/tfhe-hpu-backend/config_store/v80_archives/psi64.hpu backends/tfhe-hpu-backend/config_store/v80_archives/psi64
```


## How to pack an archive after update
For example, if you have previously unpacked the psi64.hpu, you can use the following command to pack it back:

```
./target/release/hpu_archive_mgmt pack backends/tfhe-hpu-backend/config_store/v80_archives/psi64 backends/tfhe-hpu-backend/config_store/v80_archives/psi64.hpu
```
