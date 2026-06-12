# System tuning

This document lists OS-level settings that have a measurable impact on **TFHE-rs** performance. They are independent of the Rust toolchain and feature configuration described in [Advanced Rust setup](rust-configuration.md).

## Huge pages on Linux

**TFHE-rs** server keys and intermediate buffers are large (typically hundreds of MB to several GB depending on parameters).

On Linux, backing these allocations with huge pages reduces TLB pressure and noticeably improves throughput on PBS-heavy workloads.

Enabling Transparent Huge Pages (THP) is **recommended** whenever **TFHE-rs** is used in production or for benchmarking.

To enable it on Linux, run:
```shell
echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
```

To make this persistent across reboots, add `transparent_hugepage=always` to the kernel command line (e.g. via GRUB).
