# System tuning

This document lists OS-level settings that have a measurable impact on **TFHE-rs** performance. They are independent of the Rust toolchain and feature configuration described in [Advanced Rust setup](rust-configuration.md).

## Huge pages

**TFHE-rs** server keys and intermediate buffers are large (typically hundreds of MB to several GB depending on parameters).
Backing these allocations with huge pages reduces TLB pressure and noticeably improves throughput on PBS-heavy workloads.
Enabling huge pages is **recommended** whenever **TFHE-rs** is used in production or for benchmarking.

### Linux

The simplest option is to enable Transparent Huge Pages (THP) in `always` mode:

```shell
echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
```

To make this persistent across reboots, add `transparent_hugepage=always` to the kernel command line (e.g. via GRUB).

### macOS / Windows

**TFHE-rs** does not currently rely on platform-specific huge page APIs on these systems.
The library still runs correctly, but the performance recommendations above only apply to Linux.
