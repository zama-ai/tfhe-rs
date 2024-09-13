# Hpu Backend

Hpu is a Fpga accelerators that support a set of Integer operation over TfheUint/TfheInt.
This folder provide a wrapper around C++ communication library and expose an high-level 
HpuEngine to the user.

Through this engine, the user could xfer TfheUint/TfheInt in the hardware, offload computation 
and retrieved results when needed.
