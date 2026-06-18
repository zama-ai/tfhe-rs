//! FastKreyvium GPU keystream generation.
//!
//! FastKreyvium evaluates the standard Kreyvium cipher, but runs the keystream loop with the
//! Z4 single-bit-extraction algorithm (message_modulus 2, carry_modulus 1) instead of the 2_2
//! encoding the original GPU Kreyvium uses. The register layout is unchanged from Kreyvium: the
//! three nonlinear registers `a`/`b`/`c` plus the circular key and IV registers, with `k_offset`
//! and `iv_offset` tracking the rotating read positions into the 128-bit `k`/`iv` registers
//! maintained by the kernels across steps.
//!
//! Because the two variants share the register layout, the state type ([`CudaKreyviumState`]) and
//! the init/next/generate_keystream logic are shared with the original Kreyvium. The Rust entry
//! points (`fast_kreyvium_init`, `fast_kreyvium_next`, `fast_kreyvium_generate_keystream`) live on
//! [`CudaServerKey`] alongside the Kreyvium ones in
//! `crate::integer::gpu::server_key::radix::kreyvium`; they differ only in which set of CUDA
//! kernels they drive. The public `CudaFastKreyviumState` name is re-exported from the parent
//! module as an alias of `CudaKreyviumState`.
//!
//! [`CudaKreyviumState`]: crate::integer::gpu::server_key::CudaKreyviumState
//! [`CudaServerKey`]: crate::integer::gpu::CudaServerKey
