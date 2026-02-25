# ZK CUDA Backend

A CUDA implementation of BLS12-446 elliptic curve operations for zero-knowledge proof systems.
It provides GPU-accelerated finite field arithmetic, elliptic curve point operations, and
multi-scalar multiplication (MSM) targeting NVIDIA GPUs.

The cryptographic operations it provides are:
- Multi-precision finite field arithmetic (Fp) with Montgomery reduction
- Quadratic extension field (Fp2) operations
- Elliptic curve point operations for G1 (over Fp) and G2 (over Fp2) groups
- High-performance Multi-Scalar Multiplication (MSM) using Pippenger's algorithm
- Rust API bindings

## BLS12-446 Curve

This implementation targets the **BLS12-446** curve:
- **446-bit prime field** (Fp): 7 limbs of 64 bits (448 bits total, 2 bits headroom)
- **Two groups**: G1 (over Fp) and G2 (over Fp2)
- **Modulus**: Hardcoded from tfhe-rs reference implementation

## API

### Finite Field Arithmetic (Fp and Fp2)

**Fp** — multi-precision arithmetic for the 446-bit prime field:
- Operations: `fp_add()`, `fp_sub()`, `fp_mul()`, `fp_neg()`, `fp_inv()`, `fp_div()`, `fp_pow()`, `fp_sqrt()`, Montgomery conversions
- Operator overloads: `+`, `-`, `*`, `/`, unary `-`, `+=`, `-=`, `*=`, `/=`, `==`, `!=`
- Montgomery form: `fp_to_montgomery()` / `fp_from_montgomery()` for conversion; `fp_one_montgomery()` etc. for constants

**Fp2** — quadratic extension field (Fp2 = Fp[i], i² = −1):
- Operations: `fp2_add()`, `fp2_sub()`, `fp2_mul()`, `fp2_neg()`, `fp2_inv()`, `fp2_div()`, `fp2_square()`, `fp2_conjugate()`, `fp2_frobenius()`

### Elliptic Curve Operations

Point representations:
- **Affine**: `G1Affine`, `G2Affine` — (x, y) with infinity flag
- **Projective**: `G1Projective`, `G2Projective` — (X, Y, Z) homogeneous coordinates

Operations (template functions work for both G1 and G2):
- `point_add()`, `point_double()`, `point_neg()`, `point_scalar_mul()`
- `affine_to_projective()`, `projective_to_affine_g1()`, `projective_to_affine_g2()`
- `point_to_montgomery_inplace()`, `normalize_from_montgomery_g1()` / `normalize_from_montgomery_g2()`
- Operator overloads on projective points: `+`, unary `-`, `*` (scalar), `+=`, `==`, `!=`
- Generator access: `g1_generator()`, `g2_generator()`

### Multi-Scalar Multiplication (MSM)

Implements Pippenger's bucket method. Window sizes are selected dynamically:
- **G1**: 4-bit windows for n ≤ 256, 5-bit for n ≤ 4096, larger for bigger inputs
- **G2**: fixed 5-bit windows (Fp2 operations are 2× more expensive)

**Unmanaged API** — caller manages all device memory:
```c
// Query required scratch space, then run MSM.
size_t scratch_bytes = pippenger_scratch_size_g1(n, gpu_index);
G1Projective *d_scratch = (G1Projective *)cuda_malloc(scratch_bytes, gpu_index);
point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, n,
             d_scratch, size_tracker, /*gpu_memory_allocated=*/true);
```

**Managed API** — Rust bindings handle memory allocation and transfers internally:
```rust
let (result, size_tracker) = G1Projective::msm(&points, &scalars, stream, gpu_index, false)?;
```

See the [basic examples](cuda/tests_and_benchmarks/tests/basic/) for complete working programs.
## Dependencies

**Disclaimer**: Compilation on Windows/Mac is not supported. Only Nvidia GPUs are supported.

- nvidia driver — GPU with Compute Capability ≥ 3.0 (e.g. Ubuntu 20.04: [installation guide](https://linuxconfig.org/how-to-install-the-nvidia-drivers-on-ubuntu-20-04-focal-fossa-linux))
- [nvcc](https://docs.nvidia.com/cuda/cuda-installation-guide-linux/index.html) ≥ 10.0
- [gcc](https://gcc.gnu.org/) ≥ 8.0 — see [nvcc/gcc compatibility](https://gist.github.com/ax3l/9489132)
- [cmake](https://cmake.org/) ≥ 3.24
- libclang ≥ 9.0 — for Rust [bindgen requirements](https://rust-lang.github.io/rust-bindgen/requirements.html)

Dependencies fetched automatically by CMake: Google Test, Google Benchmark.

## Build

```bash
cd cuda
cmake -B build
cmake --build build
```

The compute capability is detected automatically from the first available GPU.
If no GPU is present, the build targets sm_70 (Volta).

### Rust API

The Rust build compiles the CUDA library automatically via `build.rs`:

```bash
# From backends/zk-cuda-backend/
cargo build --release
```

## Testing

```bash
cd cuda/build
ctest --output-on-failure       # run all tests
./test_fp                        # individual test executables
./test_fp2
./test_msm
./test_point_ops
./test_fp --gtest_filter="*Montgomery*"  # filter by name
```

Test coverage: Fp operations (22+ tests), Fp2 operations, G1/G2 point operations,
projective arithmetic, MSM correctness for various batch sizes.

## Benchmarks

```bash
cd cuda/build
./benchmark_fp
./benchmark_fp2
./benchmark_msm
```

## Technical Notes

### Montgomery Reduction

All internal multiplications use Montgomery form (R = 2^448, matching tfhe-rs).
Precomputed constants: R² mod p, R_INV mod p, p' = −p⁻¹ mod 2⁶⁴.
The `mont` convention: functions documented "MONTGOMERY" expect inputs already in
Montgomery form; "NORMAL" functions handle conversion internally.

### Memory Management

- **Unmanaged API** (`point_msm_g1`, `point_msm_g2`): all data must be on device;
  caller manages allocation and transfers. Use `pippenger_scratch_size_g1/g2()` to
  query the required scratch buffer size.
- **Managed API** (Rust `G1Projective::msm()`, `G2Projective::msm()`): handles
  allocation, host-to-device copies, and scratch space automatically.

## Security

### Side-Channel Resistance

This implementation assumes **scalars are public** and is **not** constant-time.
Do not use it for operations where scalars must remain secret.
For ZK proof generation this is acceptable when scalars are derived from public
parameters or are witness values revealed in the proof.

### Input Validation

- **Point validation**: off by default; enable with the `validate_points` feature:
  ```toml
  zk-cuda-backend = { version = "...", features = ["validate_points"] }
  ```
- **Scalar validation**: `Scalar::is_valid()` and `Scalar::reduce_once()` available in the Rust API.

## Naming Conventions

See [NAMING_CONVENTIONS.md](NAMING_CONVENTIONS.md) for the full reference.

## References

- [Pairing-Friendly Curves (BLS12)](https://eprint.iacr.org/2006/372.pdf)
- [Montgomery Reduction — Handbook of Applied Cryptography](https://cacr.uwaterloo.ca/hac/)
- [Pippenger's Algorithm](https://eprint.iacr.org/2012/549.pdf)
- [NVIDIA CUDA Best Practices Guide](https://docs.nvidia.com/cuda/cuda-c-best-practices-guide/)
- [tfhe-rs BLS12-446 reference](https://github.com/zama-ai/tfhe-rs/blob/main/tfhe-zk-pok/src/curve_446/mod.rs)
