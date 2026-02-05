# ZK CUDA Backend

A high-performance CUDA implementation of BLS12-446 elliptic curve operations for zero-knowledge proof systems. This library provides GPU-accelerated finite field arithmetic, elliptic curve point operations, and multi-scalar multiplication (MSM) optimized for NVIDIA GPUs.

## Overview

This project implements a CUDA backend for BLS12-446 elliptic curve operations, which are fundamental to zero-knowledge proof systems. The implementation focuses on performance and correctness, providing both host and device-side APIs for maximum flexibility.

**Key Features:**
- Multi-precision finite field arithmetic (Fp) with Montgomery reduction
- Quadratic extension field (Fp2) operations
- Elliptic curve operations for G1 and G2 groups
- High-performance Multi-Scalar Multiplication (MSM) using Pippenger's algorithm
- Comprehensive test suite with 100+ tests
- Performance benchmarks
- Rust API bindings

## Project Structure

```
zk-cuda-backend/
├── include/              # Header files
│   ├── fp.h              # Fp (finite field) declarations
│   ├── fp2.h             # Fp2 (quadratic extension) declarations
│   ├── curve.h           # Elliptic curve point operations
│   └── msm.h             # Multi-scalar multiplication API
│   # Note: device.h comes from tfhe-cuda-backend
├── src/                  # CUDA source files
│   ├── primitives/
│   │   ├── fp.cu         # Fp implementation
│   │   └── fp2.cu        # Fp2 implementation
│   ├── curve.cu          # Curve operations
│   └── msm/              # MSM implementation
│       └── pippenger/    # Pippenger's algorithm
├── tests/                # Test suite
│   ├── primitives/       # Fp and Fp2 tests
│   ├── test_msm.cu       # MSM tests
│   ├── test_point_ops.cu # Point operation tests
│   └── test_scalar_mul.cu # Scalar multiplication tests
├── benchmarks/          # Performance benchmarks
│   ├── benchmark_fp.cu   # Fp benchmarks
│   ├── benchmark_fp2.cu  # Fp2 benchmarks
│   └── benchmark_msm.cu  # MSM benchmarks
├── src/                  # Rust bindings
│   ├── src/             # Rust source code
│   └── include/         # C wrapper headers
└── utils/               # Utility scripts
```

## BLS12-446 Curve

This implementation targets the **BLS12-446** curve, which uses:
- **446-bit prime field** (Fp): Requires 7 limbs of 64 bits each
- **Two groups**: G1 (over Fp) and G2 (over Fp2)
- **Modulus**: Hardcoded from tfhe-rs reference implementation

The modulus and all curve constants are initialized at compile time and available as device constants for optimal performance.

## Components

### Finite Field Arithmetic (Fp and Fp2)

**Fp** - Multi-precision arithmetic for the 446-bit prime field:
- **Structure**: 7 limbs of 64 bits each (448 bits total, 2 bits headroom)
- **Montgomery Reduction**: R = 2^448, matching tfhe-rs implementation
- **Format Tracking**: `mont` field tracks whether values are in Montgomery form
- **Operations**: `fp_add()`, `fp_sub()`, `fp_mul()`, `fp_neg()`, `fp_inv()`, `fp_div()`, `fp_pow()`, `fp_sqrt()`, Montgomery conversions, etc.

**Fp2** - Quadratic extension field (Fp2 = Fp[i] where i² = -1):
- **Structure**: Two Fp elements (c0, c1) representing a + b*i
- **Operations**: `fp2_add()`, `fp2_sub()`, `fp2_mul()`, `fp2_neg()`, `fp2_inv()`, `fp2_div()`, `fp2_square()`
- **Special**: `fp2_conjugate()`, `fp2_frobenius()`, `fp2_mul_by_i()`

**Operator Overloads** (both Fp and Fp2):
- Arithmetic: `+`, `-`, `*`, `/`, unary `-`
- Compound assignment: `+=`, `-=`, `*=`, `/=`
- Comparison: `==`, `!=`
- Assignment: `=` (replaces `fp_copy()` / `fp2_copy()`)

**CUDA Kernels**: Batch operations for GPU execution

### Elliptic Curve Operations

Complete implementation for both G1 and G2 groups:

- **Point Representations**:
  - **Affine**: (x, y) coordinates with infinity flag (`G1Affine`, `G2Affine`)
  - **Projective**: (X, Y, Z) homogeneous coordinates (`G1Projective`, `G2Projective`)

- **Operations**:
  - Point addition: `point_add()`
  - Point doubling: `point_double()`
  - Point negation: `point_neg()`
  - Scalar multiplication: `point_scalar_mul()`, `projective_scalar_mul()`
  - Coordinate conversion: `affine_to_projective()`, `projective_to_affine()`

- **Operator Overloads** (Projective points):
  - Addition: `+` (point addition)
  - Negation: unary `-` (point negation)
  - Scalar multiplication: `*` (with `Scalar` type)
  - Compound assignment: `+=`
  - Comparison: `==`, `!=`
  - Assignment: `=` (replaces `point_copy()`)

- **Template API**: Generic functions that work for both G1 and G2 points
- **Generator Points**: Hardcoded G1 and G2 generators for BLS12-446

### Multi-Scalar Multiplication (MSM)

High-performance MSM implementation:

- **Algorithm**: Pippenger's bucket method with configurable window sizes
- **Window Sizes**:
  - **G1**: 4-bit windows (16 buckets: 0-15)
  - **G2**: 5-bit windows (32 buckets: 0-31) - larger windows reduce Horner doublings for more expensive Fp2 operations
- **Features**:
  - Supports both G1 and G2 groups
  - Uses projective coordinates internally (no inversions)
  - Optimized for large batch sizes
  - Register-based bucket accumulation for optimal performance

- **API**:
  - BigInt scalars (320-bit, 5 limbs): `point_msm_g1()`, `point_msm_g2()`
  - Async/Sync variants: `point_msm_async_*()` and `point_msm_*()`
  - **Managed API**: Handles memory allocation and transfers internally (convenient for Rust bindings)
  - **Unmanaged API**: Assumes data already on device, caller manages memory (better performance for pure-GPU workflows)

- **Memory**: Device pointer-based API (caller manages memory allocation for unmanaged API)

## Building

### Dependencies

**Disclaimer**: Compilation on Windows/Mac is not supported yet. Only Nvidia GPUs are supported. 

- nvidia driver - for example, if you're running Ubuntu 20.04 check this [page](https://linuxconfig.org/how-to-install-the-nvidia-drivers-on-ubuntu-20-04-focal-fossa-linux) for installation. You need an Nvidia GPU with Compute Capability >= 3.0
- [nvcc](https://docs.nvidia.com/cuda/cuda-installation-guide-linux/index.html) >= 10.0
- [gcc](https://gcc.gnu.org/) >= 8.0 - check this [page](https://gist.github.com/ax3l/9489132) for more details about nvcc/gcc compatible versions
- [cmake](https://cmake.org/) >= 3.24
- libclang, to match Rust bingen [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html) >= 9.0

Dependencies (automatically fetched by CMake):
- Google Test (for testing)
- Google Benchmark (for benchmarks)

### Build Instructions

```bash
# Create build directory
mkdir -p build
cd build

# Configure
cmake .. 

# Build
cmake --build .

# Or use make
make
```

### Building Rust API

The Rust API build automatically compiles the CUDA library via `build.rs`. Simply run:

```bash
# From the zk-cuda-backend directory (backends/zk-cuda-backend/)
cargo build --release
```

This will:
1. Automatically configure and build the CUDA library in `cuda/build/` if needed
2. Compile the Rust bindings
3. Link everything together

**Manual CUDA build** (if you need to build the CUDA library separately):

```bash
# Build the C++/CUDA library manually
cd cuda
mkdir -p build
cd build
cmake ..
make
```

## Usage

### C++/CUDA API

#### Basic Fp Operations

```cpp
#include "fp.h"

// Initialize values
Fp a, b, c;
fp_one(a);  // a = 1
fp_one(b);  // b = 1

// Using operator syntax (preferred)
c = a + b;  // c = 2
c = a - b;  // c = 0
c = a * b;  // c = 1
c = -a;     // c = -1 (mod p)

// Compound assignment
c += a;     // c = c + a
c *= b;     // c = c * b

// Assignment (copies value)
Fp d = a;   // d is a copy of a

// Named functions still available
fp_add(c, a, b);  // c = a + b = 2

// Convert to Montgomery form
fp_to_montgomery(a, a);

// Montgomery multiplication
fp_mont_mul(c, a, b);  // c = a * b (all in Montgomery form)
```

#### Elliptic Curve Operations

```cpp
#include "curve.h"

// Create points
G1Projective p1, p2, result;
// ... initialize point coordinates ...

// Using operator syntax (projective points)
result = p1 + p2;      // Point addition
result = -p1;          // Point negation
result += p2;          // Compound addition

// Scalar multiplication with Scalar type
Scalar s;
// ... initialize scalar ...
result = p1 * s;       // result = scalar * point
result = s * p1;       // Same as above

// Assignment (copies point)
G1Projective copy = p1;

// Named functions still available for affine points
G1Affine affine_point, affine_result;
uint64_t scalar[5] = {0x1234, 0, 0, 0, 0};
point_scalar_mul(affine_result, affine_point, scalar, 5);
```

#### Multi-Scalar Multiplication

```cpp
#include "msm.h"
#include "device.h"  // From tfhe-cuda-backend

// Allocate device memory
G1Affine* d_points;
Scalar* d_scalars;  // BigInt (320-bit scalars, 5 limbs)
G1Projective* d_result;
G1Projective* d_scratch;

// Calculate scratch space size
uint32_t n = 1000;  // number of points
uint32_t num_blocks = (n + 255) / 256;
size_t scratch_size = (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);

// Allocate memory using device wrappers
uint32_t gpu_index = 0;
d_points = (G1Affine*)cuda_malloc(n * sizeof(G1Affine), gpu_index);
d_scalars = (Scalar*)cuda_malloc(n * sizeof(Scalar), gpu_index);
d_result = (G1Projective*)cuda_malloc(sizeof(G1Projective), gpu_index);
d_scratch = (G1Projective*)cuda_malloc(scratch_size, gpu_index);

// Create stream and copy data to device
cudaStream_t stream = cuda_create_stream(gpu_index);
cuda_memcpy_async_to_gpu(d_points, h_points, n * sizeof(G1Affine), stream, gpu_index);
cuda_memcpy_async_to_gpu(d_scalars, h_scalars, n * sizeof(Scalar), stream, gpu_index);

// Perform MSM
point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, d_scratch, n);

// Copy result back and synchronize
G1Projective result;
cuda_memcpy_async_to_cpu(&result, d_result, sizeof(G1Projective), stream, gpu_index);
cuda_synchronize_stream(stream, gpu_index);

// Cleanup
cuda_drop(d_points, gpu_index);
cuda_drop(d_scalars, gpu_index);
cuda_drop(d_result, gpu_index);
cuda_drop(d_scratch, gpu_index);
cuda_destroy_stream(stream, gpu_index);
```

### Rust API

See the [Rust API README](src/README.md) for detailed usage examples.

```rust
use zk_cuda_backend::{G1Affine, G1Projective, Scalar};
use tfhe_cuda_backend::cuda_create_stream;

// Create points and scalars
let points: Vec<G1Affine> = vec![...];
let scalars: Vec<Scalar> = vec![...];

// Create a CUDA stream (required for MSM)
let gpu_index = 0;
let stream = cuda_create_stream(gpu_index);

// Perform MSM using managed API
// The managed API handles memory allocation and transfers internally
let (result, size_tracker) = G1Projective::msm(
    &points,
    &scalars,
    stream,
    gpu_index,
    false, // points_in_montgomery: false means points will be converted
)?;

// For G2 points:
use zk_cuda_backend::{G2Affine, G2Projective};
let (g2_result, _) = G2Projective::msm(
    &g2_points,
    &scalars,
    stream,
    gpu_index,
    true, // points_in_montgomery: true for better performance if already converted
)?;
```

## Testing

The project includes a comprehensive test suite using Google Test.

### Running Tests

```bash
# Run all tests
cd build
ctest --output-on-failure

# Run with verbose output
ctest --verbose

# Run specific test executables
./test_fp
./test_fp2
./test_msm
./test_point_ops

# Run specific test cases
./test_fp --gtest_filter="*Montgomery*"
./test_msm --gtest_filter="*G1*"
```

### Test Coverage

- **Fp Tests** (`test_fp`): 22+ tests covering:
  - Basic operations (addition, subtraction, multiplication)
  - Montgomery form conversions
  - Edge cases (zero, one, large values)
  - Property-based tests (commutativity, associativity)

- **Fp2 Tests** (`test_fp2`): Complete coverage of:
  - All Fp2 operations
  - Montgomery form operations
  - Special functions (Frobenius, conjugation)

- **Point Operation Tests** (`test_point_ops`): Verification of:
  - Point addition and doubling
  - Scalar multiplication
  - Coordinate conversions
  - Infinity point handling

- **MSM Tests** (`test_msm`): End-to-end verification:
  - G1 and G2 MSM correctness
  - Various batch sizes
  - Comparison with reference implementations

## Benchmarks

Performance benchmarks are available using Google Benchmark:

```bash
cd build
./benchmark_fp
./benchmark_fp2
./benchmark_msm
```

Benchmarks measure:
- Fp arithmetic operation throughput
- Fp2 operation performance
- MSM performance for various batch sizes
- GPU utilization and memory bandwidth

## Technical Details

### Montgomery Reduction

- **R value**: 2^448 (matching tfhe-rs)
- **Precomputed constants**: R² mod p, R_INV mod p, p' = -p⁻¹ mod 2⁶⁴
- **Format tracking**: Fp struct includes `mont` field to track representation
- **Efficiency**: All multiplications use Montgomery form internally

### MSM Algorithm

- **Pippenger's algorithm**: Bucket method with configurable window sizes
  - **G1**: 4-bit windows (16 buckets)
  - **G2**: 5-bit windows (32 buckets) - larger windows reduce expensive Fp2 field operations
- **Projective coordinates**: Avoids expensive field inversions
- **Memory layout**: Optimized for coalesced memory access
- **Thread configuration**: 128 threads/block for both G1 and G2 (optimized for H100 SM occupancy)
- **Register-based accumulation**: Uses register-based bucket accumulation instead of shared memory for better performance

### Memory Management

The library provides two MSM API variants:

- **Unmanaged API** (`point_msm_*_unmanaged_wrapper`):
  - Assumes all data (points, scalars, scratch space) is already on device
  - Caller manages all memory allocation and transfers
  - Best for performance-critical applications where data is already on GPU
  - Supports `points_in_montgomery` flag to avoid redundant conversions

- **Managed API** (`point_msm_*_managed_wrapper`):
  - Handles memory allocation and transfers internally
  - Copies data from host to device, runs MSM, copies result back
  - Convenient for Rust bindings and host-side code
  - Automatically manages scratch space allocation

- **Scratch space**: Required size is `(num_blocks + 1) * BUCKET_COUNT * sizeof(ProjectivePoint)`
  - G1: `(num_blocks + 1) * 16 * sizeof(G1Projective)`
  - G2: `(num_blocks + 1) * 32 * sizeof(G2Projective)`
- **Stream support**: Async operations with CUDA streams (all operations are async internally)

### CUDA Optimizations

- **Constant memory**: Modulus and curve constants in `__constant__` memory
- **Shared memory**: Used for bucket accumulations in MSM
- **Coalesced access**: Memory access patterns optimized for GPU
- **Separable compilation**: Enabled for better optimization

## Template Functions

Many functions are templated to work with both G1 and G2 points:
```cpp
template<typename PointType>
void point_add(PointType& result, const PointType& p1, const PointType& p2);
```

## Security

### Side-Channel Resistance

This implementation assumes **scalars are public** and is NOT constant-time. 
The MSM and scalar multiplication operations have timing variations that depend 
on scalar values (bit length, Hamming weight, specific bit patterns).

For ZK proof generation, this is acceptable if:
- Scalars are derived from public parameters
- Or are witness values that are revealed in the proof anyway

**Do not use this implementation for operations where scalars must remain secret.**

### Input Validation

- **Point validation**: Point on-curve validation is optional and controlled by the 
  `validate_points` feature flag. When disabled (default), malformed points may cause 
  undefined behavior in curve operations. Enable this feature for untrusted inputs:
  ```toml
  zk-cuda-backend = { version = "...", features = ["validate_points"] }
  ```
- **Scalar validation**: `Scalar::is_valid()` and `Scalar::reduce_if_needed()` methods available
- **Input size limits**: MSM operations are limited to 100,000 points maximum
- **Division by zero**: Caller must ensure division by zero does not occur (checks must be done at host side)

For detailed security information, see [SECURITY.md](SECURITY.md).

## References

- **BLS12 Curves**: [Pairing-Friendly Curves](https://eprint.iacr.org/2006/372.pdf)
- **Montgomery Reduction**: [Handbook of Applied Cryptography](https://cacr.uwaterloo.ca/hac/)
- **Pippenger's Algorithm**: [On the Evaluation of Powers and Monomials](https://eprint.iacr.org/2012/549.pdf)
- **CUDA Best Practices**: [NVIDIA CUDA Best Practices Guide](https://docs.nvidia.com/cuda/cuda-c-best-practices-guide/)
- **TFHE-rs Reference**: [tfhe-rs/tfhe-zk-pok/src/curve_446/mod.rs](https://github.com/zama-ai/tfhe-rs/blob/main/tfhe-zk-pok/src/curve_446/mod.rs)
