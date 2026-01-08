# Rust API for ZK CUDA Backend

This crate provides safe Rust bindings for the CUDA-based BLS12-446 curve operations, with compatibility for tfhe-zk-pok types.

## Overview

The Rust API exposes:
- **G1Affine** and **G1Projective**: G1 group points in affine and projective coordinates
- **G2Affine** and **G2Projective**: G2 group points in affine and projective coordinates
- **Scalar**: 320-bit scalars (5 limbs of 64 bits each)
- **Multi-Scalar Multiplication (MSM)**: High-performance MSM operations for G1 and G2
- Conversion functions to/from tfhe-zk-pok types
- Montgomery form conversion utilities

## Building

### Prerequisites

1. Ensure you have Rust installed (stable or nightly)
2. The CUDA library will be built automatically by `build.rs` when you run `cargo build`

### Building the Rust API

From the `zk-cuda-backend` directory (where `Cargo.toml` is located):

```bash
cargo build
```

For release builds:
```bash
cargo build --release
```

The build script (`build.rs`) will automatically:
- Configure and build the CUDA library in `cuda/build/` if needed
- Link the compiled CUDA library with the Rust bindings

## Usage

### Basic Usage

```rust
use zk_cuda_backend::{G1Affine, G1Projective, G2Affine, G2Projective};

// Create a G1 affine point at infinity
let g1_inf = G1Affine::infinity();

// Create a G1 affine point from coordinates
let g1_point = G1Affine::new(
    [0x1234, 0, 0, 0, 0, 0, 0],  // x coordinate (7 limbs)
    [0x5678, 0, 0, 0, 0, 0, 0],  // y coordinate (7 limbs)
    false  // not at infinity
);

// Convert to projective coordinates
let g1_proj = g1_point.to_projective();

// Convert back to affine
let g1_affine_again = g1_proj.to_affine();

// Similar for G2 points
let g2_point = G2Affine::new(
    ([0x1234, 0, 0, 0, 0, 0, 0], [0x5678, 0, 0, 0, 0, 0, 0]),  // x = (c0, c1)
    ([0x9abc, 0, 0, 0, 0, 0, 0], [0xdef0, 0, 0, 0, 0, 0, 0]),  // y = (c0, c1)
    false
);
```

### Multi-Scalar Multiplication (MSM)

```rust
use zk_cuda_backend::{G1Affine, G1Projective, Scalar};
use tfhe_cuda_backend::cuda_create_stream;

// Create points and scalars
let points: Vec<G1Affine> = vec![
    G1Affine::new([1, 0, 0, 0, 0, 0, 0], [2, 0, 0, 0, 0, 0, 0], false),
    // ... more points
];

let scalars: Vec<Scalar> = vec![
    Scalar::new([1, 0, 0, 0, 0]),  // Create scalar from limbs
    // ... more scalars
];

// Create a CUDA stream (required for MSM)
let gpu_index = 0;
let stream = cuda_create_stream(gpu_index);

// Perform MSM using managed API
// Returns (G1Projective, size_tracker) where size_tracker is GPU memory allocated in bytes
let (result, size_tracker) = G1Projective::msm(
    &points,
    &scalars,
    stream,
    gpu_index,
    false, // points_in_montgomery: false means points will be converted to Montgomery form
)?;

// Convert to affine if needed
let result_affine = result.to_affine();
```

For G2 points:
```rust
use zk_cuda_backend::{G2Affine, G2Projective, Scalar};
use tfhe_cuda_backend::cuda_create_stream;

let g2_points: Vec<G2Affine> = vec![/* ... */];
let scalars: Vec<Scalar> = vec![/* ... */];

let gpu_index = 0;
let stream = cuda_create_stream(gpu_index);

// For best performance, pass points already in Montgomery form
let (result, _) = G2Projective::msm(
    &g2_points,
    &scalars,
    stream,
    gpu_index,
    true, // points_in_montgomery: true avoids conversion overhead
)?;
```

### Scalar Type (BigInt)

Scalars are represented as `BigInt` (aliased as `Scalar`), which is a 320-bit integer using 5 limbs of 64 bits each:

```rust
use zk_cuda_backend::Scalar;

// Create a scalar from limbs (little-endian: limb[0] is LSB)
let scalar = Scalar {
    limb: [0x1234567890ABCDEF, 0xFEDCBA0987654321, 0, 0, 0]
};

// Or use the BigInt type directly
use zk_cuda_backend::BigInt;
let scalar: Scalar = BigInt { limb: [1, 2, 3, 4, 5] };
```

### Montgomery Form Conversion

The API provides utilities for converting points to/from Montgomery form:

```rust
use zk_cuda_backend::{G1Affine, g1_affine_from_montgomery};

// Convert from Montgomery form (if point is in Montgomery form)
let point_montgomery = G1Affine::new(/* ... */);
let point_normal = g1_affine_from_montgomery(&point_montgomery);
```

### Integration with tfhe-zk-pok

The API provides conversion functions to/from tfhe-zk-pok types. These work with arkworks types that tfhe-zk-pok uses internally:

```rust
use zk_cuda_backend::{
    G1Affine, G1Projective, G2Affine, G2Projective,
    g1_affine_from_tfhe_zk_pok, g1_projective_to_tfhe_zk_pok,
    g2_affine_from_tfhe_zk_pok, g2_projective_to_tfhe_zk_pok,
};

// Convert from tfhe-zk-pok G1Affine to our G1Affine
let tfhe_point: tfhe_zk_pok::curve_446::G1Affine = /* ... */;
let our_point = g1_affine_from_tfhe_zk_pok(&tfhe_point)?;

// Convert our G1Projective to tfhe-zk-pok G1Affine
use tfhe_cuda_backend::cuda_create_stream;
let stream = cuda_create_stream(0);
let (our_proj, _) = G1Projective::msm(&points, &scalars, stream, 0, false)?;
let tfhe_affine = g1_projective_to_tfhe_zk_pok(&our_proj)?;
```

## Type Structure

### Fp (Field Element)
- 7 limbs of 64 bits each (446-bit prime field)
- Little-endian: `limb[0]` is the least significant word
- Includes `mont` field to track Montgomery form state

### Scalar
- 5 limbs of 64 bits each (320-bit integer)
- Little-endian: `limb[0]` is the least significant word
- Used for scalar multiplication and MSM operations

### G1Affine
- `x: [u64; 7]` - x coordinate in Fp
- `y: [u64; 7]` - y coordinate in Fp
- `infinity: bool` - true if point at infinity

### G2Affine
- `x: ([u64; 7], [u64; 7])` - x coordinate in Fp2 (c0, c1)
- `y: ([u64; 7], [u64; 7])` - y coordinate in Fp2 (c0, c1)
- `infinity: bool` - true if point at infinity

### G1Projective
- `X: [u64; 7]` - X coordinate in Fp
- `Y: [u64; 7]` - Y coordinate in Fp
- `Z: [u64; 7]` - Z coordinate in Fp
- Represents affine point (X/Z, Y/Z)

### G2Projective
- `X: ([u64; 7], [u64; 7])` - X coordinate in Fp2
- `Y: ([u64; 7], [u64; 7])` - Y coordinate in Fp2
- `Z: ([u64; 7], [u64; 7])` - Z coordinate in Fp2
- Represents affine point (X/Z, Y/Z)

## Error Handling

MSM operations return `Result<T, String>`:
- `Ok(T)` on success
- `Err(String)` on failure (e.g., CUDA errors, mismatched array lengths)

```rust
use tfhe_cuda_backend::cuda_create_stream;

let stream = cuda_create_stream(0);
match G1Projective::msm(&points, &scalars, stream, 0, false) {
    Ok((result, _)) => println!("MSM succeeded"),
    Err(e) => eprintln!("MSM failed: {}", e),
}
```

## Performance Considerations

- **MSM operations**: Automatically handle CUDA memory allocation, stream management, and synchronization
- **Montgomery form**: Points are converted to Montgomery form internally for MSM operations
- **Batch operations**: MSM is optimized for large batch sizes
- **GPU selection**: Specify `gpu_index` to use a specific GPU (0 for first GPU)

## Testing

Run the test suite:

```bash
# From the zk-cuda-backend directory
cargo test
```

The test suite includes:
- Point creation and conversion tests
- MSM correctness tests
- Integration tests with tfhe-zk-pok (if available)
- Edge case tests (infinity points, zero scalars, etc.)

## Benchmarks

Run benchmarks:

```bash
# From the zk-cuda-backend directory
cargo bench
```

Benchmarks measure MSM performance for various batch sizes on G1 and G2 groups.

## Notes

- All coordinates are stored in little-endian format
- The infinity flag is separate from coordinate values
- Projective coordinates use Z=0 to represent infinity
- Conversions between affine and projective are provided for both G1 and G2
- MSM operations automatically handle memory management and CUDA setup
- The API is thread-safe for concurrent MSM operations on different GPUs

## License

Same as the parent project.
