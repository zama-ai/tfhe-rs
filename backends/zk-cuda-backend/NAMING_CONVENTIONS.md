# Naming Conventions

This document defines the naming conventions used throughout the zk-cuda-backend codebase.

## Types and Structs

**Rule: `PascalCase`, no underscores.**

| Category | Pattern | Examples |
|----------|---------|----------|
| Field elements | Short math names | `Fp`, `Fp2` (future: `Fp6`, `Fp12`) |
| Big integers | `BigInt<N>` template | `BigInt<7>`, `BigInt<5>` |
| Scalars | Alias of BigInt | `Scalar` (= `BigInt<ZP_LIMBS>`) |
| Curve points (affine) | `G{1,2}Affine` | `G1Affine`, `G2Affine` |
| Curve points (projective) | `G{1,2}Projective` | `G1Projective`, `G2Projective` |
| Enums | `PascalCase` | `ComparisonType` |

**FFI boundary types (api.h):** Use `G1Point`/`G2Point` (affine) and `G1ProjectivePoint`/`G2ProjectivePoint` for C compatibility. Type aliases bridge to internal names.

**Rust types** mirror internal CUDA names: `G1Affine`, `G1Projective`, `G2Affine`, `G2Projective`, `Scalar`.

## Template Parameters and Trait Structs

**Template parameters: `PascalCase` with descriptive suffix.**

| Parameter | Used in |
|-----------|---------|
| `AffineType` | MSM kernels, launch params |
| `ProjectiveType` | MSM kernels, launch params |
| `PointType` | Generic point operations |
| `FieldType` | Trait associated type |
| `N` | `BigInt<N>` |

**Trait structs:**

| Struct | Purpose | Location |
|--------|---------|----------|
| `Affine<T>` | Affine point ops dispatch | `point_traits.h` |
| `Projective<T>` | Projective point ops dispatch | `point_traits.h` |
| `SelectorChooser<T>` | Maps point type -> trait struct | `point_traits.h` |
| `MSMTraits<T>` | Maps projective -> affine type | `curve.h` |
| `MSMWindowSize<T>` | Window size constant per type | `msm.h` |
| `Phase1KernelLaunchParams<T>` | Kernel config for accumulation | `msm_pippenger.cu` |
| `Phase2KernelLaunchParams<T>` | Kernel config for reduction | `msm_pippenger.cu` |

## Functions

### Field Arithmetic

**Rule: `<field>_<operation>` — lowercase snake_case, field prefix.**

| Pattern | Meaning | Examples |
|---------|---------|---------|
| `fp_<op>` | Basic operation | `fp_add`, `fp_sub`, `fp_neg`, `fp_copy`, `fp_cmp` |
| `fp_is_<pred>` | Predicate | `fp_is_zero`, `fp_is_one`, `fp_is_quadratic_residue` |
| `fp_mont_<op>` | Montgomery-domain operation | `fp_mont_mul`, `fp_mont_inv`, `fp_mont_reduce` |
| `fp_<op>_raw` | No modular reduction | `fp_add_raw`, `fp_sub_raw`, `fp_mul_schoolbook_raw` |
| `fp_to_montgomery` / `fp_from_montgomery` | Form conversion | |
| `fp_<constant>` | Return constant (normal form) | `fp_zero`, `fp_one`, `fp_modulus` |
| `fp_<constant>_montgomery` | Return constant (Montgomery) | `fp_one_montgomery`, `fp_two_montgomery` |

Fp2 follows identical patterns with `fp2_` prefix.

### Point Operations (Generic Template)

**Rule: `point_<operation>` for G1/G2-generic operations.**

```
point_add, point_double, point_neg, point_scalar_mul
point_at_infinity, point_to_montgomery, point_from_montgomery
point_to_montgomery_batch
```

### Point Operations (Group-Specific)

**Rule:** Group **leads** when it "owns" the concept; group **trails** when the operation is primary.

| Group leads | Group trails |
|-------------|-------------|
| `g1_point_at_infinity` | `projective_to_affine_g1` |
| `g1_is_infinity` | `normalize_projective_g1` |
| `g1_generator` | `is_on_curve_g1` |
| `g1_projective_point_at_infinity` | `curve_b_g1` |

Overloaded functions omit the group entirely.

### Projective Point Operations

**Rule: `projective_<operation>` prefix.**

`projective_point_add`, `projective_point_double`, `projective_mixed_add`, `projective_scalar_mul` — all overloaded for G1/G2.

### In-Place Host Operations

**Rule: `_inplace` suffix for host-only in-place modifications.**

`point_to_montgomery_inplace`, `point_from_montgomery_inplace`

The CUDA template batch functions (`point_to_montgomery_batch`) are also in-place but omit `_inplace` — this is intentional. The `_inplace` suffix distinguishes the host-only path from the CUDA template path.

### MSM Functions

Internal: `point_msm_async_g1`, `point_msm_g1`, `pippenger_scratch_size_g1` (group suffix).

### CUDA Kernels

**Rule: `kernel_<descriptive_name>` prefix.**

`kernel_accumulate_all_windows`, `kernel_reduce_all_windows`, `kernel_compute_window_sums`, `kernel_clear_buckets`, `kernel_point_add`, `kernel_point_to_montgomery_batch`, etc.

### FFI Wrappers

**Rule: `*_wrapper` suffix.** Group position follows the underlying function's convention:

- Group prefix: `g1_msm_managed_wrapper`, `g1_from_montgomery_wrapper`
- Group suffix: `affine_to_projective_g1_wrapper`, `is_on_curve_g1_wrapper`, `pippenger_scratch_size_g1_wrapper`
- No group: `fp_to_montgomery_wrapper`, `scalar_modulus_limbs_wrapper`

### Rust API

Standard Rust `snake_case`: `to_projective()`, `from_montgomery_normalized()`, `is_infinity()`, `msm()`.

Module-level conversions: `g1_affine_from_montgomery()`, `g1_affine_from_arkworks()`.

## Variables

**Rule: `snake_case` everywhere.**

| Convention | Examples |
|------------|---------|
| Device pointers: `d_` prefix | `d_result`, `d_points`, `d_scratch` |
| Host pointers: no prefix | `result`, `points` |
| Counts: `num_*` | `num_points`, `num_blocks`, `num_windows` |
| Indices: `*_idx` | `window_idx`, `bucket_idx`, `point_idx` |
| Memory sizes: `*_bytes` | `points_bytes`, `scratch_bytes` |
| Booleans: descriptive | `valid`, `overflow`, `points_in_montgomery` |
| Shared memory: `shared_*` | `shared_mem`, `shared_points`, `shared_sums` |
| CUDA params | `stream`, `gpu_index`, `size_tracker` |

## Constants and Macros

**Rule: `UPPER_SNAKE_CASE`.**

| Prefix | Category | Examples |
|--------|----------|---------|
| `FP_` | Field parameters | `FP_LIMBS`, `FP_BITS` |
| `ZP_` | Scalar field | `ZP_LIMBS` |
| `LIMB_` | Limb config | `LIMB_BITS`, `LIMB_MAX` |
| `MSM_G1_` / `MSM_G2_` | MSM per-group | `MSM_G1_WINDOW_SIZE`, `MSM_G2_BUCKET_COUNT` |
| `MSM_` | MSM shared | `MSM_WINDOW_SIZE`, `MSM_SIGNED_BUCKET_COUNT` |
| `KERNEL_` | Kernel config | `KERNEL_THREADS_MAX` |
| `CUDA_` | CUDA arch | `CUDA_WARP_SIZE` |
| `BLS12_446_` | Curve constants | `BLS12_446_MODULUS_LIMBS` |
| `DEVICE_` | `__constant__` memory | `DEVICE_MODULUS`, `DEVICE_R2`, `DEVICE_G1_GENERATOR` |

## Files

| Category | Location | Naming |
|----------|----------|--------|
| CUDA public headers | `cuda/include/*.h` | `fp.h`, `curve.h`, `msm.h`, `point_traits.h` |
| CUDA internal headers | `cuda/src/**/*.cuh` | `common.cuh` |
| CUDA source | `cuda/src/**/*.cu` | `fp.cu`, `curve.cu`, `msm_pippenger.cu` |
| Rust modules | `src/` | `snake_case`: `types`, `conversions`, `bindings`, `g1`, `g2`, `scalar` |

## Async/Sync Pair Convention

```
<operation>_async   — launch kernel(s), return immediately
<operation>         — call _async, then synchronize
```

**`_async` suffix** for non-blocking; **no suffix** for synchronizing.
