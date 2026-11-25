# AGENTS.md

Guidance for coding agents working in TFHE-rs. The root `Makefile` is the source of truth for commands (`make help` lists targets).

## Architecture

### Workspace

| Path | Role |
|---|---|
| `tfhe/` | Main crate; everything users import |
| `tfhe-fft/`, `tfhe-ntt/` | FFT and NTT primitives used by `core_crypto` |
| `tfhe-csprng/` | AES-CTR random generators and seeders |
| `tfhe-zk-pok/` | Zero-knowledge proofs of correct encryption (`zk-pok` feature) |
| `backends/` | CUDA backends (C++/CUDA with generated Rust bindings) and the HPU (FPGA) backend |
| `utils/tfhe-versionable*`, `utils/tfhe-safe-serialize/` | Versioned serialization and safe (size-limited, optionally conformance-checked) deserialization |
| `utils/tfhe-backward-compat-data/`, `tests/` | Data from past releases and the tests that load it. `tests/` is its own package, distinct from `tfhe/tests` |
| `utils/tfhe-lints/` | Custom lints for serialization rules |
| `tfhe-benchmark/` | All benchmarks |
| `apps/`, `tasks/`, `ci/`, `scripts/` | Example applications, `cargo xtask` helpers, CI and test-runner scripts |

Some crates under `apps/` and `utils/` are excluded from the workspace and have their own lockfiles and toolchains (see `exclude` in the root `Cargo.toml`).

### Layers of the `tfhe` crate

Each layer is a module in `tfhe/src/`, built only on the layers below it. `core_crypto` is always compiled. The other layers need a Cargo feature: `boolean`, `shortint`, `integer`, and `high_level_api` comes with `integer`.

| Layer | Works on | Responsibility |
|---|---|---|
| `core_crypto` | LWE/GLWE ciphertexts and keys | Cryptographic primitives: encryption, keyswitch, programmable bootstrap (PBS), FFT. No notion of message semantics |
| `shortint` (and the independent, legacy `boolean`: add no new features to it) | One LWE ciphertext holding a few message and carry bits | Small-integer arithmetic and lookup tables via PBS; owns the parameter sets and tracks noise |
| `integer` | Vectors of shortint blocks (radix or CRT) | Arbitrary-size integer arithmetic, carry propagation, parallel algorithms; `gpu/` and `hpu/` hold the backend variants |
| `high_level_api` | `FheUint*`, `FheInt*`, `FheBool`, … (re-exported at the crate root) | Typed user API with operator overloading, key management and backend dispatch |

Alongside the layers: `strings/` (on `integer`), `zk/`, `transciphering/`, and the bindings `c_api/` and `js_on_wasm_api/`, which wrap the other layers.

Things each layer expects that are easy to miss:

- **shortint** ciphertexts carry a `Degree` (bound on the plaintext value) and a `NoiseLevel`. Every operation must update both; getting them wrong produces silently incorrect results rather than errors. The degree must stay within the server key's `max_degree` (`MaxDegree::validate`). Set the noise level with `set_noise_level`, which takes the server key's `max_noise_level` and checks it only in tests and with the `noise-asserts` feature.
- **shortint** in code that supports more than one atomic pattern, take the `AtomicPatternKind` from the key or the parameters. Build `Standard` from a PBS order only in types or paths that support only the standard pattern, and make those paths reject (panic or error) a key or parameters with another pattern.
- **integer** `unchecked_*` operations assume the input blocks have room in their carries and in their noise budget. Default operations (no prefix, e.g. `add_parallelized`) must accept any valid input (clean it if necessary) and must return clean outputs. Clean means empty carries and noise at most nominal (`is_clean()`). A shortcut that skips a bootstrap must still guarantee both. Many existing prechecks call `block_carries_are_empty()`; new prechecks use `is_clean()`.
- **integer** to split a clear scalar into a fixed number of blocks, use `BlockDecomposer::with_block_count`. It sign-extends signed values; padding with zeros gives wrong results for negative numbers.
- **high_level_api** keeps the server key in a thread-local, so `set_server_key` is needed on every thread. Operations dispatch by matching on `InternalServerKey` (CPU, CUDA, HPU): a new operation needs an arm for each backend.
- **high_level_api** errors name the public operation and the `Fhe*` types, not types from lower layers.
- The `gpu` feature changes the parameters picked by `ConfigBuilder::default()`.

### Adding a GPU operation

One operation spans several layers; use an existing one (e.g. `abs`) as the template:

1. C ABI declaration (`scratch_*`, compute, `cleanup_*`) and CUDA implementation in `backends/tfhe-cuda-backend/cuda/`.
2. `backends/tfhe-cuda-backend/src/bindings.rs` is bindgen output but is committed: rebuild to regenerate it and commit the result. A new header must be added to both `wrapper.h` and the watch list in `build.rs`.
3. FFI wrapper and `CudaServerKey` method in `tfhe/src/integer/gpu/`.
4. `InternalServerKey::Cuda` arm in `high_level_api`.
5. GPU tests reuse the CPU test bodies through `GpuFunctionExecutor`.

Changes to the CUDA crates are also subject to semver and version-bump checks in CI.

- New FFI interfaces take key parameters through `params_ffi()`, not as separate `u32` arguments for dimension, level or base log.
- Reusable workspace must be allocated in `scratch_*` and freed in the matching `cleanup_*`, which calls the buffer's `release()`. `release()` must synchronize the stream before it returns (directly or through a sub-buffer's `release()`), so that queued GPU operations complete before the caller continues. `make semgrep_and_lint_gpu_code` checks the scratch/cleanup pairing at the Rust call sites and that each `release()` synchronizes.
- `make fmt` formats only Rust. After a change to C++ or CUDA code, run `make fmt_gpu`, which needs `clang-format-15` and `cmake-format`.
- In `integer`, GPU algorithms go in `integer/gpu/`. CPU algorithm modules get no `cfg(feature = "gpu")` gates; shared test modules can have them.

### Parameters and performance

Production parameters have 2 message bits and 2 carry bits (e.g. `PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`). An operation meets these rules:

1. **Fast on production parameters.** Its algorithm minimizes the number of PBS and the PBS depth for these parameters, using a dedicated path if that is the only way (e.g. `count_bits_2_2` in `integer/server_key/radix_parallel/count_zeros_ones.rs`).
2. **Correct or rejected on every other set.** Other sets go, in order of preference, through: the same optimization if it needs no complex dedicated code; a generic, slower path (`count_bits_naive`); or an explicit rejection (error or panic with a clear message) at the entry point, if supporting them would increase the overall complexity. Never an incorrect result.
3. **Dispatch at the entry point.** The choice of path is made once, on the message and carry moduli, not spread through the algorithm.
4. **Every path is tested:** production parameters and at least one set going through each other path or the rejection.
5. The PR states how non-production sets are handled and why.

For a new operation, design the algorithm for production parameters first (rule 1). If it is not correct for the other sets as written, choose their handling (rule 2). Propose a rejection to the user before implementing it. Then write the dispatch (rule 3) and the tests (rule 4). Keep the code simple and lean where possible.

- **Do not invent parameters.** Parameter sets are produced by external tooling and security estimation. Never edit the numeric values of existing parameters. Parameters are versioned per release under `tfhe/src/shortint/parameters/v*_*`; the parameters of a released version are frozen.
- When adding a set, keep the release module, `aliases.rs` and the `VEC_ALL_*` lists in sync (the lists feed the security-estimation CI). In `tfhe/src/js_on_wasm_api/shortint.rs`, new parameters must be appended, never inserted.
- A configuration that combines compute, compact public key, compression, noise squashing or re-randomization parameters must start from the `MetaParameters` bundle of the target backend. Sets that are each valid can still be incompatible with each other.

## Commands

- Run things through `make`, which sets the right toolchain, features and flags. Tests use the stable toolchain from `rust-toolchain.toml`; fmt, clippy and docs use the nightly named in `nightly-toolchain.txt` (`make install_rs_check_toolchain`). Plain `cargo fmt` / `cargo clippy` on stable will not match CI.
- `tfhe`'s default features build only `core_crypto`. For the other layers, pass their feature (`shortint`, `integer`, …).
- Checks before pushing: `make fpcc` is the fast subset (formatting, typos, doc checks; no clippy). `make pcc` is the full set CI runs and is slow; prefer the per-layer target for what you touched (`make clippy_core`, `clippy_shortint`, `clippy_integer`, …). `make conformance` rewrites files (formatting and newlines). For a broad clippy check that needs no CUDA install, see "GPU code without a GPU".
- Clippy runs with `-D warnings` over several feature combinations per layer. Code behind `cfg(feature = ...)` is only checked by the matching make target.

### Running tests

The shortint, integer and high-level API suites take hours and many GB of RAM. Never run a whole suite to validate a change; run one test with the features of its layer:

```bash
RUSTFLAGS="-C target-cpu=native" cargo test --profile devo \
  --features=integer,internal-keycache -p tfhe -- \
  integer::block_decomposition::tests::test_bit_block_decomposer --exact
```

- Take the feature list from the layer's `test_*` target in the Makefile (`test_core_crypto`, `test_shortint`, `test_integer`, `test_high_level_api`, …).
- `--profile devo` is optimized without LTO and compiles much faster than the Makefile default (`release`, fat LTO). `make test_integer CARGO_PROFILE=devo` runs the whole integer suite with this profile.
- Most shortint/integer tests are generated per parameter set by `create_parameterized_test!`; filter on the function name to run every variant, or on the full generated name for one.
- `FAST_TESTS` and `NIGHTLY_TESTS` select subsets of tests in the CI test scripts (`scripts/test_filtering.py`). `NIGHTLY_TESTS` has nothing to do with the nightly toolchain.
- `.lfsconfig` disables automatic Git LFS fetching. Test data is pulled by `make pull_*` targets (`pull_backward_compat_data`, `pull_test_vectors`, …).
- Investigate each test failure. Do not call a failure "pre-existing" or "unrelated" until you have followed the call chain and found the cause.
- Test the success path, not only the error paths.

### GPU code without a GPU

`DOCS_RS=1` makes the CUDA build scripts skip the real CUDA build, so GPU code can be type-checked and linted without a CUDA toolchain or device:

```bash
DOCS_RS=1 make clippy_gpu
```

This only checks that the code compiles and lints; it cannot run GPU code. Code behind `cfg(feature = "gpu")` is not seen by a non-GPU build, so lint it this way whenever you touch it. The target covers `boolean`, `shortint`, `integer`, `zk-pok` and GPU code with all targets, so it is also a broad check for other changes. `DOCS_RS=1` also skips the regeneration of the bindings: regenerate `bindings.rs` on a machine with CUDA.

## Serialization and backward compatibility

Serialized data from past releases must stay readable. This is the most common source of CI failures on otherwise correct changes.

- Any type deriving `Serialize`/`Deserialize` must also derive `Versionize`, with a dispatch enum in the layer's `backward_compatibility/` module. The `serialize_without_versionize` lint (`make tfhe_lints`) checks only that `Serialize` types implement `Versionize`.
- Changing the layout of a versioned type (fields or variants added, removed, retyped, reordered or renamed) requires keeping the old layout as a versioned snapshot, appending a variant to the dispatch enum (never reorder or rename existing ones) and implementing `Upgrade`. Procedure: `utils/tfhe-versionable/README.md`.
- Renaming a type that implements `Named` is a compatibility break.
- New versioned types or versions need historical test data: `utils/tfhe-backward-compat-data/README.md`. Generate it from the shared small `INSECURE_*` parameter sets in that crate, not from production parameters: the data is stored in Git LFS and production keys add gigabytes.

## Security rules

- **Deserialized data is untrusted.** Data coming from outside is expected to go through `safe_deserialize_conformant` (size limit plus conformance check against the expected parameters) before use; `safe_deserialize` skips the conformance check. Code that runs on deserialized data before conformance (custom `Deserialize` impls, `Upgrade` impls) and conformance itself must not panic or allocate based on attacker-controlled sizes.
- Conformant inputs must not make code panic, and must not cost more memory or compute than the expected parameters allow. Every invariant that later code relies on, including sizes and counts that drive cost, must be checked by the type's `is_conformant`. Tests for tampered data assert that conformance rejects it.
- Avoid `unwrap`, `expect` and indexing on values derived from external input; return errors instead.
- Validate sizes with checked arithmetic before allocations and FFI conversions. Return an error for invalid external data. Use assertions only for internal invariants and caller preconditions.
- For a fix where external input can cause a panic, an abort or a GPU fault, the commit message, PR text, comments, test names and new panic or error messages describe only the code change, not the effect of the bug. Report the details through the process in `SECURITY.md`. If you are not sure, show the text to the user first.

## Code style

- Match the surrounding code: naming, comment density, module structure. When an established in-repo pattern exists for a situation, copy it rather than inventing a variant. When you introduce a new helper or constant, replace every existing occurrence it covers instead of leaving mixed conventions.
- Extend existing functions, helpers and parameterized tests to cover the new case. Do not copy them. Reuse test helpers from lower layers. Versioned type snapshots are the exception: they are copies on purpose.
- Use the narrowest visibility that works: no modifier if only the module and its descendants use an item, then `pub(super)`, `pub(in path)`, and `pub(crate)` only for real crate-wide use.
- Prefer making the code explicit (naming, types, a small function) over commenting it. Comment only what the code can't say: why, non-obvious invariants, spec or paper references. For a workaround of an upstream limitation, link the upstream issue. Comments and identifiers describe the code as it stands: never mention the change, the request or a previous version ("now uses…", "fixed…", a `new_foo` or `foo_v2` next to the `foo` it replaces). Versioned type snapshots (`FooV0`, `FooV1`, …) are the exception.

## Conventions

- Commit messages are checked on every commit of a PR by `.github/workflows/check_commit.yml`: conventional format with a restricted type list (`ci` and `build` are not accepted; use `chore(ci)`), a line-length limit, and signed commits. Mark breaking changes, including serialization breaks, with `!`. Rebase on `main`; no merge commits.
- PRs containing AI-generated code must say so in the description and be human-reviewed (`CONTRIBUTION_GUIDELINES.md`). Other parts of that file lag behind the Makefile.
- Every Rust code block in `tfhe/docs/**/*.md` must be registered with `doctest!` in `tfhe/src/test_user_docs.rs`. Doc file and directory names use dashes, not underscores.
- No call to the `dbg` macro in any tracked file. The check is a plain text search, so do not write the macro with its `!` in comments or docs either. `Cargo.lock` must be up to date.
- CI decides which test workflows run from hand-written path filters in `.github/workflows/`. When you change a `make test_*` target, its launcher script or what it depends on, update the filters of the workflows that run it.
- Each published crate must build from its crates.io package alone. Build scripts and CMake files must not read files from sibling crates. The CUDA build scripts pass shared paths through `links` and `DEP_*` variables.
- Files starting with an "autogenerated" header (e.g. in `core_crypto/commons/noise_formulas/`) must not be edited by hand.
