# Project specific lints for TFHE-rs

This tool is based on [dylint](https://github.com/trailofbits/dylint).

## Usage

From TFHE-rs root folder:

```
make tfhe_lints
```

## Lints

### `serialize_without_versionize`

**What it does:**
For every type that implements `Serialize`, checks that it also implements `Versionize`.

**Why is this bad?**
If a type is serializable but does not implement `Versionize`, it is likely that the
implementation has been forgotten.

**Example:**

```rust
// Bad
#[derive(Serialize)]
pub struct MyStruct {}

// Good
#[derive(Serialize, Versionize)]
#[versionize(MyStructVersions)]
pub struct MyStruct {}
```

### `invalid_versionize_dispatch`

**What it does:**
For every enum that derives `VersionsDispatch`, checks that:

1. The enum name ends with `Versions`.
2. Variants are named `V0`, `V1`, ... in order.
3. Inner types follow the naming convention: `{Base}V0`, `{Base}V1`, ... for older
   versions and `{Base}` (without a version suffix) for the last (current) variant,
   where `{Base}` is the enum name without the `Versions` suffix.

**Why is this bad?**
Consistent naming across all dispatch enums makes it much easier to spot versioning
mistakes during code review.

**Example:**

```rust
// Bad: enum name missing Versions suffix
#[derive(VersionsDispatch)]
pub enum MyStructVer {
    V0(MyStructV0),
    V1(MyStruct),
}

// Bad: variant names not following V0, V1, ... convention
#[derive(VersionsDispatch)]
pub enum MyStructVersions {
    First(MyStructV0),
    Second(MyStruct),
}

// Good
#[derive(VersionsDispatch)]
pub enum MyStructVersions {
    V0(MyStructV0),
    V1(MyStruct),
}
```

## Snapshot lint (`tfhe_lints_snapshot`)

### `versions_dispatch_snapshot`

**What it does:**
Collects metadata about enums implementing `VersionsDispatch`, recording each variant's
fully-resolved inner type path and a SHA-256 hash of its fields. Also collects `Upgrade`
trait implementations and hashes their body. The collected data is written to JSON files
for use by the backward-compatibility checker.

**Why is this needed?**
Proc macros only see token-level type names (e.g. `ServerKey`) without full paths, causing
name collisions. This lint runs inside the compiler with access to `TyCtxt`, providing
canonical full paths and full field-level type information for hashing.

**Output format:**

```json
[
  {
    "enum_name": "my_crate::backward_compat::MyTypeVersions",
    "variants": [
      {
        "index": 0,
        "inner_type_def_path": "my_crate::backward_compat::MyTypeV0",
        "inner_type_display": "my_crate::backward_compat::MyTypeV0",
        "struct_hash": "aabbcc..."
      },
      {
        "index": 1,
        "inner_type_def_path": "my_crate::MyType",
        "inner_type_display": "my_crate::MyType",
        "struct_hash": "ddeeff..."
      }
    ],
    "upgrades": [
      {
        "source_def_path": "my_crate::backward_compat::MyTypeV0",
        "target_def_path": "my_crate::MyType",
        "body_hash": "112233..."
      }
    ]
  }
]
```

## Backward compatibility checking

Snapshots are generated and compared using targets defined in `utils/tfhe-lints/Makefile`
(included by the project root `Makefile`).

### Generate the base snapshot

Run this on the main branch. The generated files should be committed.

```
make backward-snapshot-base
```

This runs the snapshot lint on `tfhe`, `tfhe-zk-pok` and `tfhe-csprng`, writing results
to `utils/tfhe-lints/snapshots/` with the `base` suffix.

### Generate the head snapshot

Run this on the feature branch.

```
make backward-snapshot-head
```

This creates a `head/` subdirectory in the snapshots folder with results from the same
crates.

### Check backward compatibility

Compare base and head snapshots for breaking changes:

```
make backward-snapshot-check
```

By default this fails if new enums are present in head but not in base. To allow new
enums:

```
make backward-snapshot-check ALLOW_ADDITIONAL_ENUMS=true
```

The base and head directories/suffixes can be overridden:

```
make backward-snapshot-check BASE_DIR=../base/utils/tfhe-lints/snapshots BASE_FILE=base HEAD_DIR=utils/tfhe-lints/snapshots/head HEAD_FILE=head
```

### Generate a diff report

Generate a markdown report comparing two snapshots:

```
make backward-snapshot-generate
```

The output file defaults to `../report.md` and can be overridden with `OUTPUT_FILE`.

### What the checker verifies

The `tfhe-backward-compat-checker` compares a base snapshot against a head snapshot and
reports errors if:

- An enum was **removed**
- Variants were **removed** from an enum
- A variant's `struct_hash` **changed** (the inner type's fields were modified)
- An upgrade's `body_hash` **changed** (the upgrade implementation was modified)
- An upgrade was **removed**

Adding new enums, new variants, or new upgrades is allowed (not a breaking change).

## Updating to new toolchains

The dylint library is frequently updated to support new toolchains. To update the tool to the
latest supported toolchain, simply run the following command in this folder:

```
cargo dylint upgrade
```

Since the tool uses the Rust compiler API, which is unstable, manual adjustments to the code may be
necessary.
