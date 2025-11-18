# Project specific lints for TFHE-rs
This tool is based on [dylint](https://github.com/trailofbits/dylint).

## Usage
From TFHE-rs root folder:
```
make tfhe_lints
```

## `serialize_without_versionize`

### What it does
For every type that implements `Serialize`, checks that it also implement `Versionize`

### Why is this bad?
If a type is serializable but does not implement Versionize, it is likely that the
implementation has been forgotten.

### Example
```rust
#[derive(Serialize)]
pub struct MyStruct {}
```
Use instead:
```rust
#[derive(Serialize, Versionize)]
#[versionize(MyStructVersions)]
pub struct MyStruct {}
```

## Updating to new toolchains
The dylint library is frequently updated too new toolchains. To update the tool to the latest
supported toolchain, simply run the following command in this folder:
```
cargo dylint upgrade
```

Since the tool uses the Rust compiler API, which is unstable, manual adjustments to the code may be
necessary.
