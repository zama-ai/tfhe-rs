# TFHE-lints

A collection of rust lints specific to the **TFHE-rs** project. This tool is built using [rustc-tools](https://github.com/GuillaumeGomez/rustc-tools).

## List of lints
- `serilaize_without_versionize`: warns if `Serialize` is implemented without `Versionize`

## Installation

### Install the inner tool
```
cargo install --path ../cargo-tfhe-lints-inner
```

### Install this wrapper
```
cargo install --path .
```

## Usage
Use it as any other cargo tool:
```
cargo tfhe-lints
```
You can specify features like you would do with clippy.
