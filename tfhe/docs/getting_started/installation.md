# Installation



## Importing into your project

To use `TFHE-rs` in your project, you first need to add it as a dependency in your `Cargo.toml`:

```toml
tfhe = { version = "0.3.0", features = [ "boolean", "shortint", "integer", "x86_64-unix" ] }
```

{% hint style="success" %}
When running code that uses `TFHE-rs`, it is highly recommended to run in release mode with cargo's `--release` flag to have the best possible performance
{% endhint %}



## Supported platforms

TFHE-rs is supported on Linux (x86, aarch64), macOS (x86, aarch64) and Windows (x86 with `RDSEED` instruction).

| OS      | x86           | aarch64          |
| ------- | ------------- | ---------------- |
| Linux   | `x86_64-unix` | `aarch64-unix`\* |
| macOS   | `x86_64-unix` | `aarch64-unix`\* |
| Windows | `x86_64`      | Unsupported      |

{% hint style="info" %}
Users who have ARM devices can use TFHE-rs by compiling using the `nightly` toolchain (see
[Configuration](../how_to/rust_configuration.md) for more details).
{% endhint %}
