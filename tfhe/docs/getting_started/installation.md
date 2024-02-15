# Installation



## Importing into your project

To use `TFHE-rs` in your project, you first need to add it as a dependency in your `Cargo.toml`.

If you are using an `x86_64` machine running a Unix-like OS:
```toml
tfhe = { version = "0.6.0", features = [ "boolean", "shortint", "integer", "x86_64-unix" ] }
```

If you are using an `ARM` machine running a Unix-like OS:
```toml
tfhe = { version = "0.6.0", features = [ "boolean", "shortint", "integer", "aarch64-unix" ] }
```

If you are using an `x86_64` machines with the [`rdseed instruction`](https://en.wikipedia.org/wiki/RDRAND) running Windows:

```toml
tfhe = { version = "*", features = ["boolean", "shortint", "integer", "x86_64"] }
```


{% hint style="info" %}
You need to use a Rust version >= 1.73 to compile TFHE-rs.
{% endhint %}

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
