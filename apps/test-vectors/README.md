# Test vectors for TFHE
This folder contains test vectors for the core TFHE-rs algorithms.

The test vectors are located in `data`, and are generated using the sample program in `src/main.rs`.

To re-generate the test vectors, assuming you have [rustup](https://rust-lang.org/tools/install/) installed on your system, simply run the following command in the current folder:
```
cargo run --release
```

See [the data folder](data/README.md) for more information about the generated values.
