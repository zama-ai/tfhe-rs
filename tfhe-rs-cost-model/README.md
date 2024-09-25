
# Noise Sampling & Assurance Tool

Before a `Makefile` is done (**TODO**?), we run the tool (only analysis of previously gathered samples) in `./src` via
```bash
./bin/python3 external_product_correction.py --chunks 192 --rust-toolchain nightly-2024-08-19 --analysis-only --dir multi-bit-sampling/gf2/ -- --algorithm multi-bit-ext-prod --multi-bit-grouping-factor 2
```
where Python has its local environment and additional lib's installed locally, some of the following commands may help:
```bash
python3 -m venv .
./bin/pip install scipy
./bin/pip install scikit-learn
```
Also, the current Rust toolchain can be found in `/toolchain.txt`


## "Advanced"

The command that is called can be called directly as
```bash
$ RUSTFLAGS="-C target-cpu=native" cargo run --release -- --help
```
which writes down the list of parameters that can also be given to the analyzing tool after `--`.


## How It Works

???

  - all is orchestrated by `external_product_correction.py`
  - Rust code is compiled & executed ... this generates vector(s) of errors
  - samples are analyzed and curves are fitted


## Nice-To-Have

  - `Makefile`?
  - analysis tool not only for the external product, but as an assurator for other op's, too
  - use noise formulas extracted from the latest optimizer
  - simple interface to add custom circuits easily (like compression)
  - improve output:
    - meaning of printed values
  - ...
