
# Noise Sampling & Assurance Tool

Before a `Makefile` is done (**TODO**?), we run the tool (only analysis of previously gathered samples) in `./src` via

```bash
./bin/python3 external_product_correction.py --chunks 192 --rust-toolchain nightly-2024-08-19 --analysis-only --dir multi-bit-sampling/gf2/ -- --algorithm multi-bit-ext-prod --multi-bit-grouping-factor 2
```
where Python has its local environment and additional lib's installed locally, some of the following commands may help:
```bash
python3 -m venv .
./bin/pip install scipy scikit-learn
```
Also, the current Rust toolchain can be found in `/toolchain.txt`


## AWS

  - login to AWS web UI, start your instance and login via `ssh`
  - init screen session via `$ screen`
  - run the command:
```bash
$ rm -r path/to/samples ; ./bin/python3 external_product_correction.py --chunks <number-of-cpus> --rust-toolchain nightly-x86_64-unknown-linux-gnu --dir path/to/samples -- --algorithm multi-bit-ext-prod --multi-bit-grouping-factor <gf> > path/to/output.dat ; sudo poweroff
```
  - e.g.
```bash
$ rm -r fft-kara/samples-gf=2 ; ./bin/python3 external_product_correction.py --chunks 64 --rust-toolchain nightly-x86_64-unknown-linux-gnu --dir fft-kara/samples-gf=2/ -- --algorithm multi-bit-ext-prod --multi-bit-grouping-factor 2 > fft-kara/gf=2.dat ; sudo poweroff
```
  - detach the screen with `Ctrl + A`, then `D`
    - list active screen sessions via `screen -ls`
    - reattach to screen session via `screen -r <session_id>`
  - exit ssh

### Forgot to start `screen`?

Solution: [https://serverfault.com/questions/55880/moving-an-already-running-process-to-screen](https://serverfault.com/questions/55880/moving-an-already-running-process-to-screen)


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

  - `Makefile`? part of CI workflow? test report?
    - for now, improve output: meaning of printed values, ...
  - rework as an assurance tool for all op's (not only for external product)
    - make a macro that generates these tests?
    - put this macro "near" each tested operation (i.e., greatly simplify adding new op's)
  - use noise formulas extracted from the latest optimizer (was there a PR on that?)
