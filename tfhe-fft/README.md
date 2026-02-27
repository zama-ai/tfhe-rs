tfhe-fft is a pure Rust high performance fast Fourier transform library
that processes vectors of sizes that are powers of two. It was made to be used
as a backend in Zama's [TFHE-rs](https://docs.zama.org/tfhe-rs) library.

This library provides two FFT modules:
 - The ordered module FFT applies a forward/inverse FFT that takes its input in standard
 order, and outputs the result in standard order. For more detail on what the FFT
 computes, check the ordered module-level documentation.
 - The unordered module FFT applies a forward FFT that takes its input in standard order,
 and outputs the result in a certain permuted order that may depend on the FFT plan. On the
 other hand, the inverse FFT takes its input in that same permuted order and outputs its result
 in standard order. This is useful for cases where the order of the coefficients in the
 Fourier domain is not important. An example is using the Fourier transform for vector
 convolution. The only operations that are performed in the Fourier domain are elementwise, and
 so the order of the coefficients does not affect the results.

Additionally, an optional 128-bit negacyclic FFT module is provided.

## Features

 - `std` (default): This enables runtime arch detection for accelerated SIMD
   instructions, and an FFT plan that measures the various implementations to
   choose the fastest one at runtime.
 - `fft128`: This flag provides access to the 128-bit FFT, which is accessible in the
   [`fft128`] module.
 - `avx512` (default): This enables AVX512F instructions on CPUs that support them to further
   speed up the FFT.
 - `serde`: This enables serialization and deserialization functions for the
   unordered plan. These allow for data in the Fourier domain to be serialized
   from the permuted order to the standard order, and deserialized from the
   standard order to the permuted order. This is needed since the inverse
   transform must be used with the same plan that computed/deserialized the
   forward transform (or more specifically, a plan with the same internal base
   FFT size).

## Example

```rust
use tfhe_fft::c64;
use tfhe_fft::ordered::{Method, Plan};
use dyn_stack::{PodBuffer, PodStack};
use num_complex::ComplexFloat;
use std::time::Duration;

fn main() {
    const N: usize = 4;
    let plan = Plan::new(4, Method::Measure(Duration::from_millis(10)));
    let mut scratch_memory = PodBuffer::try_new(plan.fft_scratch()).unwrap();
    let stack = PodStack::new(&mut scratch_memory);

    let data = [
        c64::new(1.0, 0.0),
        c64::new(2.0, 0.0),
        c64::new(3.0, 0.0),
        c64::new(4.0, 0.0),
    ];

    let mut transformed_fwd = data;
    plan.fwd(&mut transformed_fwd, stack);

    let mut transformed_inv = transformed_fwd;
    plan.inv(&mut transformed_inv, stack);

    for (actual, expected) in transformed_inv.iter().map(|z| z / N as f64).zip(data) {
        assert!((expected - actual).abs() < 1e-9);
    }
}
```

## Links

 - [Zama](https://www.zama.org/)
 - [TFHE-rs Sources](https://github.com/zama-ai/tfhe-rs)

## License

This software is distributed under the BSD-3-Clause-Clear license with an
exemption that gives rights to use our patents for research, evaluation and
prototyping purposes, as well as for your personal projects.

If you want to use tfhe-fft in a commercial product however, you will need to
purchase a separate commercial licence.

If you have any questions, please contact us at `hello@zama.org.`
