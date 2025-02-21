# Cryptographic Parameters

The security and efficiency of the FHE algorithms is impacted by the choice of cryptographic parameters.

All parameter sets provide at least 128-bits of security according to the [Lattice-Estimator](https://github.com/malb/lattice-estimator). The recommended parameters for the CPU have an error probability of less than $$2^{-128}$$ when using programmable bootstrapping. This error probability is due to the noisy nature of FHE computations (see [here](../../getting\_started/security\_and\_cryptography.md) for more details about the encryption process).

## Default parameters

When using the high-level API of **TFHE-rs**, you can create a key pair using the default recommended set of parameters with the `Config` object:

```rust
use tfhe::{ConfigBuilder, generate_keys};

fn main() {
    let config = ConfigBuilder::default().build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);

    // encryption and FHE operations
}
```

These default parameters may be updated with every new release of **TFHE-rs**. They use blocks of 2 bits of message and 2 bits of carry, a tweaked uniform (TUniform) noise distribution and a $$2^{-128}$$ failure probability for the PBS.

It is possible to override the default parameters with the `with_custom_parameters(block_parameters)` method of the `Config` object. For example, to use a Gaussian distribution instead of the TUniform one you can do:

```rust
use tfhe::{ConfigBuilder, generate_keys};
use tfhe::shortint::parameters::v1_0::V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;

fn main() {
    let config =
        ConfigBuilder::with_custom_parameters(V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128)
            .build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);

    // encryption and FHE operations
}

```

## Parameters versioning and naming scheme

Parameter sets are versioned for backward compatibility. That way, it is possible to tie the set of parameters to a specific version of **TFHE-rs**, and be confident that the underlying parameters won't change after an upgrade.

The various parameter sets are stored as variables inside the `tfhe::shortint::parameters` module, in submodules named after the versions of **TFHE-rs** where these parameters where added. For example, parameters added in **TFHE-rs** v1.0 can be found inside `tfhe::shortint::parameters::v1_0`.

The names of the parameters give some indications of the capabilities they provide. For example, `tfhe::parameters::v1_0::V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128` can be decoded that way:
- `V1_0`: these parameters were introduced in **TFHE-rs** v1.0
- `MESSAGE_2`: LWE blocks include 2 bits of message
- `CARRY_2`: LWE blocks include 2 bits of carry
- `KS_PBS`: the keyswitch is computed before the bootstrap
- `TUNIFORM`: the tweaked uniform noise distribution is used
- `2M128`: the probability of failure for the bootstrap is $$2^{-128}$$

For convenience, aliases are provided for the most used sets of parameters. They are found in the module `tfhe::shortint::parameters::aliases`. Note, however, that these parameters are not stable in time and are always updated to the latest **TFHE-rs** version. For this reason, they should only be used for prototyping and are not suitable for production use cases.
