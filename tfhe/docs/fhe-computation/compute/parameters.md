# Cryptographic Parameters

This document explains how the choice of cryptographic parameters impacts both the security and efficiency of FHE algorithms. The chosen parameters determine the error probability (sometimes referred to failure probability) and overall performance of computations using fully homomorphic encryption. This error probability is due to the noisy nature of FHE computations (see [here](../../getting-started/security-and-cryptography.md) for more details about the encryption process).

All parameter sets provide at least 128-bits of security according to the [Lattice-Estimator](https://github.com/malb/lattice-estimator). 

## Default parameters
Currently, the default parameters use blocks that contain 2 bits of message and 2 bits of carry - a tweaked uniform (TUniform, defined [here](../../getting-started/security-and-cryptography.md#noise)) noise distribution, and have a bootstrapping failure probability $$p_{error} \le 2^{-128}$$.
These are particularly suitable for applications that need to be secure in the IND-CPA^D model (see [here](../../getting-started/security-and-cryptography.md#security) for more details).

When using the high-level API of **TFHE-rs**, you can create a key pair using the default recommended set of parameters. For example:

```rust
use tfhe::{ConfigBuilder, generate_keys};

fn main() {
    let config = ConfigBuilder::default().build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);

    // encryption and FHE operations
}
```

{% hint style="info" %}
These default parameters may be updated with in future releases of **TFHE-rs**, potentially causing incompatibilities between versions. For production systems, it is therefore recommended to specify a fixed parameter set.
{% endhint %}

## Parameters versioning and naming scheme

Parameter sets are versioned for backward compatibility. This means that each set of parameters can be tied to a specific version of **TFHE-rs**, so that they remain unchanged and compatible after an upgrade.

All parameter sets are stored as variables inside the `tfhe::shortint::parameters` module, with submodules named after the versions of **TFHE-rs** in which these parameters where added. For example, parameters added in **TFHE-rs** v1.0 can be found inside `tfhe::shortint::parameters::v1_0`.

The naming convention of these parameters indicates their capabilities. Taking `tfhe::parameters::v1_0::V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128` as an example:
- `V1_0`: these parameters were introduced in **TFHE-rs** v1.0
- `MESSAGE_2`: LWE blocks include 2 bits of message
- `CARRY_2`: LWE blocks include 2 bits of carry
- `KS_PBS`: the keyswitch is computed before the bootstrap
- `TUNIFORM`: the tweaked uniform noise distribution is used
- `2M128`: the probability of failure for the bootstrap is $$2^{-128}$$

For convenience, aliases are provided for the most used sets of parameters and stored in the module `tfhe::shortint::parameters::aliases`. Note, however, that these parameters are not stable over time and are always updated to the latest **TFHE-rs** version. For this reason, they should only be used for prototyping and are not suitable for production use cases.


## How to choose the parameter sets
You can override the default parameters with the `with_custom_parameters(block_parameters)` method of the `Config` object. For example, to use a Gaussian distribution instead of the TUniform one, you can modify your configuration as follows:

```rust
use tfhe::{ConfigBuilder, generate_keys};
use tfhe::shortint::parameters::current_params::V1_5_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;

fn main() {
    let config =
        ConfigBuilder::with_custom_parameters(V1_5_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128)
            .build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);

    // encryption and FHE operations
}

```
