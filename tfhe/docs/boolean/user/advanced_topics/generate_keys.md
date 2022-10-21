# Key Generation

There are two ways to generate keys with `concrete_boolean`:
- use one of the provided parameter sets;
- create a custom parameter set.

## Provided Parameter Sets

To generate a pair of client/server keys using one of the default parameter sets, you can use
the helper function `gen_keys`:
```rust
extern crate concrete_boolean;
use concrete_boolean::gen_keys;

// We generate a set of client/server keys, using the default parameters:
let (client_key, server_key) = gen_keys();
```

It will use `DEFAULT_PARAMETERS` to generate the two keys.

To generate a pair of keys with a different parameter set, such as `TFHE_LIB_PARAMETERS`, you can
use the following function:

```rust
extern crate concrete_boolean;
use concrete_boolean::client_key::ClientKey;
use concrete_boolean::server_key::ServerKey;
use concrete_boolean::parameters::TFHE_LIB_PARAMETERS;

// generate the client key set
let cks = ClientKey::new(TFHE_LIB_PARAMETERS);

// generate the server key set
let sks = ServerKey::new(&cks);
```


## Custom Parameter Sets

If you are a cryptographer and know enough about FHE to tune the cryptographic parameters
yourself, `concrete-boolean` offers the possibility to use your own parameter set.

Note that as soon as you do not use the default parameters, it is up to
you to ensure the **correctness** and **security** of your program.

To generate a set of client/server keys using different parameters, you should use the
constructor.


```rust
extern crate concrete_boolean;
extern crate concrete_commons;
use concrete_boolean::parameters::BooleanParameters;
use concrete_boolean::client_key::ClientKey;
use concrete_boolean::server_key::ServerKey;
use concrete_commons::parameters::*;
use concrete_commons::dispersion::*;

// You can create your own set of parameters, at your own risks
let parameters = unsafe{
    BooleanParameters::new_insecure(
        LweDimension(586),
        GlweDimension(2),
        PolynomialSize(512),
        StandardDev(0.00008976167396834998),
        StandardDev(0.00000002989040792967434),
        DecompositionBaseLog(8),
        DecompositionLevelCount(2),
        DecompositionBaseLog(2),
        DecompositionLevelCount(5),
    )
};

// We generate the client key from the parameters:
let client_key = ClientKey::new(parameters);
let server_key = ServerKey::new(&client_key);
```
