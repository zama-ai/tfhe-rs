# Cryptographic Parameters

`integer` does not come with its own set of parameters. Instead, it relies on parameters from `shortint`. Currently, parameter sets having the same space dedicated to the message and the carry (i.e. `PARAM_MESSAGE_{X}_CARRY_{X}` with `X` in \[1,4]) are recommended. See [here](../shortint/parameters.md) for more details about cryptographic parameters, and [here](operations.md) to see how to properly instantiate integers depending on the chosen representation.
