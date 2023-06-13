# high_level_api

The `high_level_api` module main goal is to provide
an API that is higher level than what the `boolean`, `shortint`, `integer`
modules offers.

The way it is done is by exposing FHE types `FheBool`, `FheUint2`, etc
that are closer to the `u8`, `u16` than what Ciphertext are,
this is mainly achieved by overloading operators (`+` , `-`, `*`, etc).

Since all operations (add, sub, etc) have to be done via a `ServerKey`
it means it has to be managed by the `high_level_api`, to hide it in order
to allow operator overloading.

## How the FHE types are created in this module

Crypto parameters `tfhe::boolean::Parameters` and `tfhe::shortint::Parameters`
are what defines the number of bits a Ciphertext can store.

The way the different FHE types are created can be summarized as:

> Instead of having one struct to represent multiple parameters,
> we will create one struct per each parameter we use.


To understand that last sentence a bit more we'll explain a simplified example on shortint:

We want to provide FheUint2, FheUint4 that are based on `tfhe::shortint`

We first create a wrapper struct, that will wrap the Ciphertext type.
This struct is generic over some type called `P`, it is this genericity
that will enable us to easily create our types by using type specialization / type aliases

```rust
struct GenericShortint<P> {
    inner: shortint::Ciphertext
    // other details
}
```

We also create "parameter structs" in order the be able to
specialize our generic wrapper struct with`type FheName = GenericWrapperStruct<PameterStructName>`.

For example, depending on the values in a `shortint::Parameters` instance, the number of bits in the `shortint::Ciphertext`
is not the same:
* `PARAM_MESSAGE_2_CARRY_2_KS_PBS` -> 2 bits of message, 2 bits of carry
* `PARAM_MESSAGE_4_CARRY_4_KS_PBS` -> 4 bits of message, 4 bits of carry
(both are of type `shortint::Parameters`)
And, generally, some ciphertext encrypted with some parameters values A,
will not be compatible with another ciphertext encrypted with some parameters values B.

So in the `high_level_api` we create 2 structs `struct FheUint2Parameters { ... }` and `struct FheUint4Parameters { ... }`
which are made so that FheUint2Parameters only contains `PARAM_MESSAGE_2_CARRY_2_KS_PBS`
and FheUint4Parameters only contains `PARAM_MESSAGE_4_CARRY_4_KS_PBS`. 

This way, we can specialize our wrapper types:
* `type FheUint2 = GenericWrapperStruct<FheUint2Parameters>`
* `type FheUint4 = GenericWrapperStruct<FheUint4Parameters>`
and now we have two disctint types, that have specific crypto parameters associated with them.
Also, they are type safe (can't `+` a FheUint2 to a FheUint4 without a compilatation error
unless the implemenation explicitely allows it since the type are different, which is not the case if you
use the 'raw' shortint api)

In practice it is a bit more complex as we have to introduce traits to internally manipulate the 
"parameter struct", eg a trait to convert the `FheUint2Parameters` and `FheUint4Parameters` back into `shortint::Parameters`,

```rust
pub trait ShortIntegerParameter: Copy + Into< crate::shortint::ClassicPBSParameters> {
    // ...
}
```

The `ShortIntegerParameter` is meant to be implemented on "parameter struct"
that map to specific `shortint::Parameters`, like FheUint2Parameters and FheUint2Parameters
does, and so we require the `Into<shortint::Parameters>` convertion to be able to internally
interact with the shortint API.

The same wrapping proccess is done for ClientKey, ServerKey, PublicKey, etc.
  
