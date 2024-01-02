# Managing Data Through Various TFHE-rs Versions

In what follows, the process to manage data when upgrading the TFHE-rs version (starting from the 0.4.2 release) is given. This details the method to make data, which have initially been generated with an older version of TFHE-rs, usable with a newer version.


## Forward Compatibility Strategy

The current strategy that has been adopted for TFHE-rs is the following:

- TFHE-rs has a global `SERIALIZATION_VERSION` constant;
- When breaking serialization changes are introduced, this global version is bumped;
- Using dedicated serialization primitives which check this constant. If the data is incompatible, these primitives return an error.

To be able to use older serialized data with newer versions, the following is done on new major releases:

- A minor update is done to the previously released branch to add the new release as an optional dependency;
- Conversion code is added to the previous branch to be able to load old data and convert it to the new data format.

In practice, if we take the 0.5 release as a concrete example, here is what will happen:

- 0.5.0 is released with breaking changes to the serialization;
- 0.4.2 has tfhe@0.5.0 as optional dependency gated by the `forward_compatibility` feature;
- Conversion code is added to 0.4.2, if possible without any user input, but some data migration will likely require some information to be provided by the developer writing the migration code;
- 0.4.2 is released.

{% hint style="info" %}
Note that if you do not need forward compatibility 0.4.2 will be equivalent to 0.4.1 from a usability perspective and you can safely update.
Note also that the 0.5.0 has no knowledge of previous releases.
{% endhint %}

## What it means from a developer perspective

A set of generic tooling is given to allow migrating data by using several workflows. The data migration is considered to be an application/protocol layer concern to avoid imposing design choices.

Examples to migrate data:

An `Application` uses TFHE-rs 0.4.1 and needs/wants to upgrade to 0.5.0 to benefit from various improvements.

Example timeline of the data migration or `Bulk Data Migration`:
- A new transition version of the `Application` is compiled with the 0.4.2 release of TFHE-rs;
- The transition version of the `Application` adds code to read previously stored data, convert it to the proper format for 0.5.0 and save it back to disk;
- The service enters a maintenance period (if relevant);
- Migration of data from 0.4.2 to 0.5.0 is done with the transition version of the `Application`, note that depending on the volume of data this transition can take a significant amount of time;
- The updated version of the `Application` is compiled with the 0.5.0 release of TFHE-rs and put in production;
- Service is resumed with the updated `Application` (if relevant).

The above case is describing a simple use case, where only a single version of data has to be managed. Moreover, it not relevant in the case where the data is so large that migrating it in one go is not doable, or if the service cannot suffer any interruption.

In order to manage more complicated cases, another method called `Migrate On Read`. 

Here is an example timeline where data is migrated only as needed `Migrate On Read`:
- A new version of the `Application` is compiled, it has tfhe@0.4.2 as dependency (the dependency will need to be renamed to avoid conflicts, a possible name is to use the major version like `tfhe_0_4`) and tfhe@0.5.0 which will not be renamed and can be accessed as `tfhe`
- Code to manage reading the data is added to the `Application`:
- The code determines whether the data was saved with the 0.4 `Application` or the 0.5 `Application`, if the data is already up to date with the 0.5 format it can be loaded right away, if it's in the 0.4 format the `Application` can check if an updated version of the data is already available in the 0.5 format and loads that if it's available, otherwise it converts the data to 0.5, saves the converted data to avoid having to convert it every time it is accessed and continue processing with the 0.5 data

The above is more complicated to manage as data will be present on disk with several versions, however it allows to run the service continuously or near-continuously once the new `Application` is deployed (it will require careful routing or error handling as nodes with outdated `Application` won't be able to process the 0.5 data).

Also, if required, several version of TFHE-rs can be "chained" to upgrade very old data to newer formats.
The above pattern can be extended to have `tfhe_0_4` (tfhe@0.4.2 renamed), `tfhe_0_5` (tfhe@0.5.0 renamed) and `tfhe` being tfhe@0.6.0, this will require special handling from the developers so that their protocol can handle data from 0.4.2, 0.5.0 and 0.6.0 using all the conversion tooling from the relevant version.

E.g., if some computation requires version data from version 0.4.2 a conversion function could be called `upgrade_data_from_0_4_to_0_6` and do:

- read data from 0.4.2
- convert to 0.5.0 format using `tfhe_0_4`
- convert to 0.6.0 format using `tfhe_0_5`
- save to disk in 0.6.0 format
- process 0.6.0 data with `tfhe` which is tfhe@0.6.0

## A concrete example for shortint

The following very small sample project shows how some data can be migrated in a project following the pattern explained above:

Cargo.toml:

```toml
[package]
name = "data_migration_tfhe"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
# The project used tfhe 0.4.1, it now depends on the 0.4.2 with the forward compatibility code
tfhe_0_4 = { package = "tfhe", version = "0.4.2", features = [
    "x86_64-unix",
    "boolean",
    "shortint",
    "integer",
    "forward_compatibility",
] }
# The project now uses tfhe 0.5.0 as it's "normal/default" tfhe version for all processing except
# data upgrade, as only old versions will be retrofitted with code to migrate code to newer versions
tfhe = { version = "0.5", features = [
    "x86_64-unix",
    "boolean",
    "shortint",
    "integer",
] }
```

src/main.rs:

```rust
fn old_tfhe_data_generation() -> tfhe_0_4::shortint::Ciphertext {
    use tfhe_0_4::shortint::gen_keys;
    use tfhe_0_4::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    let ct = cks.encrypt(2);

    ct
}

fn data_migration(old_ciphertext: tfhe_0_4::shortint::Ciphertext) {
    use tfhe::shortint::Ciphertext;
    use tfhe_0_4::forward_compatibility::ConvertInto;

    // Here as tfhe_0_4 depends on tfhe 0.5.0 and tfhe 0.5.0 is a dependency of our project the
    // forward compatibility works out of the box using tfhe types and the tfhe_0_4 conversion code
    let new_ct: Ciphertext = old_ciphertext.convert_into();

    println!("{:?}", new_ct.noise_level())
}

fn main() {
    data_migration(old_tfhe_data_generation())
}
```

This will output:

```console
NoiseLevel(18446744073709551615)
```

The noise level here is set at usize::MAX on a 64 bits system, it corresponds to the constant `NoiseLevel::UNKNOWN` from shortint, as the noise level was not a value that was directly tracked in TFHE-rs the noise level is set to this unknown constant when migrating the ciphertext. It is recommended to first apply a PBS to reset the noise level to a known nominal level as some algorithms will always clean ciphertexts which are not at the nominal noise level.

## Breaking changes and additional migration information

The main breaking change going from 0.4.2 to 0.5.0 with respect to data migration is that the High Level API dropped support for `shortint`. The `boolean` format has changed to use `integer`'s `BooleanBlock` under the hood.

This means that any data coming from the High Level API which previously used `boolean` or `shortint` is not supported for the data migration.
