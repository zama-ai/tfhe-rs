# Managing Data Through Various TFHE-rs Versions

In what follows, the process to manage data when upgrading the TFHE-rs version (starting from the 0.5.5 release) is given. This page details the methods to make data, which have initially been generated with an older version of TFHE-rs, usable with a newer version.

## Forward Compatibility Strategy

The current strategy that has been adopted for TFHE-rs is the following:

- TFHE-rs has a global `SERIALIZATION_VERSION` constant;
- When breaking serialization changes are introduced, this global version is bumped;
- Safe serialization primitives check this constant upon deserialization, if the data is incompatible, these primitives return an error.

To be able to use older serialized data with newer versions, the following is done on new major TFHE-rs releases:

- A minor update is done to the previously released branch to add the new release as an optional dependency;
- Conversion code is added to the previous branch to be able to load old data and convert it to the new data format.

In practice, if we take the 0.6 release as a concrete example, here is what will happen:

- 0.6.0 is released with breaking changes to the serialization;
- 0.5.5 has tfhe@0.6.0 as optional dependency gated by the `forward_compatibility` feature;
- Conversion code is added to 0.5.5, if possible without any user input, but some data migration will likely require some information to be provided by the developer writing the migration code;
- 0.5.5 is released.

{% hint style="info" %}
Note that if you do not need forward compatibility 0.5.5 will be equivalent to 0.5.3 from a usability perspective and you can safely update.
Note also that the 0.6.0 has no knowledge of previous releases.
{% endhint %}

## What it means from a developer perspective

A set of generic tooling is given to allow migrating data by using several workflows. The data migration is considered to be an application/protocol layer concern to avoid imposing design choices.

Examples to migrate data:

An `Application` uses TFHE-rs 0.5.3 and needs/wants to upgrade to 0.6.0 to benefit from various improvements.

Example timeline of the data migration or `Bulk Data Migration`:
- A new transition version of the `Application` is compiled with the 0.5.5 release of TFHE-rs;
- The transition version of the `Application` adds code to read previously stored data, convert it to the proper format for 0.6.0 and save it back to disk;
- The service enters a maintenance period (if relevant);
- Migration of data from 0.5.5 to 0.6.0 is done with the transition version of the `Application`, note that depending on the volume of data this transition can take a significant amount of time;
- The updated version of the `Application` is compiled with the 0.6.0 release of TFHE-rs and put in production;
- Service is resumed with the updated `Application` (if relevant).

The above case is describing a simple use case, where only a single version of data has to be managed. Moreover, the above strategy is not relevant in the case where the data is so large that migrating it in one go is not doable, or if the service cannot suffer any interruption.

In order to manage more complicated cases, another method called `Migrate On Read` can be used.

Here is an example timeline where data is migrated only as needed with the `Migrate On Read` approach:
- A new version of the `Application` is compiled, it has tfhe@0.5.5 as dependency (the dependency will have to be renamed to avoid conflicts, a possible name is to use the major version like `tfhe_0_5`) and tfhe@0.6.0 which will not be renamed and can be accessed as `tfhe`
- Code to manage reading the data is added to the `Application`:
- The code determines whether the data was saved with the 0.5 `Application` or the 0.6 `Application`, if the data is already up to date with the 0.6 format it can be loaded right away, if it's in the 0.5 format the `Application` can check if an updated version of the data is already available in the 0.6 format and loads that if it's available, otherwise it converts the data to 0.6, saves the converted data to avoid having to convert it every time it is accessed and continue processing with the 0.6 data

The above is more complicated to manage as data will be present on disk with several versions, however it allows to run the service continuously or near-continuously once the new `Application` is deployed (it will require careful routing or error handling as nodes with outdated `Application` won't be able to process the 0.6 data).

Also, if required, several version of TFHE-rs can be "chained" to upgrade very old data to newer formats.
The above pattern can be extended to have `tfhe_0_5` (tfhe@0.5.5 renamed), `tfhe_0_6` (tfhe@0.6.0 renamed) and `tfhe` being tfhe@0.7.0, this will require special handling from the developers so that their protocol can handle data from 0.5.5, 0.6.0 and 0.7.0 using all the conversion tooling from the relevant version.

E.g., if some computation requires data from version 0.5.5 a conversion function could be called `upgrade_data_from_0_5_to_0_7` and do:

- read data from 0.5.5
- convert to 0.6.0 format using `tfhe_0_6`
- convert to 0.7.0 format using `tfhe_0_7`
- save to disk in 0.7.0 format
- process 0.7.0 data with `tfhe` which is tfhe@0.7.0
