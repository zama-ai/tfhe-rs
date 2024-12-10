# TFHE-versionable
This crate provides type level versioning for serialized data. It offers a way
to add backward compatibility on any data type. The versioning scheme works
recursively and is independent of the chosen serialized file format. It uses the
`serde` framework.

The crate will convert any type into an equivalent packed with versions
information. This "versioned" type is then serializable using any format
compatible with `serde`.

To use it, simply define an enum that have a variant for each version of your
target type.

For example, if you have defined an internal type:
```rust
struct MyStruct {
	val: u32
}
```

You have to define the following enum:
```rust
enum MyStructVersions {
	V0(MyStruct)
}
```

If at a subsequent point in time you want to add a field to this struct, the
idea is to copy the previously defined version of the struct and create a new
one with the added field. This mostly becomes:
```rust
struct MyStruct {
	val: u32,
	newval: u64
}

struct MyStructV0 {
	val: u32
}

enum MyStructVersions {
	V0(MyStructV0),
	V1(MyStruct)
}
```

You also have to implement the `Upgrade` trait, that tells how to go from a
version to another.

To make this work recursively, this crate defines 3 derive macro that should be
used on these types:
- `Versionize` should be used on the current version of your type, the one that
  is used in your code
- `Version` is used on every previous version of this type
- `VersionsDispatch` is used on the enum holding all the versions

This will implement the `Versionize`/`Unversionize` traits with their
`versionize` and `unversionize` methods that should be used before/after the
calls to `serialize`/`deserialize`.

The enum variants should keep their order and names between versions. The only
allowed operation on this enum is to add a new variant.

# Complete example
```rust
use tfhe_versionable::{Unversionize, Upgrade, Version, Versionize, VersionsDispatch};

// The structure that should be versioned, as defined in your code
#[derive(Versionize)]
#[versionize(MyStructVersions)] // Link to the enum type that will holds all the versions of this type
struct MyStruct<T: Default> {
    attr: T,
    builtin: u32,
}

// To avoid polluting your code, the old versions can be defined in another module/file, along with the dispatch enum
#[derive(Version)] // Used to mark an old version of the type
struct MyStructV0 {
    builtin: u32,
}

// The Upgrade trait tells how to go from the first version to the last. During unversioning, the
// upgrade method will be called on the deserialized value enough times to go to the last variant.
impl<T: Default> Upgrade<MyStruct<T>> for MyStructV0 {
    fn upgrade(self) -> MyStruct<T> {
        MyStruct {
            attr: T::default(),
            builtin: self.builtin,
        }
    }
}

// This is the dispatch enum, that holds one variant for each version of your type.
#[derive(VersionsDispatch)]
// This enum is not directly used but serves as a template to generate new enums that will be
// serialized. This allows recursive versioning.
#[allow(unused)]
enum MyStructVersions<T: Default> {
    V0(MyStructV0),
    V1(MyStruct<T>),
}

fn main() {
    let ms = MyStruct {
        attr: 37u64,
        builtin: 1234,
    };

    let serialized = bincode::serialize(&ms.versionize()).unwrap();

    // This can be called in future versions of your application, when more variants have been added
    let _unserialized = MyStruct::<u64>::unversionize(bincode::deserialize(&serialized).unwrap());
}
```

See the `examples` folder for more usecases.
