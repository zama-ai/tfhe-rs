//! Shows a basic usage of this crate

use tfhe_versionable::{Unversionize, Upgrade, Version, Versionize, VersionsDispatch};

// The structure that should be versioned, as defined in your code
#[derive(Versionize)]
#[versionize(MyStructVersions)] // Link to the enum type that will holds all the versions of this
                                // type
struct MyStruct<T: Default> {
    attr: T,
    builtin: u32,
}

// To avoid polluting your code, the old versions can be defined in another module/file, along with
// the dispatch enum
#[derive(Version)] // Used to mark an old version of the type
struct MyStructV0 {
    builtin: u32,
}

// The Upgrade trait tells how to go from the first version to the last. During unversioning, the
// upgrade method will be called on the deserialized value enough times to go to the last variant.
impl<T: Default> Upgrade<MyStruct<T>> for MyStructV0 {
    fn upgrade(self) -> Result<MyStruct<T>, String> {
        Ok(MyStruct {
            attr: T::default(),
            builtin: self.builtin,
        })
    }
}

// This is the dispatch enum, that holds one variant for each version of your type.
#[derive(VersionsDispatch)]
// This enum is not directly used but serves as a template to generate a new enum that will be
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
