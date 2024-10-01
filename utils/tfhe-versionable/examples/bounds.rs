//! Example of a simple struct with an Upgrade impl that requires a specific bound.
//! In that case, the previous versions of the type used a string as a representation, but it has
//! been changed to a Generic. For the upgrade to work, we need to be able to create this generic
//! from a String.

use std::error::Error;
use std::io::Cursor;
use std::str::FromStr;

use tfhe_versionable::{Unversionize, Upgrade, Version, Versionize, VersionsDispatch};

/// The previous version of our application
mod v0 {
    use tfhe_versionable::{Versionize, VersionsDispatch};

    #[derive(Versionize)]
    #[versionize(MyStructVersions)]
    pub(super) struct MyStruct {
        pub(super) val: String,
    }

    #[derive(VersionsDispatch)]
    #[allow(unused)]
    pub(super) enum MyStructVersions {
        V0(MyStruct),
    }
}

#[derive(Version)]
struct MyStructV0 {
    val: String,
}

#[derive(Versionize)]
#[versionize(MyStructVersions)]
struct MyStruct<T> {
    val: T,
}

impl<T: FromStr> Upgrade<MyStruct<T>> for MyStructV0
where
    <T as FromStr>::Err: Error + Send + Sync + 'static,
{
    type Error = <T as FromStr>::Err;

    fn upgrade(self) -> Result<MyStruct<T>, Self::Error> {
        let val = T::from_str(&self.val)?;

        Ok(MyStruct { val })
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructVersions<T> {
    V0(MyStructV0),
    V1(MyStruct<T>),
}

fn main() {
    let val = 64;
    let stru_v0 = v0::MyStruct {
        val: format!("{val}"),
    };

    let mut ser = Vec::new();
    ciborium::ser::into_writer(&stru_v0.versionize(), &mut ser).unwrap();

    let unvers =
        MyStruct::<u64>::unversionize(ciborium::de::from_reader(&mut Cursor::new(&ser)).unwrap())
            .unwrap();

    assert_eq!(unvers.val, val);
}

#[test]
fn test() {
    main()
}
