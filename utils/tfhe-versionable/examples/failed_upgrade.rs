//! The upgrade method can return an error. In that case, the error is propagated to
//! the outer `unversionize` call.

use tfhe_versionable::{Unversionize, Versionize};

mod v0 {
    use serde::{Deserialize, Serialize};
    use tfhe_versionable::Versionize;

    use backward_compat::MyStructVersions;

    #[derive(Serialize, Deserialize, Versionize)]
    #[versionize(MyStructVersions)]
    pub struct MyStruct(pub Option<u32>);

    mod backward_compat {
        use tfhe_versionable::VersionsDispatch;

        use super::MyStruct;

        #[derive(VersionsDispatch)]
        #[allow(unused)]
        pub enum MyStructVersions {
            V0(MyStruct),
        }
    }
}

mod v1 {
    use serde::{Deserialize, Serialize};
    use tfhe_versionable::Versionize;

    use backward_compat::MyStructVersions;

    #[derive(Serialize, Deserialize, Versionize)]
    #[versionize(MyStructVersions)]
    pub struct MyStruct(pub u32);

    mod backward_compat {
        use std::error::Error;
        use std::fmt::Display;

        use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

        use super::MyStruct;

        #[derive(Version)]
        pub struct MyStructV0(pub Option<u32>);

        #[derive(Debug, Clone)]
        pub struct EmptyValueError;

        impl Display for EmptyValueError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "Value is empty")
            }
        }

        impl Error for EmptyValueError {}

        impl Upgrade<MyStruct> for MyStructV0 {
            type Error = EmptyValueError;
            fn upgrade(self) -> Result<MyStruct, Self::Error> {
                match self.0 {
                    Some(val) => Ok(MyStruct(val)),
                    None => Err(EmptyValueError),
                }
            }
        }

        #[derive(VersionsDispatch)]
        #[allow(unused)]
        pub enum MyStructVersions {
            V0(MyStructV0),
            V1(MyStruct),
        }
    }
}

fn main() {
    let v0 = v0::MyStruct(Some(37));
    let serialized = bincode::serialize(&v0.versionize()).unwrap();

    let v1 = v1::MyStruct::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    assert_eq!(v0.0.unwrap(), v1.0);

    let v0_empty = v0::MyStruct(None);
    let serialized_empty = bincode::serialize(&v0_empty.versionize()).unwrap();

    assert!(v1::MyStruct::unversionize(bincode::deserialize(&serialized_empty).unwrap()).is_err());
}

#[test]
fn test() {
    main()
}
