//! The `VersionizeVec` and `UnversionizeVec` traits are also automatically derived
//! So that Vec can be versioned as well. Because of the recursivity, each element of the vec
//! has its own version tag. For built-in rust types and anything that derives `NotVersioned`,
//! the versioning of the whole vec is skipped.

use std::convert::Infallible;

use tfhe_versionable::{Unversionize, Upgrade, Version, Versionize, VersionsDispatch};

#[derive(Version)]
struct MyStructInnerV0 {
    val: u64,
}

#[derive(Versionize)]
#[versionize(MyStructInnerVersions)]
struct MyStructInner<T> {
    val: u64,
    gen: T,
}

impl<T: Default> Upgrade<MyStructInner<T>> for MyStructInnerV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<MyStructInner<T>, Self::Error> {
        Ok(MyStructInner {
            val: self.val,
            gen: T::default(),
        })
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructInnerVersions<T> {
    V0(MyStructInnerV0),
    V1(MyStructInner<T>),
}

#[derive(Versionize)]
#[versionize(MyVecVersions)]
struct MyVec<T> {
    vec: Vec<MyStructInner<T>>,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyVecVersions<T> {
    V0(MyVec<T>),
}

mod v0 {
    use tfhe_versionable::{Versionize, VersionsDispatch};

    #[derive(Versionize)]
    #[versionize(MyStructInnerVersions)]
    pub(super) struct MyStructInner {
        pub(super) val: u64,
    }

    #[derive(VersionsDispatch)]
    #[allow(unused)]
    pub(super) enum MyStructInnerVersions {
        V0(MyStructInner),
    }

    #[derive(Versionize)]
    #[versionize(MyVecVersions)]
    pub(super) struct MyVec {
        pub(super) vec: Vec<MyStructInner>,
    }

    #[derive(VersionsDispatch)]
    #[allow(unused)]
    pub(super) enum MyVecVersions {
        V0(MyVec),
    }
}

fn main() {
    let values: [u64; 6] = [12, 23, 34, 45, 56, 67];
    let vec = values
        .iter()
        .map(|val| v0::MyStructInner { val: *val })
        .collect();
    let mv = v0::MyVec { vec };

    let serialized = bincode::serialize(&mv.versionize()).unwrap();

    let unserialized =
        MyVec::<u64>::unversionize(bincode::deserialize(&serialized).unwrap()).unwrap();

    let unser_values: Vec<u64> = unserialized.vec.iter().map(|inner| inner.val).collect();

    assert_eq!(unser_values, values);
}

#[test]
fn test() {
    main()
}
