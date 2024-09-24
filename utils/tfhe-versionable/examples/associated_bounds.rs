/// In this example, we use a generic that is not versionable itself. Only its associated types
/// should be versioned.
use tfhe_versionable::{Versionize, VersionsDispatch};

trait WithAssociated {
    type Assoc;
    type OtherAssoc;
}

struct Marker;

impl WithAssociated for Marker {
    type Assoc = u64;

    type OtherAssoc = u32;
}

#[derive(VersionsDispatch)]
#[allow(unused)]
enum MyStructVersions<T: WithAssociated> {
    V0(MyStruct<T>),
}

#[derive(Versionize)]
#[versionize(MyStructVersions)]
struct MyStruct<T: WithAssociated> {
    val: T::Assoc,
    other_val: T::OtherAssoc,
}

fn main() {
    let ms = MyStruct::<Marker> {
        val: 27,
        other_val: 54,
    };

    ms.versionize();
}

#[test]
fn test() {
    main()
}
