//! This test checks that the bounds added by the proc macro does not prevent the code to
//! compile by leaking a private type
use tfhe_versionable::Versionize;

mod mymod {
    use tfhe_versionable::{Versionize, VersionsDispatch};

    #[derive(Versionize)]
    #[versionize(PublicVersions)]
    pub struct Public<T> {
        private: Private<T>,
    }

    impl Public<u64> {
        pub fn new(val: u64) -> Self {
            Self {
                private: Private(val),
            }
        }
    }

    #[derive(VersionsDispatch)]
    #[allow(unused)]
    pub enum PublicVersions<T> {
        V0(Public<T>),
    }

    #[derive(Versionize)]
    #[versionize(PrivateVersions)]
    struct Private<T>(T);

    #[derive(VersionsDispatch)]
    enum PrivateVersions<T> {
        #[allow(dead_code)]
        V0(Private<T>),
    }
}

#[test]
fn bounds_private_in_public() {
    let public = mymod::Public::new(42);

    let _vers = public.versionize();
}
