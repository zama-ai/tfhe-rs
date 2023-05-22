use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::high_level_api) enum PublicKeyDyn {
    Big(crate::integer::PublicKeyBig),
    Small(crate::integer::PublicKeySmall),
}

pub(in crate::high_level_api::integers) mod compressed {
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(in crate::high_level_api) enum CompressedPublicKeyDyn {
        Big(crate::integer::CompressedPublicKeyBig),
        Small(crate::integer::CompressedPublicKeySmall),
    }

    impl CompressedPublicKeyDyn {
        pub(crate) fn decompress(self) -> super::PublicKeyDyn {
            match self {
                CompressedPublicKeyDyn::Big(key) => super::PublicKeyDyn::Big(key.into()),
                CompressedPublicKeyDyn::Small(key) => super::PublicKeyDyn::Small(key.into()),
            }
        }
    }
}
