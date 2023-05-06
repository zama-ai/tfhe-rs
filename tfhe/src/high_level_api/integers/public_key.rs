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
}
