pub use base::GenericShortInt;
pub use compressed::CompressedGenericShortint;

pub use static_::{
    CompressedFheUint2, CompressedFheUint3, CompressedFheUint4, FheUint2, FheUint2Parameters,
    FheUint3, FheUint3Parameters, FheUint4, FheUint4Parameters,
};

use super::client_key::GenericShortIntClientKey;
use super::public_key::compressed::GenericShortIntCompressedPublicKey;
use super::public_key::GenericShortIntPublicKey;
use super::server_key::{GenericShortIntCompressedServerKey, GenericShortIntServerKey};

mod base;
mod compressed;
pub(crate) mod static_;
