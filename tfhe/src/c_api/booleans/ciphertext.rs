use crate::boolean;

pub struct BooleanCiphertext(pub(in crate::c_api) boolean::ciphertext::Ciphertext);
