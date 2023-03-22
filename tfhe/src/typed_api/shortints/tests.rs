use crate::typed_api::prelude::*;
use crate::typed_api::{generate_keys, CompressedFheUint2, ConfigBuilder, FheUint2};

#[test]
fn test_shortint_compressed() {
    let config = ConfigBuilder::all_enabled().enable_default_uint2().build();
    let (client_key, _) = generate_keys(config);

    let compressed: CompressedFheUint2 = CompressedFheUint2::try_encrypt(2, &client_key).unwrap();
    let a = FheUint2::from(compressed);
    let decompressed = a.decrypt(&client_key);
    assert_eq!(decompressed, 2);
}
