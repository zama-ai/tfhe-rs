use crate::nist_submission::NIST_META_PARAMS_2_2;
use crate::shortint::server_key::tests::noise_distribution::br_dp_ks_ms::{
    noise_check_encrypt_br_dp_ks_ms_noise, noise_check_encrypt_br_dp_ks_ms_pfail,
};
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_stringified_test;

create_parameterized_stringified_test!(noise_check_encrypt_br_dp_ks_ms_noise {
    NIST_META_PARAMS_2_2,
});

create_parameterized_stringified_test!(noise_check_encrypt_br_dp_ks_ms_pfail {
    NIST_META_PARAMS_2_2,
});
