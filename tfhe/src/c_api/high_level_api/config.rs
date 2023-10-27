use crate::c_api::utils::*;
use std::os::raw::c_int;

pub struct ConfigBuilder(pub(in crate::c_api) crate::high_level_api::ConfigBuilder);
pub struct Config(pub(in crate::c_api) crate::high_level_api::Config);

impl_destroy_on_type!(ConfigBuilder);
impl_destroy_on_type!(Config);

#[no_mangle]
pub unsafe extern "C" fn config_builder_default(result: *mut *mut ConfigBuilder) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let inner_builder = crate::high_level_api::ConfigBuilder::default();

        *result = Box::into_raw(Box::new(ConfigBuilder(inner_builder)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn config_builder_default_with_small_encryption(
    builder: *mut *mut ConfigBuilder,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(builder).unwrap();

        let inner_builder = crate::high_level_api::ConfigBuilder::default_with_small_encryption();
        *builder = Box::into_raw(Box::new(ConfigBuilder(inner_builder)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn config_builder_default_with_big_encryption(
    builder: *mut *mut ConfigBuilder,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(builder).unwrap();

        let inner_builder = crate::high_level_api::ConfigBuilder::default_with_big_encryption();
        *builder = Box::into_raw(Box::new(ConfigBuilder(inner_builder)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn config_builder_clone(
    input: *const ConfigBuilder,
    result: *mut *mut ConfigBuilder,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let cloned = get_ref_checked(input).unwrap().0.clone();

        *result = Box::into_raw(Box::new(ConfigBuilder(cloned)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn config_builder_use_custom_parameters(
    builder: *mut *mut ConfigBuilder,
    shortint_block_parameters: crate::c_api::shortint::parameters::ShortintPBSParameters,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(builder).unwrap();

        let params: crate::shortint::ClassicPBSParameters =
            shortint_block_parameters.try_into().unwrap();
        let inner = Box::from_raw(*builder)
            .0
            .use_custom_parameters(params, None);
        *builder = Box::into_raw(Box::new(ConfigBuilder(inner)));
    })
}

/// Takes ownership of the builder
#[no_mangle]
pub unsafe extern "C" fn config_builder_build(
    builder: *mut ConfigBuilder,
    result: *mut *mut Config,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let config = Box::from_raw(builder).0.build();

        *result = Box::into_raw(Box::new(Config(config)));
    })
}
