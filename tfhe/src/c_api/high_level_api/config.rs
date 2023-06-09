use crate::c_api::utils::*;
use std::os::raw::c_int;

pub struct ConfigBuilder(pub(in crate::c_api) crate::high_level_api::ConfigBuilder);
pub struct Config(pub(in crate::c_api) crate::high_level_api::Config);

impl_destroy_on_type!(ConfigBuilder);
impl_destroy_on_type!(Config);

#[no_mangle]
pub unsafe extern "C" fn config_builder_all_disabled(result: *mut *mut ConfigBuilder) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let inner_builder = crate::high_level_api::ConfigBuilder::all_disabled();

        *result = Box::into_raw(Box::new(ConfigBuilder(inner_builder)));
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

macro_rules! define_enable_default_fn(
    ($type_name:ident) => {
        ::paste::paste!{
            #[no_mangle]
            pub unsafe extern "C" fn [<config_builder_enable_default_ $type_name>](
                builder: *mut *mut ConfigBuilder,
            ) -> ::std::os::raw::c_int {
                catch_panic(|| {
                    check_ptr_is_non_null_and_aligned(builder).unwrap();

                    let inner = Box::from_raw(*builder).0.[<enable_default_ $type_name>]();
                    *builder = Box::into_raw(Box::new(ConfigBuilder(inner)));
                })
            }
        }
    };
    ($type_name:ident @small) => {
        ::paste::paste!{
            #[no_mangle]
            pub unsafe extern "C" fn [<config_builder_enable_default_ $type_name _small>](
                builder: *mut *mut ConfigBuilder,
            ) -> ::std::os::raw::c_int {
                catch_panic(|| {
                    check_ptr_is_non_null_and_aligned(builder).unwrap();

                    let inner = Box::from_raw(*builder).0.[<enable_default_ $type_name _small>]();
                    *builder = Box::into_raw(Box::new(ConfigBuilder(inner)));
                })
            }
        }
    }
);

#[cfg(feature = "boolean")]
define_enable_default_fn!(bool);
#[cfg(feature = "integer")]
define_enable_default_fn!(integers);
#[cfg(feature = "integer")]
define_enable_default_fn!(integers @small);

#[no_mangle]
pub unsafe extern "C" fn config_builder_enable_custom_integers(
    builder: *mut *mut ConfigBuilder,
    shortint_block_parameters: crate::c_api::shortint::parameters::ShortintPBSParameters,
) -> ::std::os::raw::c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(builder).unwrap();

        let params: crate::shortint::ClassicPBSParameters = shortint_block_parameters.into();
        let inner = Box::from_raw(*builder)
            .0
            .enable_custom_integers(params, None);
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
