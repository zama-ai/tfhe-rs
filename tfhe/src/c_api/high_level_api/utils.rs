/// The C Standard only define integers from u8 to u64.
/// So to support u128 and u256 we had to create our own C friendly
/// data types.
///
/// This trait exists to be able to easily write wrapper function
/// by allowing to generically go from a C API scalar type to a rust one
pub(in crate::c_api::high_level_api) trait CApiIntegerType:
    From<Self::RustEquivalent>
{
    type RustEquivalent: From<Self>;

    fn to_rust(self) -> Self::RustEquivalent {
        Self::RustEquivalent::from(self)
    }
}

macro_rules! impl_c_api_integer_type(
    // For when the C Integer type is _not_ the same as the Rust Integer type
    ($c_type:ty => $rust_type:ty) => {
        impl CApiIntegerType for $c_type {
            type RustEquivalent = $rust_type;
        }
    };
    // For when the C Integer type is the same as Rust Integer type
    ($type:ty) => {
        impl CApiIntegerType for $type {
            type RustEquivalent = $type;
        }
    };
);

impl_c_api_integer_type!(bool);
impl_c_api_integer_type!(u8);
impl_c_api_integer_type!(u16);
impl_c_api_integer_type!(u32);
impl_c_api_integer_type!(u64);
impl_c_api_integer_type!(i8);
impl_c_api_integer_type!(i16);
impl_c_api_integer_type!(i32);
impl_c_api_integer_type!(i64);
impl_c_api_integer_type!(crate::c_api::high_level_api::u128::U128 => u128);
impl_c_api_integer_type!(crate::c_api::high_level_api::i128::I128 => i128);
impl_c_api_integer_type!(crate::c_api::high_level_api::u256::U256 => crate::integer::U256);
impl_c_api_integer_type!(crate::c_api::high_level_api::i256::I256 => crate::integer::I256);
impl_c_api_integer_type!(crate::c_api::high_level_api::u512::U512 => crate::integer::bigint::U512);
impl_c_api_integer_type!(crate::c_api::high_level_api::u1024::U1024 => crate::integer::bigint::U1024);
impl_c_api_integer_type!(crate::c_api::high_level_api::u2048::U2048 => crate::integer::bigint::U2048);

macro_rules! impl_destroy_on_type {
    ($wrapper_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            #[doc = "ptr can be null (no-op in that case)"]
            pub unsafe extern "C" fn [<$wrapper_type:snake _destroy>](
                ptr: *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    if (!ptr.is_null()) {
                        $crate::c_api::utils::check_ptr_is_non_null_and_aligned(ptr).unwrap();
                        drop(Box::from_raw(ptr));
                    }
                })
            }
        }
    };
}

pub(crate) use impl_destroy_on_type;

macro_rules! impl_try_encrypt_with_client_key_on_type {
    ($wrapper_type:ty{$wrapped_type:ty}, $input_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn  [<$wrapper_type:snake _try_encrypt_with_client_key_ $input_type:snake>](
                value: $input_type,
                client_key: *const $crate::c_api::high_level_api::keys::ClientKey,
                result: *mut *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let value = <$input_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::to_rust(value);
                    let client_key = $crate::c_api::utils::get_ref_checked(client_key).unwrap();

                    let inner = <$wrapped_type>::try_encrypt(value, &client_key.0).unwrap();

                    *result = Box::into_raw(Box::new($wrapper_type(inner)));
                })
            }
        }
    };
}

pub(crate) use impl_try_encrypt_with_client_key_on_type;

macro_rules! impl_try_encrypt_with_public_key_on_type {
    ($wrapper_type:ty{$wrapped_type:ty}, $input_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn  [<$wrapper_type:snake _try_encrypt_with_public_key_ $input_type:snake>](
                value: $input_type,
                public_key: *const $crate::c_api::high_level_api::keys::PublicKey,
                result: *mut *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let value = <$input_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::to_rust(value);

                    let public_key = $crate::c_api::utils::get_ref_checked(public_key).unwrap();

                    let inner = <$wrapped_type>::try_encrypt(value, &public_key.0).unwrap();

                    *result = Box::into_raw(Box::new($wrapper_type(inner)));
                })
            }
        }
    };
}

pub(crate) use impl_try_encrypt_with_public_key_on_type;

macro_rules! impl_try_encrypt_trivial_on_type {
    ($wrapper_type:ty{$wrapped_type:ty}, $input_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn  [<$wrapper_type:snake _try_encrypt_trivial_ $input_type:snake>](
                value: $input_type,
                result: *mut *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let value = <$input_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::to_rust(value);

                    let inner = <$wrapped_type>::try_encrypt_trivial(value).unwrap();

                    *result = Box::into_raw(Box::new($wrapper_type(inner)));
                })
            }
        }
    };
}

pub(crate) use impl_try_encrypt_trivial_on_type;

macro_rules! impl_decrypt_on_type {
    ($wrapper_type:ty, $output_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn  [<$wrapper_type:snake _decrypt>](
                encrypted_value: *const $wrapper_type,
                client_key: *const $crate::c_api::high_level_api::keys::ClientKey,
                result: *mut $output_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let client_key = $crate::c_api::utils::get_ref_checked(client_key).unwrap();
                    let encrypted_value = $crate::c_api::utils::get_ref_checked(encrypted_value).unwrap();

                    type RustScalarType_ = <$output_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::RustEquivalent;

                    let rust_clear: RustScalarType_ = encrypted_value.0.decrypt(&client_key.0);

                    *result = <$output_type>::from(rust_clear);
                })
            }
        }
    };
}

pub(crate) use impl_decrypt_on_type;

macro_rules! impl_try_decrypt_trivial_on_type {
    ($wrapper_type:ty, $output_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn  [<$wrapper_type:snake _try_decrypt_trivial>](
                encrypted_value: *const $wrapper_type,
                result: *mut $output_type,
            ) -> ::std::os::raw::c_int {
                type RustScalarType_ = <$output_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::RustEquivalent;

                let mut rust_result: Option<RustScalarType_> = None;

                // This is done the 'hard' way because we don't want to unwrap the decrypt_trivial
                // as the panic will print something and pollute.
                $crate::c_api::utils::catch_panic(|| {
                    let encrypted_value = $crate::c_api::utils::get_ref_checked(encrypted_value).unwrap();

                    rust_result = encrypted_value.0.try_decrypt_trivial().ok();
                });

                match rust_result {
                    Some(value) => {
                        *result = <$output_type>::from(value);
                        0
                    }
                    None => 1
                }
            }
        }
    };
}

pub(crate) use impl_try_decrypt_trivial_on_type;

macro_rules! impl_clone_on_type {
    ($wrapper_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<$wrapper_type:snake _clone>](
                sself: *const $wrapper_type,
                result: *mut *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    $crate::c_api::utils::check_ptr_is_non_null_and_aligned(result).unwrap();

                    let wrapper = $crate::c_api::utils::get_ref_checked(sself).unwrap();

                    let heap_allocated_object = Box::new($wrapper_type(wrapper.0.clone()));

                    *result = Box::into_raw(heap_allocated_object);
                })
            }
        }
    };
}

pub(crate) use impl_clone_on_type;

macro_rules! impl_serialize_deserialize_on_type {
    ($wrapper_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<$wrapper_type:snake _serialize>](
                sself: *const $wrapper_type,
                result: *mut $crate::c_api::buffer::DynamicBuffer,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    $crate::c_api::utils::check_ptr_is_non_null_and_aligned(result).unwrap();

                    let wrapper = $crate::c_api::utils::get_ref_checked(sself).unwrap();

                    let buffer: $crate::c_api::buffer::DynamicBuffer = bincode::serialize(&wrapper.0)
                        .unwrap()
                        .into();

                    *result = buffer;
                })
            }

            #[no_mangle]
            pub unsafe extern "C" fn [<$wrapper_type:snake _deserialize>](
                buffer_view: $crate::c_api::buffer::DynamicBufferView,
                result: *mut *mut $wrapper_type,
                ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    $crate::c_api::utils::check_ptr_is_non_null_and_aligned(result).unwrap();

                    // First fill the result with a null ptr so that if we fail and the return code is not
                    // checked, then any access to the result pointer will segfault (mimics malloc on failure)
                    *result = std::ptr::null_mut();

                    let object = bincode::deserialize(buffer_view.as_slice()).unwrap();

                    let heap_allocated_object = Box::new($wrapper_type(object));

                    *result = Box::into_raw(heap_allocated_object);
                })
            }
        }
    };
}

pub(crate) use impl_serialize_deserialize_on_type;

macro_rules! impl_safe_serialize_on_type {
    ($wrapper_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<$wrapper_type:snake _safe_serialize>](
                sself: *const $wrapper_type,
                result: *mut crate::c_api::buffer::DynamicBuffer,
                serialized_size_limit: u64,
            ) -> ::std::os::raw::c_int {
                crate::c_api::utils::catch_panic(|| {
                    crate::c_api::utils::check_ptr_is_non_null_and_aligned(result).unwrap();

                    let mut buffer = vec![];

                    let sself = crate::c_api::utils::get_ref_checked(sself).unwrap();

                    crate::high_level_api::safe_serialize(&sself.0, &mut buffer, serialized_size_limit)
                        .unwrap();

                    *result = buffer.into();
                })
            }
        }
    };
}

pub(crate) use impl_safe_serialize_on_type;

macro_rules! impl_safe_deserialize_conformant_integer {
    ($wrapper_type:ty, $conformance_param_type:ty) => {
        ::paste::paste! {
            #[no_mangle]
            /// Deserializes safely, and checks that the resulting ciphertext
            /// is in compliance with the shape of ciphertext that the `server_key` expects.
            ///
            /// This function can only deserialize, types which have been serialized
            /// by a `safe_serialize` function.
            ///
            /// - `serialized_size_limit`: size limit (in number of byte) of the serialized object
            ///    (to avoid out of memory attacks)
            /// - `server_key`: ServerKey used in the conformance check
            /// - `result`: pointer where resulting deserialized object needs to be stored.
            ///    * cannot be NULL
            ///    * (*result) will point the deserialized object on success, else NULL
            pub unsafe extern "C" fn [<$wrapper_type:snake _safe_deserialize_conformant>](
                buffer_view: crate::c_api::buffer::DynamicBufferView,
                serialized_size_limit: u64,
                server_key: *const crate::c_api::high_level_api::keys::ServerKey,
                result: *mut *mut $wrapper_type,
            ) -> ::std::os::raw::c_int {
                ::paste::paste! {
                     crate::c_api::utils::catch_panic(|| {
                        crate::c_api::utils::check_ptr_is_non_null_and_aligned(result).unwrap();

                        let sk = crate::c_api::utils::get_ref_checked(server_key).unwrap();

                        let buffer_view: &[u8] = buffer_view.as_slice();

                        // First fill the result with a null ptr so that if we fail and the return code is not
                        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
                        *result = std::ptr::null_mut();

                        let params = $crate::high_level_api::$conformance_param_type::from(&sk.0);
                        let inner = $crate::safe_deserialization::safe_deserialize_conformant(
                                buffer_view,
                                serialized_size_limit,
                                &params,
                            )
                            .unwrap();

                        let heap_allocated_object = Box::new($wrapper_type(inner));

                        *result = Box::into_raw(heap_allocated_object);
                    })
                }
            }
        }
    };
}

pub(crate) use impl_safe_deserialize_conformant_integer;

macro_rules! impl_binary_fn_on_type {
    // More general binary fn case,
    // where the type of the left-hand side can be different
    // than the type of the right-hand side.
    //
    // The result type is the one of the left-hand side.
    //
    // In practice, this is used for shifts on signed type,
    // where lhs is a signed type and rhs is an unsigned type
    (
        lhs_type: $lhs_type:ty,
        rhs_type: $rhs_type:ty,
        binary_fn_names: $($binary_fn_name:ident),*
        $(,)?
    ) => {
        $( // unroll binary_fn_names
            ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$lhs_type:snake _ $binary_fn_name>](
                    lhs: *const $lhs_type,
                    rhs: *const $rhs_type,
                    result: *mut *mut $lhs_type,
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_ref_checked(lhs).unwrap();
                        let rhs = $crate::c_api::utils::get_ref_checked(rhs).unwrap();

                        let inner = (&lhs.0).$binary_fn_name(&rhs.0);

                        *result = Box::into_raw(Box::new($lhs_type(inner)));
                    })
                }
            }
        )*

    };

    // Usual binary fn case, where lhs, rhs and result are all of the same type
    ($wrapper_type:ty => $($binary_fn_name:ident),* $(,)?) => {
        impl_binary_fn_on_type!(
            lhs_type: $wrapper_type,
            rhs_type: $wrapper_type,
            binary_fn_names: $($binary_fn_name),*
        );
    };
}

pub(crate) use impl_binary_fn_on_type;

// Like binary fn, but an extra output value is needed for the overflow flag
macro_rules! impl_binary_overflowing_fn_on_type {
    (
        lhs_type: $lhs_type:ty,
        rhs_type: $rhs_type:ty,
        binary_fn_names: $($binary_fn_name:ident),*
        $(,)?
    ) => {
        $( // unroll binary_fn_names
            ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$lhs_type:snake _ $binary_fn_name>](
                    lhs: *const $lhs_type,
                    rhs: *const $rhs_type,
                    out_result: *mut *mut $lhs_type,
                    out_overflowed: *mut *mut FheBool
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_ref_checked(lhs).unwrap();
                        let rhs = $crate::c_api::utils::get_ref_checked(rhs).unwrap();

                        let (inner, overflowed) = (&lhs.0).$binary_fn_name(&rhs.0);

                        *out_result = Box::into_raw(Box::new($lhs_type(inner)));
                        *out_overflowed = Box::into_raw(Box::new(FheBool(overflowed)))
                    })
                }
            }
        )*

    };

    // Usual binary fn case, where lhs, rhs and result are all of the same type
    ($wrapper_type:ty => $($binary_fn_name:ident),* $(,)?) => {
        impl_binary_overflowing_fn_on_type!(
            lhs_type: $wrapper_type,
            rhs_type: $wrapper_type,
            binary_fn_names: $($binary_fn_name),*
        );
    };
}

pub(crate) use impl_binary_overflowing_fn_on_type;

// Comparisons returns FheBool so we use a specialized
// macro for them
macro_rules! impl_comparison_fn_on_type {
    (
        lhs_type: $lhs_type:ty,
        rhs_type: $rhs_type:ty,
        comparison_fn_names: $($comparison_fn_name:ident),*
        $(,)?
    ) => {
        $( // unroll comparison_fn_names
            ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$lhs_type:snake _ $comparison_fn_name>](
                    lhs: *const $lhs_type,
                    rhs: *const $rhs_type,
                    result: *mut *mut $crate::c_api::high_level_api::booleans::FheBool,
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_ref_checked(lhs).unwrap();
                        let rhs = $crate::c_api::utils::get_ref_checked(rhs).unwrap();

                        let inner = (&lhs.0).$comparison_fn_name(&rhs.0);

                        let inner = $crate::c_api::high_level_api::booleans::FheBool(inner);
                        *result = Box::into_raw(Box::new(inner));
                    })
                }
            }
        )*
    };
}

pub(crate) use impl_comparison_fn_on_type;

macro_rules! impl_scalar_comparison_fn_on_type {
    (
        lhs_type: $lhs_type:ty,
        clear_type: $scalar_type:ty,
        comparison_fn_names: $($comparison_fn_name:ident),*
        $(,)?
    ) => {
        $( // unroll comparison_fn_names
            ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$lhs_type:snake _scalar_ $comparison_fn_name>](
                    lhs: *const $lhs_type,
                    rhs: $scalar_type,
                    result: *mut *mut $crate::c_api::high_level_api::booleans::FheBool,
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_ref_checked(lhs).unwrap();
                        let rhs = <$scalar_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::to_rust(rhs);


                        let inner = (&lhs.0).$comparison_fn_name(rhs);

                        let inner = $crate::c_api::high_level_api::booleans::FheBool(inner);
                        *result = Box::into_raw(Box::new(inner));
                    })
                }
            }
        )*
    };
}

pub(crate) use impl_scalar_comparison_fn_on_type;

macro_rules! impl_unary_fn_on_type {
    (
        input_type: $input_type:ty,
        output_type: $output_type:ty,
        unary_fn_names: $( $(#[$attr:meta])* $unary_fn_name:ident),*
    ) => {
        $(
            ::paste::paste! {
                $(#[$attr])*
                #[no_mangle]
                pub unsafe extern "C" fn [<$input_type:snake _ $unary_fn_name>](
                    input: *const $input_type,
                    result: *mut *mut $output_type,
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let input = $crate::c_api::utils::get_ref_checked(input).unwrap();

                        let inner = (&input.0).$unary_fn_name();

                        *result = Box::into_raw(Box::new($output_type(inner)));
                    })
                }
            }
        )*
    };
    ($wrapper_type:ty => $( $(#[$attr:meta])* $unary_fn_name:ident),* $(,)?) => {
        impl_unary_fn_on_type!(
            input_type: $wrapper_type,
            output_type: $wrapper_type,
            unary_fn_names: $( $(#[$attr])* $unary_fn_name),*
        );
    };
}

pub(crate) use impl_unary_fn_on_type;

macro_rules! impl_unary_fn_with_2_outputs_on_type {
    (
        input_type: $input_type:ty,
        output_type_1: $output_type_1:ty,
        output_type_2: $output_type_2:ty,
        unary_fn_names: $( $(#[$attr:meta])* $unary_fn_name:ident),*
    ) => {
        $(
            ::paste::paste! {
                $(#[$attr])*
                #[no_mangle]
                pub unsafe extern "C" fn [<$input_type:snake _ $unary_fn_name>](
                    input: *const $input_type,
                    result_1: *mut *mut $output_type_1,
                    result_2: *mut *mut $output_type_2,
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let input = $crate::c_api::utils::get_ref_checked(input).unwrap();

                        let (inner_1, inner_2) = (&input.0).$unary_fn_name();

                        *result_1 = Box::into_raw(Box::new($output_type_1(inner_1)));
                        *result_2 = Box::into_raw(Box::new($output_type_2(inner_2)));
                    })
                }
            }
        )*
    };
}

pub(crate) use impl_unary_fn_with_2_outputs_on_type;

macro_rules! impl_binary_assign_fn_on_type {
    // More general binary fn case,
    // where the type of the left-hand side can be different
    // than the type of the right-hand side.
    //
    // In practice, this is used for shifts on signed type,
    // where lhs is a signed type and rhs is an unsigned type
    (
        lhs_type: $lhs_type:ty,
        rhs_type: $rhs_type:ty,
        binary_fn_names: $($binary_assign_fn_name:ident),*
        $(,)?
    ) => {
        $(
            ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$lhs_type:snake _ $binary_assign_fn_name>](
                    lhs: *mut $lhs_type,
                    rhs: *const $rhs_type,
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_mut_checked(lhs).unwrap();
                        let rhs = $crate::c_api::utils::get_ref_checked(rhs).unwrap();

                        lhs.0.$binary_assign_fn_name(&rhs.0);
                    })
                }
            }
        )*
    };
    ($wrapper_type:ty => $($binary_assign_fn_name:ident),* $(,)?) => {
        impl_binary_assign_fn_on_type!(
            lhs_type: $wrapper_type,
            rhs_type: $wrapper_type,
            binary_fn_names: $($binary_assign_fn_name),*
        );
    };
}

pub(crate) use impl_binary_assign_fn_on_type;

macro_rules! impl_scalar_binary_fn_on_type {
    ($wrapper_type:ty, $scalar_type:ty => $($binary_fn_name:ident),* $(,)?) => {
        $(
            ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$wrapper_type:snake _scalar_ $binary_fn_name>](
                    lhs: *const $wrapper_type,
                    rhs: $scalar_type,
                    result: *mut *mut $wrapper_type,
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_ref_checked(lhs).unwrap();
                        let rhs = <$scalar_type as $crate::c_api::high_level_api::utils::CApiIntegerType>::to_rust(rhs);

                        let inner = (&lhs.0).$binary_fn_name(rhs);

                        *result = Box::into_raw(Box::new($wrapper_type(inner)));
                    })
                }
            }
        )*
    };
}

pub(crate) use impl_scalar_binary_fn_on_type;

macro_rules! impl_scalar_binary_assign_fn_on_type {
    ($wrapper_type:ty, $scalar_type:ty => $($binary_assign_fn_name:ident),* $(,)?) => {
        $(
            ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$wrapper_type:snake _scalar_ $binary_assign_fn_name>](
                    lhs: *mut $wrapper_type,
                    rhs: $scalar_type,
                ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let lhs = $crate::c_api::utils::get_mut_checked(lhs).unwrap();
                        let rhs = <$scalar_type as $crate::c_api::high_level_api::utils::CApiIntegerType
                            >::to_rust(rhs);

                        lhs.0.$binary_assign_fn_name(rhs);
                    })
                }
            }
        )*
    };
}

pub(crate) use impl_scalar_binary_assign_fn_on_type;

// Defines the function to cast `from` a type _into_ the given list of type
macro_rules! define_casting_operation(
    ($from:ty => $($to:ty),*) => {
        $(
            ::paste::paste!{
                #[no_mangle]
                pub unsafe extern "C" fn [<$from:snake _cast_into_ $to:snake>](
                    sself: *const $from,
                    result: *mut *mut $to,
                    ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let from = $crate::c_api::utils::get_ref_checked(sself).unwrap();
                        let cloned = from.0.clone();

                        let inner_to = <_ as $crate::prelude::CastInto<_>>::cast_into(cloned);
                        *result = Box::into_raw(Box::new($to(inner_to)));
                    })
                }
            }
        )*
    }
);

pub(crate) use define_casting_operation;
