use crate::c_api::high_level_api::booleans::FheBool;
use crate::c_api::high_level_api::integers::{
    FheUint10, FheUint12, FheUint128, FheUint14, FheUint16, FheUint2, FheUint256, FheUint32,
    FheUint4, FheUint6, FheUint64, FheUint8,
};

macro_rules! impl_array_fn {
    (
        name: $name:ident,
        inner_func: $inner_func:path,
        output_type_name: $output_type_name:ty,
        type_name: $($type_name:ty),*
        $(,)?
    ) => {
        $( // type_name
            ::paste::paste! {
                #[no_mangle]
                pub unsafe extern "C" fn [<$type_name:snake _ $name>](
                    lhs: *const *mut $type_name,
                    lhs_len: usize,
                    rhs: *const *mut $type_name,
                    rhs_len: usize,
                    result: *mut *mut $output_type_name,
                ) -> ::std::os::raw::c_int {
                    crate::c_api::utils::catch_panic(|| {
                        let lhs: &[*mut $type_name] = std::slice::from_raw_parts(lhs, lhs_len);
                        let rhs: &[*mut $type_name] = std::slice::from_raw_parts(rhs, rhs_len);

                        let cloned_lhs = lhs.iter().map(|e: &*mut $type_name| e.as_ref().unwrap().0.clone()).collect::<Vec<_>>();
                        let cloned_rhs = rhs.iter().map(|e: &*mut $type_name| e.as_ref().unwrap().0.clone()).collect::<Vec<_>>();

                        let inner = $inner_func(&cloned_lhs, &cloned_rhs);

                        *result = Box::into_raw(Box::new($output_type_name(inner)));
                    })
                }
            }
        )*
    };
}

impl_array_fn!(
    name: array_eq,
    inner_func: crate::high_level_api::array::fhe_uint_array_eq,
    output_type_name: FheBool,
    type_name: FheUint2, FheUint4, FheUint6, FheUint8, FheUint10, FheUint12, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
);

impl_array_fn!(
    name: array_contains_sub_slice,
    inner_func: crate::high_level_api::array::fhe_uint_array_contains_sub_slice,
    output_type_name: FheBool,
    type_name: FheUint2, FheUint4, FheUint6, FheUint8, FheUint10, FheUint12, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
);
