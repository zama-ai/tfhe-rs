// #[cfg(not(feature = "__coverage"))]
macro_rules! create_parametrized_test{
    (
        $name:ident {
            $($(#[$cfg:meta])* $param:ident),*
            $(,)?
        }
    ) => {
        ::paste::paste! {
            $(
                #[test]
                $(#[$cfg])*
                fn [<test_ $name _ $param:lower>]() {
                    $name($param)
                }
            )*
        }
    };
     ($name:ident)=> {
        create_parametrized_test!($name
        {
            PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            #[cfg(not(feature = "__coverage"))]
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            #[cfg(not(feature = "__coverage"))]
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            #[cfg(not(feature = "__coverage"))]
            PARAM_MESSAGE_4_CARRY_4_KS_PBS
        });
    };
}
// macro_rules! create_parametrized_test{
//
//     ($name:ident { $($param:ident),* $(,)? }) => {
//         ::paste::paste! {
//             $(
//             #[test]
//             fn [<test_ $name _ $param:lower>]() {
//                 $name($param)
//             }
//             )*
//         }
//     };
//      ($name:ident)=> {
//         create_parametrized_test!($name
//         {
//             #[cfg(not(feature = "__coverage"))]
//             PARAM_MESSAGE_1_CARRY_1_KS_PBS,
//             PARAM_MESSAGE_2_CARRY_2_KS_PBS,
//             #[cfg(not(feature = "__coverage"))]
//             PARAM_MESSAGE_3_CARRY_3_KS_PBS,
//             #[cfg(not(feature = "__coverage"))]
//             PARAM_MESSAGE_4_CARRY_4_KS_PBS
//         });
//     };
// }

// #[cfg(feature = "__coverage")]
// macro_rules! create_parametrized_test{
//     ($name:ident { $($param:ident),* $(,)? }) => {
//         ::paste::paste! {
//             $(
//             #[test]
//             fn [<test_ $name _ $param:lower>]() {
//                 use std::time::Instant;
//                 let start = Instant::now();
//                 $name($param);
//                 println!("*********** {} took: {}", stringify!($name),
// start.elapsed().as_secs());             }
//             )*
//         }
//     };
//      ($name:ident)=> {
//         create_parametrized_test!($name
//         {
//             PARAM_MESSAGE_2_CARRY_2_KS_PBS,
//         });
//     };
// }
