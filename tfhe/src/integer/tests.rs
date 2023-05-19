macro_rules! create_parametrized_test{
    ($name:ident { $($param:ident),* $(,)? }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
     ($name:ident)=> {
        create_parametrized_test!($name
        {
            PARAM_MESSAGE_1_CARRY_1,
            PARAM_MESSAGE_2_CARRY_2,
            PARAM_MESSAGE_3_CARRY_3,
            PARAM_MESSAGE_4_CARRY_4
        });
    };
}
