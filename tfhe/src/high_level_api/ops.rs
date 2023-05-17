macro_rules! define_smart_op {
    ($op_name:ident) => {
        paste::paste! {
            pub trait [< Smart $op_name >]<Rhs> {
                type Output;

                fn [< smart_ $op_name:lower >](
                    &mut self,
                    rhs: &mut Rhs,
                ) -> Self::Output;
            }

            pub trait [< Smart $op_name Assign >]<Rhs> {
                fn [< smart_ $op_name:lower _assign >](
                    &mut self,
                    rhs: &mut Rhs,
                );
            }


            /////////////////////////////////
            // Scalar versions
            ////////////////////////////////

            pub trait [< SmartScalar $op_name >]<Scalar> {
                type Output;

                fn [< smart_scalar_ $op_name:lower >](
                    &mut self,
                    rhs: Scalar,
                ) -> Self::Output;
            }

            pub trait [< SmartScalar $op_name Assign >]<Scalar> {
                fn [< smart_scalar_ $op_name:lower _assign >](
                    &mut self,
                    rhs: Scalar,
                );
            }
        }
    };
    ($($op:ident),*) => {
        $(
            define_smart_op!($op);
        )*
    };
}

define_smart_op!(Add, Sub, Mul, BitAnd, BitOr, BitXor, Shl, Shr, Eq, Ge, Gt, Le, Lt, Max, Min);

pub trait SmartNeg {
    type Output;

    fn smart_neg(&mut self) -> Self::Output;
}
