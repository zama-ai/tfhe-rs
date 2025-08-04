pub trait ScalarMul<Scalar> {
    type Output;
    type SideResources;

    fn scalar_mul(&self, rhs: Scalar, side_resources: &mut Self::SideResources) -> Self::Output;
}

pub trait ScalarMulAssign<Scalar> {
    type SideResources;

    fn scalar_mul_assign(&mut self, rhs: Scalar, side_resources: &mut Self::SideResources);
}
