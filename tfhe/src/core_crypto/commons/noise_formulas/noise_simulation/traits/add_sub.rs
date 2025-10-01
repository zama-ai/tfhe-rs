pub trait LweUncorrelatedAdd<Rhs> {
    type Output;
    type SideResources;

    fn lwe_uncorrelated_add(
        &self,
        rhs: Rhs,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}

pub trait LweUncorrelatedSub<Rhs> {
    type Output;
    type SideResources;

    fn lwe_uncorrelated_sub(
        &self,
        rhs: Rhs,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}
