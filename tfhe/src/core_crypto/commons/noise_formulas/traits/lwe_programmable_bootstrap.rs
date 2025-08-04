pub trait AllocateBootstrapResult {
    type Output;
    type SideResources;

    fn allocate_bootstrap_result(&self, side_resources: &mut Self::SideResources) -> Self::Output;
}

pub trait StandardFftBootstrap<Input, Output, Accumulator> {
    type SideResources;

    fn standard_fft_pbs(
        &self,
        input: &Input,
        output: &mut Output,
        accumulator: &Accumulator,
        side_resources: &mut Self::SideResources,
    );
}

pub trait StandardFft128Bootstrap<Input, Output, Accumulator> {
    type SideResources;

    fn standard_fft_128_pbs(
        &self,
        input: &Input,
        output: &mut Output,
        accumulator: &Accumulator,
        side_resources: &mut Self::SideResources,
    );
}
