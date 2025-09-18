pub trait AllocateLweMultiBitBlindRotateResult {
    type Output;
    type SideResources;

    fn allocate_lwe_multi_bit_blind_rotate_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}

pub trait LweMultiBitFftBlindRotate<Input, Output, Accumulator> {
    type SideResources;

    fn lwe_multi_bit_fft_blind_rotate(
        &self,
        input: &Input,
        output: &mut Output,
        accumulator: &Accumulator,
        side_resources: &mut Self::SideResources,
    );
}

pub trait LweMultiBitFft128BlindRotate<Input, Output, Accumulator> {
    type SideResources;

    fn lwe_multi_bit_fft_128_blind_rotate(
        &self,
        input: &Input,
        output: &mut Output,
        accumulator: &Accumulator,
        side_resources: &mut Self::SideResources,
    );
}
