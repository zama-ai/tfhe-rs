pub trait AllocateLweKeyswitchResult {
    type Output;
    type SideResources;

    fn allocate_lwe_keyswitch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}

pub trait LweKeyswitch<Input, Output> {
    type SideResources;

    fn lwe_keyswitch(
        &self,
        input: &Input,
        output: &mut Output,
        side_resources: &mut Self::SideResources,
    );
}
