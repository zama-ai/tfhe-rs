pub trait AllocateKeyswtichResult {
    type Output;
    type SideResources;

    fn allocate_keyswitch_result(&self, side_resources: &mut Self::SideResources) -> Self::Output;
}

pub trait Keyswitch<Input, Output> {
    type SideResources;

    fn keyswitch(
        &self,
        input: &Input,
        output: &mut Output,
        side_resources: &mut Self::SideResources,
    );
}
