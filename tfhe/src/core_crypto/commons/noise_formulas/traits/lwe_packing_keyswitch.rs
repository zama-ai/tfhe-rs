pub trait AllocateLwePackingKeyswitchResult {
    type Output;
    type SideResources;

    fn allocate_lwe_packing_keyswitch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}

pub trait LwePackingKeyswitch<Input: ?Sized, Output> {
    type SideResources;

    fn keyswitch_lwes_and_pack_in_glwe(
        &self,
        input: &Input,
        output: &mut Output,
        side_resources: &mut Self::SideResources,
    );
}
