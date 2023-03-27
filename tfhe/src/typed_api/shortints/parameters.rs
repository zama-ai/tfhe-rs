pub trait ShortIntegerParameter:
    Copy + Into<crate::shortint::Parameters<crate::shortint::KeyswitchBootstrap>>
{
    type Id: Copy;
}

pub trait StaticShortIntegerParameter: ShortIntegerParameter {
    const MESSAGE_BITS: u8;
}
