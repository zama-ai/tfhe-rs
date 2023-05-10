pub trait ShortIntegerParameter: Copy + Into<crate::shortint::ClassicPBSParameters> {
    type Id: Copy;
}

pub trait StaticShortIntegerParameter: ShortIntegerParameter {
    const MESSAGE_BITS: u8;
}
