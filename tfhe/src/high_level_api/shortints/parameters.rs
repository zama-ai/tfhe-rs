pub trait ShortIntegerParameter: Copy + Into<crate::shortint::Parameters> {
    type Id: Copy;
}

pub trait StaticShortIntegerParameter: ShortIntegerParameter {
    const MESSAGE_BITS: u8;
}
