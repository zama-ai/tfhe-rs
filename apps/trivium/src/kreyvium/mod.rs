#[allow(clippy::module_inception)]
mod kreyvium;
pub use kreyvium::KreyviumStream;

mod kreyvium_byte;
pub use kreyvium_byte::KreyviumStreamByte;

mod kreyvium_shortint;
pub use kreyvium_shortint::KreyviumStreamShortint;

#[cfg(test)]
mod test;
