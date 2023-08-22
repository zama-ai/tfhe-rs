#[allow(clippy::module_inception)]
mod trivium;
pub use trivium::TriviumStream;

mod trivium_byte;
pub use trivium_byte::TriviumStreamByte;

mod trivium_shortint;
pub use trivium_shortint::TriviumStreamShortint;

#[cfg(test)]
mod test;
