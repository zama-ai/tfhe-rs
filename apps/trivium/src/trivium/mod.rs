mod trivium_bool;
pub use trivium_bool::TriviumStream;

mod trivium_byte;
pub use trivium_byte::TriviumStreamByte;

mod trivium_shortint;
pub use trivium_shortint::TriviumStreamShortint;

#[cfg(test)]
mod test;
