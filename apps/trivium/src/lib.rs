mod static_deque;

mod kreyvium;
pub use kreyvium::{KreyviumStream, KreyviumStreamByte, KreyviumStreamShortint};

mod trivium;
pub use trivium::{TriviumStream, TriviumStreamByte, TriviumStreamShortint};

mod trans_ciphering;
pub use trans_ciphering::TransCiphering;
