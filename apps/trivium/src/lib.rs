mod static_deque;

mod kreyvium;
pub use kreyvium::KreyviumStream;
pub use kreyvium::KreyviumStreamByte;
pub use kreyvium::KreyviumStreamShortint;

mod trivium;
pub use trivium::TriviumStream;
pub use trivium::TriviumStreamByte;
pub use trivium::TriviumStreamShortint;

mod trans_ciphering;
pub use trans_ciphering::TransCiphering;
