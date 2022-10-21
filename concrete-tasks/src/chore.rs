use crate::cmd;
use std::io::Error;

pub fn format() -> Result<(), Error> {
    cmd!("cargo +nightly fmt")
}
