use crate::cmd;
use std::io::Error;

pub fn test_book_boolean() -> Result<(), Error> {
    cmd!("cargo build -p concrete-boolean --release")?;
    cmd!("rustdoc --test concrete-boolean/docs/user/introduction.md -L target/release/deps")?;
    cmd!("rustdoc --test concrete-boolean/docs/user/how_does_it_work.md -L target/release/deps")?;
    cmd!("rustdoc --test concrete-boolean/docs/user/tutorial.md -L target/release/deps")?;
    cmd!("rustdoc --test concrete-boolean/docs/user/error.md -L target/release/deps")?;
    cmd!("rustdoc --test concrete-boolean/docs/user/advanced_topics/generate_keys.md -L target/release/deps")?;
    cmd!("rustdoc --test concrete-boolean/docs/user/advanced_topics/save_load.md -L target/release/deps")
}
