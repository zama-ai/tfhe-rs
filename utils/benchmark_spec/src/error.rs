#[derive(Debug, thiserror::Error)]
pub enum SpecParseError {
    #[error("unknown token: {0}")]
    Unknown(String),

    #[error(transparent)]
    Strum(#[from] strum::ParseError),
}
