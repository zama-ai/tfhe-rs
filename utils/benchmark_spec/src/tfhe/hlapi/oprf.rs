use strum::Display;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum OprfKind {
    AnyRange,
    /// Custom-range generation fused with re-randomization of the output.
    AnyRangeRerand,
}
