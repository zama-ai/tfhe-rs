pub trait Named {
    /// Default name for the type
    const NAME: &'static str;
    /// Aliases that should also be accepted for backward compatibility when checking the name of
    /// values of this type
    const BACKWARD_COMPATIBILITY_ALIASES: &'static [&'static str] = &[];
}
