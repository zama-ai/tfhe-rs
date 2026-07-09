use std::fmt;

pub(crate) trait SpecNode: fmt::Display {
    fn child(&self) -> Option<&dyn SpecNode> {
        None
    }
}

pub(crate) fn write_spec(node: &dyn SpecNode, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "::{node}")?;
    if let Some(child) = node.child() {
        write_spec(child, f)?;
    }
    Ok(())
}
