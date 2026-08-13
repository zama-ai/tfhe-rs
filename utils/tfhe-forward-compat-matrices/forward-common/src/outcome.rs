//! One attempt at loading one artifact, and how a per-version binary hands it
//! over to the orchestrator: one tab separated line per artifact, on stdout.

/// What the consumer version made of an artifact.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub ok: bool,
    pub detail: String,
}

/// An [`Outcome`] as read back from a binary's stdout, still tied to its artifact.
#[derive(Clone, Debug)]
pub struct Report {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

pub fn report(name: &str, res: Result<(), String>) {
    match res {
        Ok(()) => println!("{name}\tOK\t"),
        Err(detail) => println!("{name}\tFAIL\t{detail}"),
    }
}

pub fn parse_report(line: &str) -> Option<Report> {
    // The detail comes last and may hold tabs of its own.
    let mut it = line.splitn(3, '\t');
    let name = it.next()?.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let status = it.next()?;
    let detail = it.next().unwrap_or("").trim().to_string();
    Some(Report {
        name,
        ok: status == "OK",
        detail,
    })
}

/// Collapse a failure reason to a single line: everything downstream of it, the
/// baseline file as well as the markdown tables, is line oriented.
pub(crate) fn single_line(detail: &str) -> String {
    detail.replace(['\n', '\r'], " ").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reported_failure_survives_the_stdout_round_trip() {
        let parsed = parse_report("CompactPkeCrs\tFAIL\tinvalid value: integer `1`").unwrap();

        assert_eq!(parsed.name, "CompactPkeCrs");
        assert!(!parsed.ok);
        assert_eq!(parsed.detail, "invalid value: integer `1`");
    }

    #[test]
    fn a_line_without_a_status_is_not_a_report() {
        assert!(parse_report("").is_none());
        assert!(parse_report("just some cargo noise").is_none());
    }
}
