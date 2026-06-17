use std::fmt::Write as _;

pub const LIMIT: u64 = 1 << 30;
pub const CLEAR_U8: u8 = 42;
pub const CLEAR_U32: u32 = 0xDEADBEEF;
pub const CLEAR_BOOL: bool = true;
pub const PROVEN_LEN: usize = 3;
pub const ZK_METADATA: &[u8] = b"fwd-compat";

pub struct Artifact {
    pub name: &'static str,
    pub file: &'static str,
}

pub const ARTIFACTS: [Artifact; 3] = [
    Artifact {
        name: "CompactPublicKey",
        file: "compact_public_key.bin",
    },
    Artifact {
        name: "CompactPkeCrs",
        file: "compact_pke_crs.bin",
    },
    Artifact {
        name: "ProvenCompactCiphertextList",
        file: "proven_compact_list.bin",
    },
];

pub fn file_of(name: &str) -> &'static str {
    ARTIFACTS
        .iter()
        .find(|a| a.name == name)
        .unwrap_or_else(|| panic!("unknown artifact {name:?}"))
        .file
}

/// Serialize `$val` into the file registered for `$name`.
/// `safe_serialize` is resolved at the call site (the per-version tfhe).
#[macro_export]
macro_rules! write_artifact {
    ($dir:expr, $name:expr, $val:expr) => {{
        let mut bytes = ::std::vec::Vec::new();
        ::tfhe::safe_serialization::safe_serialize(&$val, &mut bytes, $crate::LIMIT).unwrap();
        ::std::fs::write($dir.join($crate::file_of($name)), &bytes).unwrap();
    }};
}

/// Deserialize the file registered for `$name` as `$ty` -> `Result<$ty, String>`.
/// `safe_deserialize` is resolved at the call site (the per-version tfhe).
#[macro_export]
macro_rules! load {
    ($dir:expr, $name:expr, $ty:ty) => {
        ::std::fs::read($dir.join($crate::file_of($name)))
            .map_err(|e| e.to_string())
            .and_then(|b| {
                ::tfhe::safe_serialization::safe_deserialize::<$ty>(b.as_slice(), $crate::LIMIT)
            })
    };
}

pub fn report(name: &str, res: Result<(), String>) {
    match res {
        Ok(()) => println!("{name}\tOK\t"),
        Err(detail) => println!("{name}\tFAIL\t{detail}"),
    }
}

#[derive(Clone, Debug)]
pub struct Report {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

pub fn parse_report(line: &str) -> Option<Report> {
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

#[derive(Clone, Debug)]
pub struct Cell {
    pub ok: bool,
    pub detail: String,
}

pub struct Matrix {
    pub versions: Vec<String>,
    pub directions: Vec<(usize, usize)>,
    pub rows: Vec<(String, Vec<Option<Cell>>)>,
}

impl Matrix {
    fn col_label(&self, col: usize) -> String {
        let (p, c) = self.directions[col];
        format!("{}>{}", self.versions[p], self.versions[c])
    }

    fn cell_str(c: &Option<Cell>) -> String {
        match c {
            Some(Cell { ok: true, .. }) => "OK".to_string(),
            Some(Cell { ok: false, detail }) => {
                let reason = detail.replace(['\n', '\r'], " ").replace('|', "\\|");
                let reason = reason.trim();
                if reason.is_empty() {
                    "FAIL".to_string()
                } else {
                    format!("FAIL: {reason}")
                }
            }
            None => "-".to_string(),
        }
    }

    pub fn render_markdown(&self) -> String {
        let labels: Vec<String> = (0..self.directions.len())
            .map(|i| self.col_label(i))
            .collect();
        let mut out = String::new();
        out.push_str("| TYPE |");
        for l in &labels {
            let _ = write!(out, " {l} |");
        }
        out.push('\n');
        out.push_str("| --- |");
        for _ in &labels {
            out.push_str(" --- |");
        }
        out.push('\n');
        for (name, cells) in &self.rows {
            let _ = write!(out, "| {name} |");
            for c in cells {
                let _ = write!(out, " {} |", Self::cell_str(c));
            }
            out.push('\n');
        }
        out
    }
}
