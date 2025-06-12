use std::str::FromStr;

pub const UNUSED_FIELD_LEN: usize = 5;
pub const HASH_FIELD_LEN: usize = 7;
pub const FREQ_FIELD_LEN: usize = 4;
pub const VERSION_FIELD_LEN: usize = 2;
pub const NTT_ARCH_FIELD_LEN: usize = 1;
pub const PSI_FIELD_LEN: usize = 1;
pub const HOST_FIELD_LEN: usize = 1;
pub const USER_FIELD_LEN: usize = 1;
pub const DATE_FIELD_LEN: usize = 10;
pub const UUID_LEN: usize = UNUSED_FIELD_LEN
    + HASH_FIELD_LEN
    + FREQ_FIELD_LEN
    + VERSION_FIELD_LEN
    + NTT_ARCH_FIELD_LEN
    + PSI_FIELD_LEN
    + HOST_FIELD_LEN
    + USER_FIELD_LEN
    + DATE_FIELD_LEN;

pub(crate) const AMI_UUID_WORDS: usize = 4;

fn from_readable_hex(s: &str) -> usize {
    s.chars()
        .flat_map(|c| c.to_digit(10))
        .map(|v| v as usize)
        .fold(0, |acc, v| 10 * acc + v)
}

struct Hash(usize);
impl std::fmt::Display for Hash {
    // Hash is on 7hex digits
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:7>0x}", self.0)
    }
}

impl FromStr for Hash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != HASH_FIELD_LEN {
            Err("Hash sub-field: Invalid length".to_string())
        } else {
            Ok(Self(
                usize::from_str_radix(s, 16).map_err(|err| format!("Hash sub-field: {err:?}"))?,
            ))
        }
    }
}

pub struct Freq(usize);

impl std::fmt::Display for Freq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Freq_MHz: {}", self.0)
    }
}

// NB: Freq is displayed on 4 hex digits in human readable form
impl FromStr for Freq {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != FREQ_FIELD_LEN {
            Err("Freq sub-field: Invalid length".to_string())
        } else {
            Ok(Self(from_readable_hex(s)))
        }
    }
}

pub struct Version {
    major: usize,
    minor: usize,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}.{}", self.major, self.minor)
    }
}

// NB: Freq is displayed on 4 hex digits in human readable form
impl FromStr for Version {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != VERSION_FIELD_LEN {
            Err("Version sub-field: Invalid length".to_string())
        } else {
            let minor = from_readable_hex(&s[0..=0]);
            let major = from_readable_hex(&s[1..=1]);
            Ok(Self { major, minor })
        }
    }
}

#[derive(Debug)]
pub enum NttArch {
    Unfold = 4,
    GF64 = 5,
}

impl FromStr for NttArch {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != NTT_ARCH_FIELD_LEN {
            Err("NttArch sub-field: Invalid length".to_string())
        } else {
            let val = from_readable_hex(s);
            match val {
                0x4 => Ok(NttArch::Unfold),
                0x5 => Ok(NttArch::GF64),
                _ => Err(format!("NttArch sub-field: Invalid value {val}")),
            }
        }
    }
}

#[derive(Debug)]
pub enum Host {
    SrvZama = 1,
    Unknown,
}

impl FromStr for Host {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != PSI_FIELD_LEN {
            Err("Host sub-field: Invalid length".to_string())
        } else {
            let val = from_readable_hex(s);
            match val {
                0x1 => Ok(Host::SrvZama),
                _ => Ok(Host::Unknown),
            }
        }
    }
}

#[derive(Debug)]
pub enum Psi {
    Psi16 = 0,
    Psi32 = 1,
    Psi64 = 2,
}
impl FromStr for Psi {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != PSI_FIELD_LEN {
            Err("Psi sub-field: Invalid length".to_string())
        } else {
            let val = from_readable_hex(s);
            match val {
                0x0 => Ok(Psi::Psi16),
                0x1 => Ok(Psi::Psi32),
                0x2 => Ok(Psi::Psi64),
                _ => Err(format!("Psi sub-field: Invalid value {val}")),
            }
        }
    }
}

#[derive(Debug)]
pub struct User(usize);

impl FromStr for User {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != USER_FIELD_LEN {
            Err("User sub-field: Invalid length".to_string())
        } else {
            Ok(Self(from_readable_hex(s)))
        }
    }
}

impl std::fmt::Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

pub struct Date {
    year: usize,
    month: usize,
    day: usize,
    hour: usize,
    min: usize,
}

impl FromStr for Date {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != DATE_FIELD_LEN {
            Err("Date sub-field: Invalid length".to_string())
        } else {
            Ok(Self {
                year: from_readable_hex(&s[0..2]),
                month: from_readable_hex(&s[2..4]),
                day: from_readable_hex(&s[4..6]),
                hour: from_readable_hex(&s[6..8]),
                min: from_readable_hex(&s[8..10]),
            })
        }
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:0>2}/{:0>2}/{:0>2}::{:0>2}h{:0>2}",
            self.year, self.month, self.day, self.hour, self.min
        )
    }
}

pub struct V80Uuid {
    hash: Hash,
    freq: Freq,
    version: Version,
    arch: NttArch,
    psi: Psi,
    host: Host,
    user: User,
    date: Date,
}

impl std::fmt::Display for V80Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "hash: {}", self.hash)?;
        writeln!(f, "freq: {}", self.freq)?;
        writeln!(f, "version: {}", self.version)?;
        writeln!(f, "arch: {:?}", self.arch)?;
        writeln!(f, "psi: {:?}", self.psi)?;
        writeln!(f, "host: {:?}", self.host)?;
        writeln!(f, "user: {}", self.user)?;
        writeln!(f, "date: {}", self.date)?;
        Ok(())
    }
}

impl FromStr for V80Uuid {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != UUID_LEN {
            Err("UUID: Invalid length".to_string())
        } else {
            let mut idx = UNUSED_FIELD_LEN;
            let hash = Hash::from_str(&s[idx..idx + HASH_FIELD_LEN])?;
            idx += HASH_FIELD_LEN;
            let freq = Freq::from_str(&s[idx..idx + FREQ_FIELD_LEN])?;
            idx += FREQ_FIELD_LEN;
            let version = Version::from_str(&s[idx..idx + VERSION_FIELD_LEN])?;
            idx += VERSION_FIELD_LEN;
            let arch = NttArch::from_str(&s[idx..idx + NTT_ARCH_FIELD_LEN])?;
            idx += NTT_ARCH_FIELD_LEN;
            let psi = Psi::from_str(&s[idx..idx + PSI_FIELD_LEN])?;
            idx += PSI_FIELD_LEN;
            let host = Host::from_str(&s[idx..idx + HOST_FIELD_LEN])?;
            idx += HOST_FIELD_LEN;
            let user = User::from_str(&s[idx..idx + USER_FIELD_LEN])?;
            idx += USER_FIELD_LEN;
            let date = Date::from_str(&s[idx..idx + DATE_FIELD_LEN])?;

            Ok(Self {
                hash,
                freq,
                version,
                arch,
                psi,
                host,
                user,
                date,
            })
        }
    }
}
