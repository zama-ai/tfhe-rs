//!
//! Define hex encoding for a subset of known DOp
//! DOp are defined with two section: {Type, subtype}

/// Opcode structure
/// Gather DOp type and subtype
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Opcode {
    optype: DOpType,
    subtype: u8,
}

/// Define Instruction type as C-like enumeration
/// Types are encoded with 2bits
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum DOpType {
    ARITH = 0b00,
    SYNC = 0b01,
    MEM = 0b10,
    PBS = 0b11,
}

/// Define raw type conversion
/// Opcode is on 6bits
impl From<Opcode> for u8 {
    fn from(value: Opcode) -> Self {
        (((value.optype as u8) & 0x3) << 4) + value.subtype
    }
}
impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        let subtype = value & 0xf;
        let optype_raw = (value >> 4) & 0x3;
        let optype = match optype_raw {
            x if x == DOpType::ARITH as u8 => DOpType::ARITH,
            x if x == DOpType::SYNC as u8 => DOpType::SYNC,
            x if x == DOpType::MEM as u8 => DOpType::MEM,
            x if x == DOpType::PBS as u8 => DOpType::PBS,
            _ => panic!("Invalid DOpType"),
        };

        Self { optype, subtype }
    }
}

/// Implement helper function to create Arith DOp
impl Opcode {
    #[allow(non_snake_case)]
    pub fn ADD() -> Self {
        Self {
            optype: DOpType::ARITH,
            subtype: 0b0001,
        }
    }
    #[allow(non_snake_case)]
    pub fn SUB() -> Self {
        Self {
            optype: DOpType::ARITH,
            subtype: 0b0010,
        }
    }
    #[allow(non_snake_case)]
    pub fn MAC() -> Self {
        Self {
            optype: DOpType::ARITH,
            subtype: 0b0101,
        }
    }
}

/// Implement helper function to create ArithMsg DOp
impl Opcode {
    #[allow(non_snake_case)]
    pub fn ADDS() -> Self {
        Self {
            optype: DOpType::ARITH,
            subtype: 0b1001,
        }
    }
    #[allow(non_snake_case)]
    pub fn SUBS() -> Self {
        Self {
            optype: DOpType::ARITH,
            subtype: 0b1010,
        }
    }
    #[allow(non_snake_case)]
    pub fn SSUB() -> Self {
        Self {
            optype: DOpType::ARITH,
            subtype: 0b1011,
        }
    }
    #[allow(non_snake_case)]
    pub fn MULS() -> Self {
        Self {
            optype: DOpType::ARITH,
            subtype: 0b1100,
        }
    }
}

/// Implement helper function to create Sync DOp
impl Opcode {
    #[allow(non_snake_case)]
    pub fn SYNC() -> Self {
        Self {
            optype: DOpType::SYNC,
            subtype: 0b0000,
        }
    }
}

/// Implement helper function to create Memory DOp
impl Opcode {
    #[allow(non_snake_case)]
    pub fn LD() -> Self {
        Self {
            optype: DOpType::MEM,
            subtype: 0b0000,
        }
    }
    #[allow(non_snake_case)]
    pub fn ST() -> Self {
        Self {
            optype: DOpType::MEM,
            subtype: 0b0001,
        }
    }
}

/// Implement helper function to create Memory DOp
pub const PBS_HAS_FLUSH: u8 = 0b1000;
impl Opcode {
    #[allow(non_snake_case)]
    pub fn PBS(lut_nb: u8) -> Self {
        let lut_lg = super::ceil_ilog2(&lut_nb);
        let subtype = lut_lg & 0x3;
        Self {
            optype: DOpType::PBS,
            subtype,
        }
    }

    #[allow(non_snake_case)]
    pub fn PBS_F(lut_nb: u8) -> Self {
        let lut_lg = super::ceil_ilog2(&lut_nb);
        let subtype = PBS_HAS_FLUSH + (lut_lg & 0x3);
        Self {
            optype: DOpType::PBS,
            subtype,
        }
    }
}

impl Opcode {
    pub fn is_flush(&self) -> bool {
        (self.optype == DOpType::PBS) && (self.subtype & PBS_HAS_FLUSH) != 0
    }
    pub fn to_flush(&self) -> Self {
        Self {
            subtype: self.subtype | PBS_HAS_FLUSH,
            ..*self
        }
    }
}
