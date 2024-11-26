//!
//! Define hex encoding for a subset of known DOp

// Arith
pub const ADD: u8 = 0b00_0001;
pub const SUB: u8 = 0b00_0010;
pub const MAC: u8 = 0b00_0101;

// ArithMsg
pub const ADDS: u8 = 0b00_1001;
pub const SUBS: u8 = 0b00_1010;
pub const SSUB: u8 = 0b00_1011;
pub const MULS: u8 = 0b00_1100;

//Sync
pub const SYNC: u8 = 0b01_0000;

// LD/ST
pub const LD: u8 = 0b10_0000;
pub const ST: u8 = 0b10_0001;

// PBS
pub const PBS: u8 = 0b11_0000;
pub const PBS_ML2: u8 = 0b11_0001;
pub const PBS_ML4: u8 = 0b11_0010;
pub const PBS_ML8: u8 = 0b11_0011;
pub const PBS_F: u8 = 0b11_1000;
pub const PBS_ML2_F: u8 = 0b11_1001;
pub const PBS_ML4_F: u8 = 0b11_1010;
pub const PBS_ML8_F: u8 = 0b11_1011;
