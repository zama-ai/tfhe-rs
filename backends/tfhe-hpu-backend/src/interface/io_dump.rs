use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
/// Feature io_dump
/// Enable to log hpu object in hex file for debug purpose
use std::path::PathBuf;

use crate::interface::memory::ciphertext::SlotId;
use crate::prelude::HpuParameters;

thread_local! {
    static HPU_IO_DUMP: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

#[derive(Debug)]
pub enum DumpKind {
    Bsk,
    Ksk,
    Glwe,
    BlweIn,
    BlweOut,
}

impl DumpKind {
    const FOLDER: [&'static str; 4] = ["key", "blwe/input", "blwe/output", "glwe"];
}

pub fn set_hpu_io_dump(dir_path: &str) {
    // Enforce that given file_path exist
    let path = PathBuf::from(dir_path);
    if path.exists() {
        if path.is_file() {
            panic!("HPU_IO_DUMP: given file_path is a file. Directory expected");
        }
    } else {
        // Create it
        std::fs::create_dir_all(&path).unwrap();
    }
    // Create all subpath
    for f in DumpKind::FOLDER.iter() {
        let sub_path = path.join(f);
        std::fs::create_dir_all(sub_path).unwrap();
    }
    HPU_IO_DUMP.replace(Some(path));
}

#[derive(Debug)]
pub enum DumpId {
    Slot(SlotId, usize),
    Key(usize),
    Lut(usize),
}

pub fn dump<T: num_traits::PrimInt + num_traits::cast::AsPrimitive<u32>>(
    value: &[T],
    params: &HpuParameters,
    kind: DumpKind,
    id: DumpId,
) {
    HPU_IO_DUMP.with_borrow(|inner| {
        if let Some(path) = inner {
            // Open file
            let file_path = match id {
                DumpId::Slot(sid, cut) => match kind {
                    DumpKind::BlweIn => format!(
                        "{}/blwe/input/blwe_{:0>4x}_{cut:0>1x}.hex",
                        path.display(),
                        sid.0,
                    ),
                    DumpKind::BlweOut => format!(
                        "{}/blwe/output/blwe_{:0>4x}_{cut:0>1x}.hex",
                        path.display(),
                        sid.0,
                    ),
                    _ => panic!("Unexpected DumpId {id:?} with kind {kind:?}"),
                },

                DumpId::Key(cut) => match kind {
                    DumpKind::Bsk => format!("{}/key/bsk_{cut:0>1x}.hex", path.display(),),
                    DumpKind::Ksk => format!("{}/key/ksk_{cut:0>1x}.hex", path.display()),
                    _ => panic!("Unexpected DumpId {id:?} with kind {kind:?}"),
                },
                DumpId::Lut(cut) => match kind {
                    DumpKind::Glwe => format!("{}/glwe/glwe_{cut:0>2x}.hex", path.display()),
                    _ => panic!("Unexpected DumpId {id:?} with kind {kind:?}"),
                },
            };

            // Open file
            let mut wr_f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(file_path)
                .unwrap();

            // Dump
            // Based on configuration dump value must be shrunk to 32b (i.e. when contained
            // information is <= 32)
            let (word_bits, line_bytes) = match kind {
                DumpKind::Bsk => (params.ntt_params.ct_width, params.pc_params.bsk_bytes_w),
                DumpKind::Ksk => (
                    (params.ks_params.lbz * params.ks_params.width) as u32,
                    params.pc_params.ksk_bytes_w,
                ),
                DumpKind::Glwe => (params.ntt_params.ct_width, params.pc_params.glwe_bytes_w),
                DumpKind::BlweIn => (params.ntt_params.ct_width, params.pc_params.pem_bytes_w),
                DumpKind::BlweOut => (params.ntt_params.ct_width, params.pc_params.pem_bytes_w),
            };

            // Shrink value to 32b when possible
            if word_bits <= u32::BITS {
                let value_32b = value
                    .into_iter()
                    .map(|x| {
                        let x_u32: u32 = x.as_();
                        x_u32
                    })
                    .collect::<Vec<u32>>();
                value_32b
                    .as_slice()
                    .write_hex(&mut wr_f, line_bytes, Some("XX"));
            } else {
                value.write_hex(&mut wr_f, line_bytes, Some("XX"));
            }
        }
    })
}

/// HexMem dump trait.
///
/// Enable to generate a .mem in hex format from a rust structure.
/// `.mem` are used by RTL to load constants or stimulus
pub trait HexMem {
    fn as_bytes(&self) -> &[u8];

    fn write_hex(&self, into: &mut File, line_w: usize, pad_with: Option<&str>) {
        // Use write buffer for performances purpose
        let mut into_wrbfr = BufWriter::new(into);

        let bytes = self.as_bytes();

        let lines = bytes.len() / line_w;
        let residual = bytes.len() % line_w;

        // Write full lines
        for l in 0..lines {
            let cur_slice = &bytes[l * line_w..(l + 1) * line_w];
            for c in cur_slice.iter().rev() {
                write!(into_wrbfr, "{:02x}", c).unwrap();
            }
            writeln!(into_wrbfr).unwrap();
        }

        // Add padding if requested
        if let Some(padder) = pad_with {
            assert_eq!(
                padder.len(),
                2,
                "Padding str length must be 2 (u8 written in hex)."
            );
            let pad_len = if 0 != residual { line_w - residual } else { 0 };
            for _ in 0..pad_len {
                write!(into_wrbfr, "{padder}").unwrap();
            }
        }
        // Write residual line
        let res_slice = &bytes[lines * line_w..];
        for c in res_slice.iter().rev() {
            write!(into_wrbfr, "{:02x}", c).unwrap();
        }
        writeln!(into_wrbfr).unwrap();
    }
}

// Blanket implementation for primitive integer slice
impl<T> HexMem for &[T]
where
    T: num_traits::PrimInt,
{
    #[cfg(target_endian = "little")]
    fn as_bytes(&self) -> &[u8] {
        let len = std::mem::size_of_val(*self);
        let ptr = self.as_ptr() as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
    #[cfg(target_endian = "big")]
    compile_error!("Macro implementation of HexMem trait only supported on Little-endian machine");
}
