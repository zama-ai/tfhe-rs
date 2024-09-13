//! IOp definition is repetitive
//!
//! Indeed except the behavior IOp shared a small set of format.
//! And for a given format all the parsing logic is the same
//! This could be done with derive proc macro with a set of attributes
//! But for timinig purpose (and lake of knowledge of proc_macro) we use simple macro_rules
//! The results is less extendable but enable to reduce the repetition in IOp definition

#[macro_export]
macro_rules! ct_ct_iop {
    (
        $asm: literal
        $(,)?
    ) => {
        ::paste::paste! {
        #[derive(Debug, Clone)]
        pub struct [<IOp $asm:camel>] {
            dst: MemSlot,
            src_1: MemSlot,
            src_0: MemSlot,
        }

        impl Default for [<IOp $asm:camel>]{
            fn default() -> Self {
                Self {
                    dst: MemSlot::default_user(MemOrigin::Dst),
                    src_0: MemSlot::default_user(MemOrigin::SrcA),
                    src_1: MemSlot::default_user(MemOrigin::SrcB),
                }
            }
        }

        impl Asm for [<IOp $asm:camel>] {
            fn name(&self) -> &'static str {
                $asm
            }

            fn has_imm(&self) -> bool {
                false
            }

            fn args(&self) -> Vec<Arg> {
                vec![Arg::MemId(self.dst), Arg::MemId(self.src_0), Arg::MemId(self.src_1)]
            }

            fn dst(&self) -> Vec<Arg> {
                vec![Arg::MemId(self.dst)]
            }

            fn src(&self) -> Vec<Arg> {
                vec![Arg::MemId(self.src_0), Arg::MemId(self.src_1)]
            }

            fn from_args(&mut self, args: Vec<Arg>) -> Result<(), anyhow::Error> {
                if args.len() != 3 {
                    return Err(ArgError::InvalidNumber(3, args.len()).into());
                }

                match args[0] {
                    Arg::MemId(ids) => {
                        self.dst = ids;
                        self.dst.orig = Some(MemOrigin::Dst);
                    }
                    _ => return Err(ArgError::InvalidField("Arg::MemId".to_string(), args[0]).into()),
                }

                match args[1] {
                    Arg::MemId(ids) => {
                        self.src_0 = ids;
                        self.src_0.orig = Some(MemOrigin::SrcA);
                    }
                    _ => return Err(ArgError::InvalidField("Arg::MemId".to_string(), args[1]).into()),
                }
                match args[2] {
                    Arg::MemId(ids) => {
                        // update orig field
                        self.src_1 = ids;
                        self.src_1.orig = Some(MemOrigin::SrcB);
                    }
                    _ => return Err(ArgError::InvalidField("Arg::MemId".to_string(), args[2]).into()),
                }
                Ok(())
            }

            fn randomize(&mut self, props: &ArchProperties, rng: &mut StdRng) {
                self.dst = MemSlot::new(props, props.mem.bid, (rng.gen_range(0..(props.mem.size-props.blk_w()))/props.blk_w())*props.blk_w(), MemMode::Int{width: props.blk_w()*props.msg_w, pos: None}, Some(MemOrigin::Dst)).unwrap();
                self.src_0 = MemSlot::new(props, props.mem.bid, (rng.gen_range(0..(props.mem.size-props.blk_w()))/props.blk_w())*props.blk_w(), MemMode::Int{width: props.blk_w()*props.msg_w, pos: None}, Some(MemOrigin::SrcA)).unwrap();
                self.src_1 = MemSlot::new(props, props.mem.bid, (rng.gen_range(0..(props.mem.size-props.blk_w()))/props.blk_w())*props.blk_w(), MemMode::Int{width: props.blk_w()*props.msg_w, pos: None}, Some(MemOrigin::SrcB)).unwrap();
            }

            fn asm_encode(&self, width: usize) -> String {
                format!(
                    "{: <width$} {: <width$} {: <width$} {: <width$}",
                    self.name(),
                    // NB: Trick to impose width rendering
                    format!("{}", Arg::MemId(self.dst)),
                    format!("{}", Arg::MemId(self.src_0)),
                    format!("{}", Arg::MemId(self.src_1)),
                    width = width,
                )
            }
    }

    impl AsmBin for [<IOp $asm:camel>] {
            fn bin_encode_le(&self) -> Result<Vec<u8>, anyhow::Error> {
                let fmt_iop = fmt::IOp {
                    opcode : fmt::Opcode(fmt::iopcode::[<$asm>]),
                    fields : fmt::IOpField::[<$asm>](fmt::CtCtInsn {
                        pad_0: 0,
                        dst_ofst: self.dst.bid as u8,
                        dst_cid: self.dst.cid() as u16,
                        src_0_ofst: self.src_0.bid as u8,
                        src_0_cid: self.src_0.cid() as u16,
                        src_1_ofst: self.src_1.bid as u8,
                        src_1_cid: self.src_1.cid() as u16,
                        }),
                };

                // fmt is defined in big-endian to correctly use opcode for field decoding
                // However, the rest of the stack expect Little-endian ordering
                // -> revert the bytes stream
                let mut bytes_be = fmt_iop.to_bytes()?;
                let bytes_le = {
                    let be = bytes_be.as_mut_slice();
                    be.reverse();
                    bytes_be
                };
                Ok(bytes_le)
            }

            fn from_deku(&mut self, any: &dyn Any) -> Result<(), ParsingError>{
                let deku = match any.downcast_ref::<iop::fmt::IOp>() {
                    Some(d) => d,
                    None => return Err(ParsingError::Unmatch),
                };

                if deku.opcode.0 != fmt::iopcode::[<$asm>] {
                    Err(ParsingError::Unmatch)
                } else {
                    match &deku.fields {
                        fmt::IOpField::[<$asm>](f) => {
                            self.dst.bid= f.dst_ofst as usize;
                            self.dst.cid_ofst = f.dst_cid as usize;
                            self.dst.mode = MemMode::Raw;
                            self.dst.orig = Some(MemOrigin::Dst);
                            self.src_0.bid = f.src_0_ofst as usize;
                            self.src_0.cid_ofst = f.src_0_cid as usize;
                            self.src_0.mode = MemMode::Raw;
                            self.src_0.orig = Some(MemOrigin::SrcA);
                            self.src_1.bid = f.src_1_ofst as usize;
                            self.src_1.cid_ofst = f.src_1_cid as usize;
                            self.src_1.mode = MemMode::Raw;
                            self.src_1.orig = Some(MemOrigin::SrcB);
                            Ok(())
                        }
                        _ => Err(ParsingError::InvalidArg("".to_string()))
                    }
                }
            }
        }
        }
    };
}

#[macro_export]
macro_rules! ct_imm_iop {
    (
        $asm: literal
        $(,)?
    ) => {
        ::paste::paste! {
        #[derive(Debug, Clone)]
        pub struct [<IOp $asm:camel>] {
            dst: MemSlot,
            src: MemSlot,
            pub imm: usize,
        }


        impl Default for [<IOp $asm:camel>]{
            fn default() -> Self {
                Self {
                    dst: MemSlot::default_user(MemOrigin::Dst),
                    src: MemSlot::default_user(MemOrigin::SrcA),
                    imm: 0,
                }
            }
        }

        impl Asm for [<IOp $asm:camel>] {
            fn name(&self) -> &'static str {
                $asm
            }

            fn has_imm(&self) -> bool {
                true
            }

            fn args(&self) -> Vec<Arg> {
                vec![Arg::MemId(self.dst), Arg::MemId(self.src), Arg::Imm(self.imm)]
            }

            fn dst(&self) -> Vec<Arg> {
                vec![Arg::MemId(self.dst)]
            }

            fn src(&self) -> Vec<Arg> {
                vec![Arg::MemId(self.src), Arg::Imm(self.imm)]
            }

            fn from_args(&mut self, args: Vec<Arg>) -> Result<(), anyhow::Error> {
                if args.len() != 3 {
                    return Err(ArgError::InvalidNumber(3, args.len()).into());
                }

                match args[0] {
                    Arg::MemId(ids) => {
                        self.dst = ids;
                        self.dst.orig = Some(MemOrigin::Dst);
                    }
                    _ => return Err(ArgError::InvalidField("Arg::MemId".to_string(), args[0]).into()),
                }

                match args[1] {
                    Arg::MemId(ids) => {
                        self.src = ids;
                        self.src.orig = Some(MemOrigin::SrcA);
                    }
                    _ => return Err(ArgError::InvalidField("Arg::MemId".to_string(), args[1]).into()),
                }
                match args[2] {
                    Arg::Imm(id) => {
                        self.imm = id;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::Imm".to_string(), args[2]).into()),
                }
                Ok(())
            }

            fn randomize(&mut self, props: &ArchProperties, rng: &mut StdRng) {
                self.dst = MemSlot::new(props, props.mem.bid, (rng.gen_range(0..(props.mem.size-props.blk_w()))/props.blk_w())*props.blk_w(), MemMode::Int{width: props.blk_w()*props.msg_w, pos: None}, Some(MemOrigin::Dst)).unwrap();
                self.src = MemSlot::new(props, props.mem.bid, (rng.gen_range(0..(props.mem.size-props.blk_w()))/props.blk_w())*props.blk_w(), MemMode::Int{width: props.blk_w()*props.msg_w, pos: None}, Some(MemOrigin::SrcA)).unwrap();
                self.imm = rng.gen_range(0..(1_u128 <<props.integer_w)) as usize;
            }

            fn asm_encode(&self, width: usize) -> String {
                format!(
                    "{: <width$} {: <width$} {: <width$} {: <width$}",
                    self.name(),
                    // NB: Trick to impose width rendering
                    format!("{}", Arg::MemId(self.dst)),
                    format!("{}", Arg::MemId(self.src)),
                    format!("{}", Arg::Imm(self.imm)),
                    width = width,
                )
            }
    }

    impl AsmBin for [<IOp $asm:camel>] {
            fn bin_encode_le(&self) -> Result<Vec<u8>, anyhow::Error> {
                let imm_len = (usize::BITS - self.imm.leading_zeros()).div_ceil(32);
                let imm_vec = (0..imm_len).map(|w| ((self.imm >> (u32::BITS*w)) & u32::MAX as usize) as u32).collect::<Vec<u32>>();
                let fmt_iop = fmt::IOp {
                    opcode : fmt::Opcode(fmt::iopcode::[<$asm>]),
                    fields : fmt::IOpField::[<$asm>](fmt::CtImmInsn {
                        pad_0: 0,
                        src_ofst: self.src.bid as u8,
                        dst_ofst: self.dst.bid as u8,
                        dst_cid: self.dst.cid() as u16,
                        pad_1: 0,
                        imm_len: imm_vec.len() as u8,
                        src_cid: self.src.cid() as u16,
                        imm_val: imm_vec,
                        }),
                };
                // fmt is defined in big-endian to correctly use opcode for field decoding
                // However, the rest of the stack expect Little-endian ordering
                // -> revert the bytes stream
                let mut bytes_be = fmt_iop.to_bytes()?;
                let bytes_le = {
                    let be = bytes_be.as_mut_slice();
                    be.reverse();
                    bytes_be
                };
                Ok(bytes_le)
            }

            fn from_deku(&mut self, any: &dyn Any) -> Result<(), ParsingError>{
                let deku = match any.downcast_ref::<iop::fmt::IOp>() {
                    Some(d) => d,
                    None => return Err(ParsingError::Unmatch),
                };

                if deku.opcode.0 != fmt::iopcode::[<$asm>] {
                    Err(ParsingError::Unmatch)
                } else {
                    match &deku.fields {
                        fmt::IOpField::[<$asm>](f) => {
                            self.dst.bid= f.dst_ofst as usize;
                            self.dst.cid_ofst = f.dst_cid as usize;
                            self.dst.mode = MemMode::Raw;
                            self.dst.orig = Some(MemOrigin::Dst);
                            self.src.bid= f.src_ofst as usize;
                            self.src.cid_ofst = f.src_cid as usize;
                            self.src.mode = MemMode::Raw;
                            self.src.orig = Some(MemOrigin::SrcA);
                            self.imm = f.imm_val.iter()
                                                .enumerate()
                                                .fold(0_usize, |acc, (idx, word)| acc + ((*word as usize) << (idx * u32::BITS as usize)));

                            Ok(())
                        }
                        _ => Err(ParsingError::InvalidArg("".to_string()))
                    }
                }
            }
        }
        }
    };
}
