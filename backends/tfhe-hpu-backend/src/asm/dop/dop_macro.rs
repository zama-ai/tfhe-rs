//! DOp definition is repetitive
//!
//! Indeed except the behavior DOp shared a small set of format.
//! And for a given format all the parsing logic is the same
//! This could be done with derive proc macro with a set of attributes
//! But for timinig purpose (and lake of knowledge of proc_macro) we use simple macro_rules
//! The results is less extendable but enable to reduce the repetition in DOp definition

#[macro_export]
macro_rules! arith_dop {
    (
        $asm: literal
        $(,)?
    ) => {
        ::paste::paste! {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
        pub struct [<DOp $asm:camel>] {
            pub dst: usize,
            pub src: (usize, usize),
        }

        impl Default for [<DOp $asm:camel>]{
            fn default() -> Self {
                Self {
                    dst: 0,
                    src: (0, 0),
                }
            }
        }

        impl Asm for [<DOp $asm:camel>] {
            fn name(&self) -> &'static str {
                $asm
            }

            fn has_imm(&self) -> bool {
                false
            }

            fn args(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.dst), Arg::RegId(self.src.0), Arg::RegId(self.src.1)]
            }

            fn dst(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.dst)]
            }

            fn src(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.src.0), Arg::RegId(self.src.1)]
            }

            fn from_args(&mut self, args: Vec<Arg>) -> Result<(), anyhow::Error> {
                if args.len() != 3 {
                    return Err(ArgError::InvalidNumber(3, args.len()).into());
                }

                match args[0] {
                    Arg::RegId(id) => {
                        self.dst = id;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::RegId".to_string(), args[0]).into()),
                }

                match args[1] {
                    Arg::RegId(id) => {
                        self.src.0 = id;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::RegId".to_string(), args[1]).into()),
                }

                match args[2] {
                    Arg::RegId(id) => {
                        self.src.1 = id;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::RegId".to_string(), args[2]).into()),
                }

                Ok(())
            }

            fn randomize(&mut self, props: &ArchProperties, rng: &mut StdRng) {
                self.dst = rng.gen_range(0..props.regs);
                self.src.0 = rng.gen_range(0..props.regs);
                self.src.1 = rng.gen_range(0..props.regs);
            }

            fn asm_encode(&self, width: usize) -> String {
                format!(
                    "{: <width$} {: <width$} {: <width$} {: <width$}",
                    self.name(),
                    // NB: Trick to impose width rendering
                    format!("{}", Arg::RegId(self.dst)),
                    format!("{}", Arg::RegId(self.src.0)),
                    format!("{}", Arg::RegId(self.src.1)),
                    width = width,
                )
            }
    }

    impl AsmBin for [<DOp $asm:camel>] {
            fn bin_encode_le(&self) -> Result<Vec<u8>, anyhow::Error> {
                let fmt_dop = fmt::DOp {
                    opcode : fmt::Opcode(fmt::dopcode::[<$asm>]),
                    fields : fmt::DOpField::[<$asm>](fmt::PeArithInsn {
                        mul_factor: 0,
                        src1_rid: self.src.1 as u8,
                        src0_rid: self.src.0 as u8,
                        dst_rid: self.dst as u8,
                        }),
                };
                // fmt is defined in big-endian to correctly use opcode for field decoding
                // However, the rest of the stack expect Little-endian ordering
                // -> revert the bytes stream
                let mut bytes_be = fmt_dop.to_bytes()?;
                let bytes_le = {
                    let be = bytes_be.as_mut_slice();
                    be.reverse();
                    bytes_be
                };
                Ok(bytes_le)
            }

            fn from_deku(&mut self, any: &dyn Any) -> Result<(), ParsingError>{
                let deku = match any.downcast_ref::<dop::fmt::DOp>() {
                    Some(d) => d,
                    None => return Err(ParsingError::Unmatch),
                };

                if deku.opcode.0 != fmt::dopcode::[<$asm>] {
                    Err(ParsingError::Unmatch.into())
                } else {
                    match &deku.fields {
                        fmt::DOpField::[<$asm>](f) => {
                            self.src.1 = f.src1_rid as usize;
                            self.src.0 = f.src0_rid as usize;
                            self.dst = f.dst_rid as usize;
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
macro_rules! arith_mf_dop {
    (
        $asm: literal
        $(,)?
    ) => {
        ::paste::paste! {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
        pub struct [<DOp $asm:camel>] {
            pub dst: usize,
            pub src: (usize, usize),
            pub mul_factor: usize
        }

        impl Default for [<DOp $asm:camel>]{
            fn default()-> Self {
                Self {
                    dst: 0,
                    src: (0, 0),
                    mul_factor: 0
                }
            }
        }

        impl Asm for [<DOp $asm:camel>] {
            fn name(&self) -> &'static str {
                $asm
            }

            fn has_imm(&self) -> bool {
                true
            }

            fn args(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.dst), Arg::RegId(self.src.0), Arg::RegId(self.src.1), Arg::Imm(self.mul_factor)]
            }

            fn dst(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.dst)]
            }

            fn src(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.src.0), Arg::RegId(self.src.1)]
            }

            fn from_args(&mut self, args: Vec<Arg>) -> Result<(), anyhow::Error> {
                if args.len() != 4{
                    return Err(ArgError::InvalidNumber(4, args.len()).into());
                }

                match args[0] {
                    Arg::RegId(id) => {
                        self.dst = id;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::RegId".to_string(), args[0]).into()),
                }

                match args[1] {
                    Arg::RegId(id) => {
                        self.src.0 = id;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::RegId".to_string(), args[1]).into()),
                }

                match args[2] {
                    Arg::RegId(id) => {
                        self.src.1 = id;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::RegId".to_string(), args[2]).into()),
                }

                match args[3] {
                    Arg::Imm(s) => {
                        self.mul_factor = s;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::Imm".to_string(), args[3]).into()),
                }
                Ok(())
            }

            fn randomize(&mut self, props: &ArchProperties, rng: &mut StdRng) {
                self.dst = rng.gen_range(0..props.regs);
                self.src.0 = rng.gen_range(0..props.regs);
                self.src.1 = rng.gen_range(0..props.regs);
                self.mul_factor = rng.gen_range(0..(1 << props.msg_w));
            }

            fn asm_encode(&self, width: usize) -> String {
                format!(
                    "{: <width$} {: <width$} {: <width$} {: <width$} {: <width$}",
                    self.name(),
                    // NB: Trick to impose width rendering
                    format!("{}", Arg::RegId(self.dst)),
                    format!("{}", Arg::RegId(self.src.0)),
                    format!("{}", Arg::RegId(self.src.1)),
                    format!("{}", Arg::Imm(self.mul_factor)),
                    width = width,
                )
            }
    }

    impl AsmBin for [<DOp $asm:camel>] {
            fn bin_encode_le(&self) -> Result<Vec<u8>, anyhow::Error> {
                let fmt_dop = fmt::DOp {
                    opcode : fmt::Opcode(fmt::dopcode::[<$asm>]),
                    fields : fmt::DOpField::[<$asm>](fmt::PeArithInsn {
                        mul_factor: self.mul_factor as u8,
                        src1_rid: self.src.1 as u8,
                        src0_rid: self.src.0 as u8,
                        dst_rid: self.dst as u8,
                        }),
                };
                // fmt is defined in big-endian to correctly use opcode for field decoding
                // However, the rest of the stack expect Little-endian ordering
                // -> revert the bytes stream
                let mut bytes_be = fmt_dop.to_bytes()?;
                let bytes_le = {
                    let be = bytes_be.as_mut_slice();
                    be.reverse();
                    bytes_be
                };
                Ok(bytes_le)
            }

            fn from_deku(&mut self, any: &dyn Any) -> Result<(), ParsingError>{
                let deku = match any.downcast_ref::<dop::fmt::DOp>() {
                    Some(d) => d,
                    None => return Err(ParsingError::Unmatch),
                };

                if deku.opcode.0 != fmt::dopcode::[<$asm>] {
                    Err(ParsingError::Unmatch)
                } else {
                    match &deku.fields {
                        fmt::DOpField::[<$asm>](f) => {
                            self.mul_factor = f.mul_factor as usize;
                            self.src.1 = f.src1_rid as usize;
                            self.src.0 = f.src0_rid as usize;
                            self.dst = f.dst_rid as usize;
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
macro_rules! arith_msg_dop {
    (
        $asm: literal
        $(,)?
    ) => {
        ::paste::paste! {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
        pub struct [<DOp $asm:camel>] {
            pub dst: usize,
            pub src: usize,
            pub msg_cst: usize
        }

        impl Default for [<DOp $asm:camel>]{
            fn default() -> Self {
                Self {
                    dst: 0,
                    src: 0,
                    msg_cst: 0
                }
            }
        }

        impl Asm for [<DOp $asm:camel>] {
            fn name(&self) -> &'static str {
                $asm
            }

            fn has_imm(&self) -> bool {
                true
            }

            fn args(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.dst), Arg::RegId(self.src), Arg::Imm(self.msg_cst)]
            }

            fn dst(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.dst)]
            }

            fn src(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.src)]
            }

            fn from_args(&mut self, args: Vec<Arg>) -> Result<(), anyhow::Error> {
                if args.len() != 3{
                    return Err(ArgError::InvalidNumber(3, args.len()).into());
                }

                match args[0] {
                    Arg::RegId(id) => {
                        self.dst = id;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::RegId".to_string(), args[0]).into()),
                }

                match args[1] {
                    Arg::RegId(id) => {
                        self.src = id;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::RegId".to_string(), args[1]).into()),
                }

                match args[2] {
                    Arg::Imm(s) => {
                        self.msg_cst= s;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::Imm".to_string(), args[2]).into()),
                }
                Ok(())
            }

            fn randomize(&mut self, props: &ArchProperties, rng: &mut StdRng) {
                self.dst = rng.gen_range(0..props.regs);
                self.src = rng.gen_range(0..props.regs);
                self.msg_cst = rng.gen_range(0..(1 << (props.carry_w + props.msg_w)));
            }

            fn asm_encode(&self, width: usize) -> String {
                format!(
                    "{: <width$} {: <width$} {: <width$} {: <width$}",
                    self.name(),
                    // NB: Trick to impose width rendering
                    format!("{}", Arg::RegId(self.dst)),
                    format!("{}", Arg::RegId(self.src)),
                    format!("{}", Arg::Imm(self.msg_cst)),
                    width = width,
                )
            }
    }

    impl AsmBin for [<DOp $asm:camel>] {
            fn bin_encode_le(&self) -> Result<Vec<u8>, anyhow::Error> {
                let fmt_dop = fmt::DOp {
                    opcode : fmt::Opcode(fmt::dopcode::[<$asm>]),
                    fields : fmt::DOpField::[<$asm>](fmt::PeArithMsgInsn {
                        msg_cst: self.msg_cst as u16,
                        src_rid: self.src as u8,
                        dst_rid: self.dst as u8,
                        }),
                };
                // fmt is defined in big-endian to correctly use opcode for field decoding
                // However, the rest of the stack expect Little-endian ordering
                // -> revert the bytes stream
                let mut bytes_be = fmt_dop.to_bytes()?;
                let bytes_le = {
                    let be = bytes_be.as_mut_slice();
                    be.reverse();
                    bytes_be
                };
                Ok(bytes_le)
            }

            fn from_deku(&mut self, any: &dyn Any) -> Result<(), ParsingError>{
                let deku = match any.downcast_ref::<dop::fmt::DOp>() {
                    Some(d) => d,
                    None => return Err(ParsingError::Unmatch),
                };

                if deku.opcode.0 != fmt::dopcode::[<$asm>] {
                    Err(ParsingError::Unmatch)
                } else {
                    match &deku.fields {
                        fmt::DOpField::[<$asm>](f) => {
                            self.msg_cst = f.msg_cst as usize;
                            self.src = f.src_rid as usize;
                            self.dst = f.dst_rid as usize;
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
macro_rules! memld_dop {
    (
        $asm: literal,
        $mem_orig: expr
        $(,)?
    ) => {
        ::paste::paste! {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
        pub struct [<DOp $asm:camel>] {
            pub dst: usize,
            pub src: MemSlot,
        }

        impl Default for [<DOp $asm:camel>]{
            fn default() -> Self {
                Self {
                    dst: 0,
                    src: MemSlot::default(),
                }
            }
        }

        impl Asm for [<DOp $asm:camel>] {
            fn name(&self) -> &'static str {
                $asm
            }

            fn has_imm(&self) -> bool {
                false
            }

            fn args(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.dst), Arg::MemId(self.src)]
            }

            fn dst(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.dst)]
            }

            fn src(&self) -> Vec<Arg> {
                vec![Arg::MemId(self.src)]
            }

            fn from_args(&mut self, args: Vec<Arg>) -> Result<(), anyhow::Error> {
                if args.len() != 2 {
                    return Err(ArgError::InvalidNumber(2, args.len()).into());
                }

                match args[0] {
                    Arg::RegId(id) => {
                        self.dst = id;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::RegId".to_string(), args[0]).into()),
                }

                match args[1] {
                    Arg::MemId(ids) => {
                        self.src = ids;
                        if $mem_orig.is_some() {
                            // NB: Integer mode inner slot must be ported back on cid_ofst
                            match self.src.mode {
                                MemMode::Int{pos,..} => {
                                    self.src.cid_ofst += pos.unwrap_or(0);
                                }
                                _ =>{}
                            }
                            self.src.mode = MemMode::Template;
                        }
                        self.src.orig = $mem_orig;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::MemId".to_string(), args[1]).into()),
                }
                Ok(())
            }

            fn randomize(&mut self, props: &ArchProperties, rng: &mut StdRng) {
                self.dst = rng.gen_range(0..props.regs);
                self.src = if $mem_orig.is_some() {
                        MemSlot::new(props, props.mem.bid, rng.gen_range(0..props.mem.size), MemMode::Template, $mem_orig).unwrap()
                    } else {
                        MemSlot::new(props, props.mem.bid, rng.gen_range(0..props.mem.size), MemMode::Int{width: props.blk_w(), pos: Some(rng.gen_range(0..props.blk_w()))}, $mem_orig).unwrap()
                    };
            }

            fn asm_encode(&self, width: usize) -> String {
                format!(
                    "{: <width$} {: <width$} {: <width$}",
                    "LD",
                    // NB: Trick to impose width rendering
                    format!("{}", Arg::RegId(self.dst)),
                    format!("{}", Arg::MemId(self.src)),
                    width = width,
                )
            }
    }

    impl AsmBin for [<DOp $asm:camel>] {
            fn bin_encode_le(&self) -> Result<Vec<u8>, anyhow::Error> {
                let fmt_dop = fmt::DOp {
                    opcode : fmt::Opcode(fmt::dopcode::[<$asm>]),
                    fields : fmt::DOpField::[<$asm>](fmt::PeMemInsn {
                        ct_ofst: self.src.bid as u8,
                        cid: self.src.cid() as u16,
                        rid: self.dst as u8,
                        }),
                };
                // fmt is defined in big-endian to correctly use opcode for field decoding
                // However, the rest of the stack expect Little-endian ordering
                // -> revert the bytes stream
                let mut bytes_be = fmt_dop.to_bytes()?;
                let bytes_le = {
                    let be = bytes_be.as_mut_slice();
                    be.reverse();
                    bytes_be
                };
                Ok(bytes_le)
            }

            fn from_deku(&mut self, any: &dyn Any) -> Result<(), ParsingError>{
                let deku = match any.downcast_ref::<dop::fmt::DOp>() {
                    Some(d) => d,
                    None => return Err(ParsingError::Unmatch),
                };

                if deku.opcode.0 != fmt::dopcode::[<$asm>] {
                    Err(ParsingError::Unmatch)
                } else {
                    match &deku.fields {
                        fmt::DOpField::[<$asm>](f) => {
                            if $mem_orig.is_some() { // Templated LD
                                self.src.bid = f.ct_ofst as usize;
                                self.src.cid_ofst = f.cid as usize;
                                self.src.mode = MemMode::Template;
                                self.src.orig = $mem_orig;
                                self.dst = f.rid as usize;
                            } else {
                                self.src.bid = f.ct_ofst as usize;
                                self.src.cid_ofst = f.cid as usize;
                                self.src.mode = MemMode::Raw;
                                self.src.orig = $mem_orig;
                                self.dst = f.rid as usize;
                            }
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
macro_rules! memst_dop {
    (
        $asm: literal,
        $mem_orig: expr
        $(,)?
    ) => {
        ::paste::paste! {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
        pub struct [<DOp $asm:camel>] {
            pub dst: MemSlot,
            pub src: usize,
        }

        impl Default for [<DOp $asm:camel>]{
            fn default() -> Self {
                Self {
                    dst: MemSlot::default(),
                    src: 0
                }
            }
        }

        impl Asm for [<DOp $asm:camel>] {
            fn name(&self) -> &'static str {
                $asm
            }

            fn has_imm(&self) -> bool {
                false
            }

            fn args(&self) -> Vec<Arg> {
                vec![Arg::MemId(self.dst), Arg::RegId(self.src)]
            }

            fn dst(&self) -> Vec<Arg> {
                vec![Arg::MemId(self.dst)]
            }

            fn src(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.src)]
            }

            fn from_args(&mut self, args: Vec<Arg>) -> Result<(), anyhow::Error> {
                if args.len() != 2 {
                    return Err(ArgError::InvalidNumber(2, args.len()).into());
                }

                match args[0] {
                    Arg::MemId(ids) => {
                        self.dst = ids;
                        if $mem_orig.is_some() {
                            // NB: Integer mode inner slot must be ported back on cid_ofst
                            match self.dst.mode {
                                MemMode::Int{pos,..} => {
                                    self.dst.cid_ofst += pos.unwrap_or(0);
                                }
                                _ =>{}
                            }
                            self.dst.mode = MemMode::Template;
                        }
                        self.dst.orig = $mem_orig;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::MemId".to_string(), args[1]).into()),
                }
                match args[1] {
                    Arg::RegId(id) => {
                        self.src = id;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::RegId".to_string(), args[0]).into()),
                }

                Ok(())
            }

            fn randomize(&mut self, props: &ArchProperties, rng: &mut StdRng) {
                self.dst = if $mem_orig.is_some() {
                        MemSlot::new(props, props.mem.bid, rng.gen_range(0..props.mem.size), MemMode::Template, $mem_orig).unwrap()
                    } else {
                        MemSlot::new(props, props.mem.bid, rng.gen_range(0..props.mem.size), MemMode::Int{width: props.blk_w(), pos: Some(rng.gen_range(0..props.blk_w()))}, $mem_orig).unwrap()
                    };
                self.src = rng.gen_range(0..props.regs);
            }

            fn asm_encode(&self, width: usize) -> String {
                format!(
                    "{: <width$} {: <width$} {: <width$}",
                    "ST",
                    // NB: Trick to impose width rendering
                    format!("{}", Arg::MemId(self.dst)),
                    format!("{}", Arg::RegId(self.src)),
                    width = width,
                )
            }
    }

    impl AsmBin for [<DOp $asm:camel>] {
            fn bin_encode_le(&self) -> Result<Vec<u8>, anyhow::Error> {
                let fmt_dop = fmt::DOp {
                    opcode : fmt::Opcode(fmt::dopcode::[<$asm>]),
                    fields : fmt::DOpField::[<$asm>](fmt::PeMemInsn {
                        ct_ofst: self.dst.bid as u8,
                        cid: self.dst.cid() as u16,
                        rid: self.src as u8,
                        }),
                };
                // fmt is defined in big-endian to correctly use opcode for field decoding
                // However, the rest of the stack expect Little-endian ordering
                // -> revert the bytes stream
                let mut bytes_be = fmt_dop.to_bytes()?;
                let bytes_le = {
                    let be = bytes_be.as_mut_slice();
                    be.reverse();
                    bytes_be
                };
                Ok(bytes_le)
            }

            fn from_deku(&mut self, any: &dyn Any) -> Result<(), ParsingError>{
                let deku = match any.downcast_ref::<dop::fmt::DOp>() {
                    Some(d) => d,
                    None => return Err(ParsingError::Unmatch),
                };

                if deku.opcode.0 != fmt::dopcode::[<$asm>] {
                    Err(ParsingError::Unmatch)
                } else {
                    match &deku.fields {
                        fmt::DOpField::[<$asm>](f) => {
                            if $mem_orig.is_some() { // Templated LD
                                self.dst.bid = f.ct_ofst as usize;
                                self.dst.cid_ofst = f.cid as usize;
                                self.dst.mode = MemMode::Template;
                                self.dst.orig = $mem_orig;
                                self.src = f.rid as usize;
                            } else {
                                self.dst.bid = f.ct_ofst as usize;
                                self.dst.cid_ofst = f.cid as usize;
                                self.dst.mode = MemMode::Raw;
                                self.dst.orig = $mem_orig;
                                self.src = f.rid as usize;
                            }
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
macro_rules! pbs_dop {
    (
        $asm: literal
        $(,)?
    ) => {
        ::paste::paste! {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
        pub struct [<DOp $asm:camel>] {
            pub dst: usize,
            pub src: usize,
            pub lut: Pbs,
        }

        impl Default for [<DOp $asm:camel>]{
            fn default() -> Self {
                Self {
                    dst: 0,
                    src: 0,
                    lut: Pbs::from_gid(0)
                }
            }
        }

        impl Asm for [<DOp $asm:camel>] {
            fn name(&self) -> &'static str {
                $asm
            }

            fn has_imm(&self) -> bool {
                false
            }

            fn args(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.dst), Arg::RegId(self.src), Arg::Pbs(self.lut)]
            }

            fn dst(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.dst)]
            }

            fn src(&self) -> Vec<Arg> {
                vec![Arg::RegId(self.src)]
            }

            fn from_args(&mut self, args: Vec<Arg>) -> Result<(), anyhow::Error> {
                if args.len() != 3{
                    return Err(ArgError::InvalidNumber(3, args.len()).into());
                }

                match args[0] {
                    Arg::RegId(id) => {
                        self.dst = id;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::RegId".to_string(), args[0]).into()),
                }

                match args[1] {
                    Arg::RegId(id) => {
                        self.src = id;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::RegId".to_string(), args[1]).into()),
                }

                match args[2] {
                    Arg::Pbs(lut) => {
                        self.lut = lut;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::Pbs".to_string(), args[2]).into()),
                }
                Ok(())
            }

            fn randomize(&mut self, props: &ArchProperties, rng: &mut StdRng) {
                self.dst = rng.gen_range(0..props.regs);
                self.src = rng.gen_range(0..props.regs);
                self.lut = Pbs::from_gid(rng.gen_range(0..Pbs::iter().count()));
            }

            fn asm_encode(&self, width: usize) -> String {
                format!(
                    "{: <width$} {: <width$} {: <width$} {: <width$}",
                    self.name(),
                    // NB: Trick to impose width rendering
                    format!("{}", Arg::RegId(self.dst)),
                    format!("{}", Arg::RegId(self.src)),
                    format!("{}", Arg::Pbs(self.lut)),
                    width = width,
                )
            }
    }

    impl AsmBin for [<DOp $asm:camel>] {
            fn bin_encode_le(&self) -> Result<Vec<u8>, anyhow::Error> {
                let fmt_dop = fmt::DOp {
                    opcode : fmt::Opcode(fmt::dopcode::[<$asm>]),
                    fields : fmt::DOpField::[<$asm>](fmt::PePbsInsn {
                        gid: self.lut.gid() as u32,
                        src_rid: self.src as u8,
                        dst_rid: self.dst as u8,
                        }),
                };
                // fmt is defined in big-endian to correctly use opcode for field decoding
                // However, the rest of the stack expect Little-endian ordering
                // -> revert the bytes stream
                let mut bytes_be = fmt_dop.to_bytes()?;
                let bytes_le = {
                    let be = bytes_be.as_mut_slice();
                    be.reverse();
                    bytes_be
                };
                Ok(bytes_le)
            }

            fn from_deku(&mut self, any: &dyn Any) -> Result<(), ParsingError>{
                let deku = match any.downcast_ref::<dop::fmt::DOp>() {
                    Some(d) => d,
                    None => return Err(ParsingError::Unmatch),
                };

                if deku.opcode.0 != fmt::dopcode::[<$asm>] {
                    Err(ParsingError::Unmatch)
                } else {
                    match &deku.fields {
                        fmt::DOpField::[<$asm>](f) => {
                            self.lut = Pbs::from_gid(f.gid as usize).into();
                            self.src = f.src_rid as usize;
                            self.dst = f.dst_rid as usize;
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
macro_rules! sync_dop {
    (
        $asm: literal
        $(,)?
    ) => {
        ::paste::paste! {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
        pub struct [<DOp $asm:camel>] {
            pub sid: usize
        }

        impl Default for [<DOp $asm:camel>]{
            fn default() -> Self {
                Self {
                    sid: 0
                }
            }
        }

        impl Asm for [<DOp $asm:camel>] {
            fn name(&self) -> &'static str {
                $asm
            }

            fn has_imm(&self) -> bool {
                false
            }

            fn args(&self) -> Vec<Arg> {
                vec![Arg::Imm(self.sid)]
            }

            fn dst(&self) -> Vec<Arg> {
                vec![]
            }

            fn src(&self) -> Vec<Arg> {
                vec![]
            }

            fn from_args(&mut self, args: Vec<Arg>) -> Result<(), anyhow::Error> {
                if args.len() != 1{
                    return Err(ArgError::InvalidNumber(1, args.len()).into());
                }

                match args[0] {
                    Arg::Imm(s) => {
                        self.sid= s;
                    }
                    _ => return Err(ArgError::InvalidField("Arg::Imm".to_string(), args[0]).into()),
                }
                Ok(())
            }

            fn randomize(&mut self, _props: &ArchProperties, rng: &mut StdRng) {
                self.sid = rng.gen_range(0..(1 << 26));
            }

            fn asm_encode(&self, width: usize) -> String {
                format!(
                    "{: <width$} {: <width$}",
                    self.name(),
                    // NB: Trick to impose width rendering
                    format!("{}", Arg::Imm(self.sid)),
                    width = width,
                )
            }
    }

    impl AsmBin for [<DOp $asm:camel>] {
            fn bin_encode_le(&self) -> Result<Vec<u8>, anyhow::Error> {
                let fmt_dop = fmt::DOp {
                    opcode : fmt::Opcode(fmt::dopcode::[<$asm>]),
                    fields : fmt::DOpField::[<$asm>](fmt::PeSyncInsn {
                        sid: self.sid as u32,
                        }),
                };
                // fmt is defined in big-endian to correctly use opcode for field decoding
                // However, the rest of the stack expect Little-endian ordering
                // -> revert the bytes stream
                let mut bytes_be = fmt_dop.to_bytes()?;
                let bytes_le = {
                    let be = bytes_be.as_mut_slice();
                    be.reverse();
                    bytes_be
                };
                Ok(bytes_le)
            }

            fn from_deku(&mut self, any: &dyn Any) -> Result<(), ParsingError>{
                let deku = match any.downcast_ref::<dop::fmt::DOp>() {
                    Some(d) => d,
                    None => return Err(ParsingError::Unmatch),
                };

                if deku.opcode.0 != fmt::dopcode::[<$asm>] {
                    Err(ParsingError::Unmatch.into())
                } else {
                    match &deku.fields {
                        fmt::DOpField::[<$asm>](f) => {
                            self.sid = f.sid as usize;
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
