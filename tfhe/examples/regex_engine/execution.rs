use std::collections::HashMap;
use std::rc::Rc;
use tfhe::integer::{IntegerCiphertext, RadixCiphertext, ServerKey};

use crate::parser::u8_to_char;

#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum Executed {
    Constant { c: u8 },
    CtPos { at: usize },
    And { a: Box<Executed>, b: Box<Executed> },
    Or { a: Box<Executed>, b: Box<Executed> },
    Equal { a: Box<Executed>, b: Box<Executed> },
    GreaterOrEqual { a: Box<Executed>, b: Box<Executed> },
    LessOrEqual { a: Box<Executed>, b: Box<Executed> },
    Not { a: Box<Executed> },
}
type ExecutedResult = (RadixCiphertext, Executed);

impl Executed {
    pub(crate) fn ct_pos(at: usize) -> Self {
        Executed::CtPos { at }
    }

    fn get_trivial_constant(&self) -> Option<u8> {
        match self {
            Self::Constant { c } => Some(*c),
            _ => None,
        }
    }
}

const CT_FALSE: u8 = 0;
const CT_TRUE: u8 = 1;

pub(crate) struct Execution {
    sk: ServerKey,
    cache: HashMap<Executed, RadixCiphertext>,

    ct_ops: usize,
    cache_hits: usize,
}
pub(crate) type LazyExecution = Rc<dyn Fn(&mut Execution) -> ExecutedResult>;

impl Execution {
    pub(crate) fn new(sk: ServerKey) -> Self {
        Self {
            sk,
            cache: HashMap::new(),
            ct_ops: 0,
            cache_hits: 0,
        }
    }

    pub(crate) fn ct_operations_count(&self) -> usize {
        self.ct_ops
    }

    pub(crate) fn cache_hits(&self) -> usize {
        self.cache_hits
    }

    pub(crate) fn ct_eq(&mut self, a: ExecutedResult, b: ExecutedResult) -> ExecutedResult {
        let ctx = Executed::Equal {
            a: Box::new(a.1.clone()),
            b: Box::new(b.1.clone()),
        };
        self.with_cache(
            ctx.clone(),
            Rc::new(move |exec: &mut Execution| {
                exec.ct_ops += 1;

                let mut ct_a = a.0.clone();
                let mut ct_b = b.0.clone();
                (
                    exec.sk
                        .smart_eq(&mut ct_a, &mut ct_b)
                        .into_radix(ct_a.blocks().len(), &exec.sk),
                    ctx.clone(),
                )
            }),
        )
    }

    pub(crate) fn ct_ge(&mut self, a: ExecutedResult, b: ExecutedResult) -> ExecutedResult {
        let ctx = Executed::GreaterOrEqual {
            a: Box::new(a.1.clone()),
            b: Box::new(b.1.clone()),
        };
        self.with_cache(
            ctx.clone(),
            Rc::new(move |exec| {
                exec.ct_ops += 1;

                let mut ct_a = a.0.clone();
                let mut ct_b = b.0.clone();
                (
                    exec.sk
                        .smart_gt(&mut ct_a, &mut ct_b)
                        .into_radix(ct_a.blocks().len(), &exec.sk),
                    ctx.clone(),
                )
            }),
        )
    }

    pub(crate) fn ct_le(&mut self, a: ExecutedResult, b: ExecutedResult) -> ExecutedResult {
        let ctx = Executed::LessOrEqual {
            a: Box::new(a.1.clone()),
            b: Box::new(b.1.clone()),
        };
        self.with_cache(
            ctx.clone(),
            Rc::new(move |exec| {
                exec.ct_ops += 1;

                let mut ct_a = a.0.clone();
                let mut ct_b = b.0.clone();
                (
                    exec.sk
                        .smart_le(&mut ct_a, &mut ct_b)
                        .into_radix(ct_a.blocks().len(), &exec.sk),
                    ctx.clone(),
                )
            }),
        )
    }

    pub(crate) fn ct_and(&mut self, a: ExecutedResult, b: ExecutedResult) -> ExecutedResult {
        let ctx = Executed::And {
            a: Box::new(a.1.clone()),
            b: Box::new(b.1.clone()),
        };

        let c_a = a.1.get_trivial_constant();
        let c_b = b.1.get_trivial_constant();
        if c_a == Some(CT_TRUE) {
            return (b.0, ctx);
        }
        if c_a == Some(CT_FALSE) {
            return (a.0, ctx);
        }
        if c_b == Some(CT_TRUE) {
            return (a.0, ctx);
        }
        if c_b == Some(CT_FALSE) {
            return (b.0, ctx);
        }

        self.with_cache(
            ctx.clone(),
            Rc::new(move |exec| {
                exec.ct_ops += 1;

                let mut ct_a = a.0.clone();
                let mut ct_b = b.0.clone();
                (exec.sk.smart_bitand(&mut ct_a, &mut ct_b), ctx.clone())
            }),
        )
    }

    pub(crate) fn ct_or(&mut self, a: ExecutedResult, b: ExecutedResult) -> ExecutedResult {
        let ctx = Executed::Or {
            a: Box::new(a.1.clone()),
            b: Box::new(b.1.clone()),
        };

        let c_a = a.1.get_trivial_constant();
        let c_b = b.1.get_trivial_constant();
        if c_a == Some(CT_TRUE) {
            return (a.0, ctx);
        }
        if c_b == Some(CT_TRUE) {
            return (b.0, ctx);
        }
        if c_a == Some(CT_FALSE) && c_b == Some(CT_FALSE) {
            return (a.0, ctx);
        }

        self.with_cache(
            ctx.clone(),
            Rc::new(move |exec| {
                exec.ct_ops += 1;

                let mut ct_a = a.0.clone();
                let mut ct_b = b.0.clone();
                (exec.sk.smart_bitor(&mut ct_a, &mut ct_b), ctx.clone())
            }),
        )
    }

    pub(crate) fn ct_not(&mut self, a: ExecutedResult) -> ExecutedResult {
        let ctx = Executed::Not {
            a: Box::new(a.1.clone()),
        };
        self.with_cache(
            ctx.clone(),
            Rc::new(move |exec| {
                exec.ct_ops += 1;

                let mut ct_a = a.0.clone();
                let mut ct_b = exec.ct_constant(1).0;
                (exec.sk.smart_bitxor(&mut ct_a, &mut ct_b), ctx.clone())
            }),
        )
    }

    pub(crate) fn ct_false(&self) -> ExecutedResult {
        self.ct_constant(CT_FALSE)
    }

    pub(crate) fn ct_true(&self) -> ExecutedResult {
        self.ct_constant(CT_TRUE)
    }

    pub(crate) fn ct_constant(&self, c: u8) -> ExecutedResult {
        (
            self.sk.create_trivial_radix(c as u64, 4),
            Executed::Constant { c },
        )
    }

    fn with_cache(&mut self, ctx: Executed, f: LazyExecution) -> ExecutedResult {
        if let Some(res) = self.cache.get(&ctx) {
            trace!("cache hit: {:?}", &ctx);
            self.cache_hits += 1;
            return (res.clone(), ctx);
        }
        debug!("evaluation for: {:?}", &ctx);
        let res = f(self);
        self.cache.insert(ctx, res.0.clone());
        res
    }
}

impl std::fmt::Debug for Executed {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Constant { c } => match c {
                0 => write!(f, "f"),
                1 => write!(f, "t"),
                _ => write!(f, "{}", u8_to_char(*c)),
            },
            Self::CtPos { at } => write!(f, "ct_{}", at),
            Self::And { a, b } => {
                write!(f, "(")?;
                a.fmt(f)?;
                write!(f, "/\\")?;
                b.fmt(f)?;
                write!(f, ")")
            }
            Self::Or { a, b } => {
                write!(f, "(")?;
                a.fmt(f)?;
                write!(f, "\\/")?;
                b.fmt(f)?;
                write!(f, ")")
            }
            Self::Equal { a, b } => {
                write!(f, "(")?;
                a.fmt(f)?;
                write!(f, "==")?;
                b.fmt(f)?;
                write!(f, ")")
            }
            Self::GreaterOrEqual { a, b } => {
                write!(f, "(")?;
                a.fmt(f)?;
                write!(f, ">=")?;
                b.fmt(f)?;
                write!(f, ")")
            }
            Self::LessOrEqual { a, b } => {
                write!(f, "(")?;
                a.fmt(f)?;
                write!(f, "<=")?;
                b.fmt(f)?;
                write!(f, ")")
            }
            Self::Not { a } => {
                write!(f, "(!")?;
                a.fmt(f)?;
                write!(f, ")")
            }
        }
    }
}
