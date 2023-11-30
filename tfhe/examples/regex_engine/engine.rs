use crate::execution::{Executed, Execution, LazyExecution};
use crate::parser::{parse, RegExpr};
use std::rc::Rc;
use tfhe::integer::{RadixCiphertext, ServerKey};

pub fn has_match(
    sk: &ServerKey,
    content: &[RadixCiphertext],
    pattern: &str,
) -> Result<RadixCiphertext, Box<dyn std::error::Error>> {
    let re = parse(pattern)?;

    let branches: Vec<LazyExecution> = (0..content.len())
        .flat_map(|i| build_branches(content, &re, i))
        .map(|(lazy_branch_res, _)| lazy_branch_res)
        .collect();

    let mut exec = Execution::new(sk.clone());

    let res = if branches.len() <= 1 {
        branches
            .first()
            .map_or(exec.ct_false(), |branch| branch(&mut exec))
            .0
    } else {
        branches[1..]
            .iter()
            .fold(branches[0](&mut exec), |res, branch| {
                let branch_res = branch(&mut exec);
                exec.ct_or(res, branch_res)
            })
            .0
    };
    info!(
        "{} ciphertext operations, {} cache hits",
        exec.ct_operations_count(),
        exec.cache_hits(),
    );
    Ok(res)
}

fn build_branches(
    content: &[RadixCiphertext],
    re: &RegExpr,
    c_pos: usize,
) -> Vec<(LazyExecution, usize)> {
    trace!("program pointer: regex={:?}, content pos={}", re, c_pos);
    match re {
        RegExpr::Sof => {
            if c_pos == 0 {
                return vec![(Rc::new(|exec| exec.ct_true()), c_pos)];
            } else {
                return vec![];
            }
        }
        RegExpr::Eof => {
            if c_pos == content.len() {
                return vec![(Rc::new(|exec| exec.ct_true()), c_pos)];
            } else {
                return vec![];
            }
        }
        _ => (),
    };

    if c_pos >= content.len() {
        return vec![];
    }

    match re.clone() {
        RegExpr::Char { c } => {
            let c_char = (content[c_pos].clone(), Executed::ct_pos(c_pos));
            vec![(
                Rc::new(move |exec| exec.ct_eq(c_char.clone(), exec.ct_constant(c))),
                c_pos + 1,
            )]
        }
        RegExpr::AnyChar => vec![(Rc::new(|exec| exec.ct_true()), c_pos + 1)],
        RegExpr::Not { not_re } => build_branches(content, &not_re, c_pos)
            .into_iter()
            .map(|(branch, c_pos)| {
                (
                    Rc::new(move |exec: &mut Execution| {
                        let branch_res = branch(exec);
                        exec.ct_not(branch_res)
                    }) as LazyExecution,
                    c_pos,
                )
            })
            .collect(),
        RegExpr::Either { l_re, r_re } => {
            let mut res = build_branches(content, &l_re, c_pos);
            res.append(&mut build_branches(content, &r_re, c_pos));
            res
        }
        RegExpr::Between { from, to } => {
            let c_char = (content[c_pos].clone(), Executed::ct_pos(c_pos));
            vec![(
                Rc::new(move |exec| {
                    let ct_from = exec.ct_constant(from);
                    let ct_to = exec.ct_constant(to);
                    let ge_from = exec.ct_ge(c_char.clone(), ct_from);
                    let le_to = exec.ct_le(c_char.clone(), ct_to);
                    exec.ct_and(ge_from, le_to)
                }),
                c_pos + 1,
            )]
        }
        RegExpr::Range { cs } => {
            let c_char = (content[c_pos].clone(), Executed::ct_pos(c_pos));
            vec![(
                Rc::new(move |exec| {
                    cs[1..].iter().fold(
                        exec.ct_eq(c_char.clone(), exec.ct_constant(cs[0])),
                        |res, c| {
                            let ct_c_char_eq = exec.ct_eq(c_char.clone(), exec.ct_constant(*c));
                            exec.ct_or(res, ct_c_char_eq)
                        },
                    )
                }),
                c_pos + 1,
            )]
        }
        RegExpr::Repeated {
            repeat_re,
            at_least,
            at_most,
        } => {
            let at_least = at_least.unwrap_or(0);
            let at_most = at_most.unwrap_or(content.len() - c_pos);

            if at_least > at_most {
                return vec![];
            }

            let mut res = vec![
                if at_least == 0 {
                    vec![(
                        Rc::new(|exec: &mut Execution| exec.ct_true()) as LazyExecution,
                        c_pos,
                    )]
                } else {
                    vec![]
                },
                build_branches(
                    content,
                    &(RegExpr::Seq {
                        re_xs: std::iter::repeat(*repeat_re.clone())
                            .take(std::cmp::max(1, at_least))
                            .collect(),
                    }),
                    c_pos,
                ),
            ];

            for _ in (at_least + 1)..(at_most + 1) {
                res.push(
                    res.last()
                        .unwrap()
                        .iter()
                        .flat_map(|(branch_prev, branch_c_pos)| {
                            build_branches(content, &repeat_re, *branch_c_pos)
                                .into_iter()
                                .map(move |(branch_x, branch_x_c_pos)| {
                                    let branch_prev = branch_prev.clone();
                                    (
                                        Rc::new(move |exec: &mut Execution| {
                                            let res_prev = branch_prev(exec);
                                            let res_x = branch_x(exec);
                                            exec.ct_and(res_prev, res_x)
                                        }) as LazyExecution,
                                        branch_x_c_pos,
                                    )
                                })
                        })
                        .collect(),
                );
            }
            res.into_iter().flatten().collect()
        }
        RegExpr::Optional { opt_re } => {
            let mut res = build_branches(content, &opt_re, c_pos);
            res.push((Rc::new(|exec| exec.ct_true()), c_pos));
            res
        }
        RegExpr::Seq { re_xs } => re_xs[1..].iter().fold(
            build_branches(content, &re_xs[0], c_pos),
            |continuations, re_x| {
                continuations
                    .into_iter()
                    .flat_map(|(branch_prev, branch_prev_c_pos)| {
                        build_branches(content, re_x, branch_prev_c_pos)
                            .into_iter()
                            .map(move |(branch_x, branch_x_c_pos)| {
                                let branch_prev = branch_prev.clone();
                                (
                                    Rc::new(move |exec: &mut Execution| {
                                        let res_prev = branch_prev(exec);
                                        let res_x = branch_x(exec);
                                        exec.ct_and(res_prev, res_x)
                                    }) as LazyExecution,
                                    branch_x_c_pos,
                                )
                            })
                    })
                    .collect()
            },
        ),
        _ => panic!("unmatched regex variant"),
    }
}

#[cfg(test)]
mod tests {
    use crate::engine::has_match;
    use test_case::test_case;

    use crate::ciphertext::{encrypt_str, gen_keys, StringCiphertext};
    use lazy_static::lazy_static;
    use tfhe::integer::{RadixClientKey, ServerKey};

    lazy_static! {
        pub static ref KEYS: (RadixClientKey, ServerKey) = gen_keys();
    }

    #[test_case("ab", "/ab/", 1)]
    #[test_case("b", "/ab/", 0)]
    #[test_case("ab", "/a?b/", 1)]
    #[test_case("b", "/a?b/", 1)]
    #[test_case("ab", "/^ab|cd$/", 1)]
    #[test_case(" ab", "/^ab|cd$/", 0)]
    #[test_case(" cd", "/^ab|cd$/", 0)]
    #[test_case("cd", "/^ab|cd$/", 1)]
    #[test_case("abcd", "/^ab|cd$/", 0)]
    #[test_case("abcd", "/ab|cd$/", 1)]
    #[test_case("abc", "/abc/", 1)]
    #[test_case("123abc", "/abc/", 1)]
    #[test_case("123abc456", "/abc/", 1)]
    #[test_case("123abdc456", "/abc/", 0)]
    #[test_case("abc456", "/abc/", 1)]
    #[test_case("bc", "/a*bc/", 1)]
    #[test_case("cdaabc", "/a*bc/", 1)]
    #[test_case("cdbc", "/a+bc/", 0)]
    #[test_case("bc", "/a+bc/", 0)]
    #[test_case("Ab", "/ab/i", 1 ; "ab case insensitive")]
    #[test_case("Ab", "/ab/", 0 ; "ab case sensitive")]
    #[test_case("cD", "/ab|cd/i", 1)]
    #[test_case("cD", "/cD/", 1)]
    #[test_case("test a num 8", "/8/", 1)]
    #[test_case("test a num 8", "/^8/", 0)]
    #[test_case("4453", "/^[0-9]*$/", 1)]
    #[test_case("4453", "/^[09]*$/", 0)]
    #[test_case("09009", "/^[09]*$/", 1)]
    #[test_case("de", "/^ab|cd|de$/", 1 ; "multiple or")]
    #[test_case(" de", "/^ab|cd|de$/", 0 ; "multiple or nests below ^")]
    fn test_has_match(content: &str, pattern: &str, exp: u64) {
        let ct_content: StringCiphertext = encrypt_str(&KEYS.0, content).unwrap();
        let ct_res = has_match(&KEYS.1, &ct_content, pattern).unwrap();

        let got = KEYS.0.decrypt(&ct_res);
        assert_eq!(exp, got);
    }
}
