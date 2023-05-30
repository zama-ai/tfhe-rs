use combine::parser::byte;
use combine::parser::byte::byte;
use combine::*;

use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum RegExpr {
    Sof,
    Eof,
    Char {
        c: u8,
    },
    AnyChar,
    Between {
        from: u8,
        to: u8,
    },
    Range {
        cs: Vec<u8>,
    },
    Not {
        not_re: Box<RegExpr>,
    },
    Either {
        l_re: Box<RegExpr>,
        r_re: Box<RegExpr>,
    },
    Optional {
        opt_re: Box<RegExpr>,
    },
    Repeated {
        repeat_re: Box<RegExpr>,
        at_least: Option<usize>, // if None: no least limit, aka 0 times
        at_most: Option<usize>,  // if None: no most limit
    },
    Seq {
        re_xs: Vec<RegExpr>,
    },
}

impl RegExpr {
    fn case_insensitive(self) -> Self {
        match self {
            Self::Char { c } => Self::Range {
                cs: case_insensitive(c),
            },
            Self::Not { not_re } => Self::Not {
                not_re: Box::new(not_re.case_insensitive()),
            },
            Self::Either { l_re, r_re } => Self::Either {
                l_re: Box::new(l_re.case_insensitive()),
                r_re: Box::new(r_re.case_insensitive()),
            },
            Self::Optional { opt_re } => Self::Optional {
                opt_re: Box::new(opt_re.case_insensitive()),
            },
            Self::Repeated {
                repeat_re,
                at_least,
                at_most,
            } => Self::Repeated {
                repeat_re: Box::new(repeat_re.case_insensitive()),
                at_least,
                at_most,
            },
            Self::Seq { re_xs } => Self::Seq {
                re_xs: re_xs.into_iter().map(|re| re.case_insensitive()).collect(),
            },
            _ => self,
        }
    }
}

fn case_insensitive(x: u8) -> Vec<u8> {
    let c = u8_to_char(x);
    if c.is_ascii_lowercase() {
        return vec![x, c.to_ascii_uppercase() as u8];
    }
    if c.is_ascii_uppercase() {
        return vec![x, c.to_ascii_lowercase() as u8];
    }
    vec![x]
}

pub(crate) fn u8_to_char(c: u8) -> char {
    char::from_u32(c as u32).unwrap()
}

impl fmt::Debug for RegExpr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Sof => write!(f, "^"),
            Self::Eof => write!(f, "$"),
            Self::Char { c } => write!(f, "{}", u8_to_char(*c)),
            Self::AnyChar => write!(f, "."),
            Self::Not { not_re } => {
                write!(f, "[^")?;
                not_re.fmt(f)?;
                write!(f, "]")
            }
            Self::Between { from, to } => {
                write!(f, "[{}->{}]", u8_to_char(*from), u8_to_char(*to),)
            }
            Self::Range { cs } => write!(
                f,
                "[{}]",
                cs.iter().map(|c| u8_to_char(*c)).collect::<String>(),
            ),
            Self::Either { l_re, r_re } => {
                write!(f, "(")?;
                l_re.fmt(f)?;
                write!(f, "|")?;
                r_re.fmt(f)?;
                write!(f, ")")
            }
            Self::Repeated {
                repeat_re,
                at_least,
                at_most,
            } => {
                let stringify_opt_n = |opt_n: &Option<usize>| -> String {
                    opt_n.map_or("*".to_string(), |n| format!("{:?}", n))
                };
                repeat_re.fmt(f)?;
                write!(
                    f,
                    "{{{},{}}}",
                    stringify_opt_n(at_least),
                    stringify_opt_n(at_most)
                )
            }
            Self::Optional { opt_re } => {
                opt_re.fmt(f)?;
                write!(f, "?")
            }
            Self::Seq { re_xs } => {
                write!(f, "<")?;
                for re_x in re_xs {
                    re_x.fmt(f)?;
                }
                write!(f, ">")?;
                Ok(())
            }
        }
    }
}

pub(crate) fn parse(pattern: &str) -> Result<RegExpr, Box<dyn std::error::Error>> {
    let (parsed, unparsed) = (
        between(
            byte(b'/'),
            byte(b'/'),
            (optional(byte(b'^')), regex(), optional(byte(b'$'))),
        )
        .map(|(sof, re, eof)| {
            if sof.is_none() && eof.is_none() {
                return re;
            }
            let mut re_xs = vec![];
            if sof.is_some() {
                re_xs.push(RegExpr::Sof);
            }
            re_xs.push(re);
            if eof.is_some() {
                re_xs.push(RegExpr::Eof);
            }
            RegExpr::Seq { re_xs }
        }),
        optional(byte(b'i')),
    )
        .map(|(re, case_insensitive)| {
            if case_insensitive.is_some() {
                re.case_insensitive()
            } else {
                re
            }
        })
        .parse(pattern.as_bytes())?;
    if !unparsed.is_empty() {
        return Err(format!(
            "failed to parse regular expression, unexpected token at start of: {}",
            std::str::from_utf8(unparsed).unwrap()
        )
        .into());
    }

    Ok(parsed)
}

// based on grammar from: https://matt.might.net/articles/parsing-regex-with-recursive-descent/
//
//  <regex> ::= <term> '|' <regex>
//           |  <term>
//
//  <term> ::= { <factor> }
//
//  <factor> ::= <base> { '*' }
//
//  <base> ::= <char>
//          |  '\' <char>
//          |  '(' <regex> ')'

parser! {
    fn regex[Input]()(Input) -> RegExpr
        where [Input: Stream<Token = u8>]
        {
            regex_()
        }
}

fn regex_<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    choice((
        attempt(
            (term(), byte(b'|'), regex()).map(|(l_re, _, r_re)| RegExpr::Either {
                l_re: Box::new(l_re),
                r_re: Box::new(r_re),
            }),
        ),
        term(),
    ))
}

fn term<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    many(factor()).map(|re_xs: Vec<RegExpr>| {
        if re_xs.len() == 1 {
            re_xs[0].clone()
        } else {
            RegExpr::Seq { re_xs }
        }
    })
}

fn factor<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    choice((
        attempt((atom(), byte(b'?'))).map(|(re, _)| RegExpr::Optional {
            opt_re: Box::new(re),
        }),
        attempt(repeated()),
        atom(),
    ))
}

const NON_ESCAPABLE_SYMBOLS: [u8; 14] = [
    b'&', b';', b':', b',', b'`', b'~', b'-', b'_', b'!', b'@', b'#', b'%', b'\'', b'\"',
];

fn atom<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    choice((
        byte(b'.').map(|_| RegExpr::AnyChar),
        attempt(byte(b'\\').with(parser::token::any())).map(|c| RegExpr::Char { c }),
        choice((
            byte::alpha_num(),
            parser::token::one_of(NON_ESCAPABLE_SYMBOLS),
        ))
        .map(|c| RegExpr::Char { c }),
        between(byte(b'['), byte(b']'), range()),
        between(byte(b'('), byte(b')'), regex()),
    ))
}

parser! {
    fn range[Input]()(Input) -> RegExpr
        where [Input: Stream<Token = u8>]
        {
            range_()
        }
}

fn range_<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    choice((
        byte(b'^').with(range()).map(|re| RegExpr::Not {
            not_re: Box::new(re),
        }),
        attempt(
            (byte::alpha_num(), byte(b'-'), byte::alpha_num())
                .map(|(from, _, to)| RegExpr::Between { from, to }),
        ),
        many1(byte::alpha_num()).map(|cs| RegExpr::Range { cs }),
    ))
}

fn repeated<Input>() -> impl Parser<Input, Output = RegExpr>
where
    Input: Stream<Token = u8>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    choice((
        attempt((atom(), choice((byte(b'*'), byte(b'+'))))).map(|(re, c)| RegExpr::Repeated {
            repeat_re: Box::new(re),
            at_least: if c == b'*' { None } else { Some(1) },
            at_most: None,
        }),
        attempt((
            atom(),
            between(byte(b'{'), byte(b'}'), many::<Vec<u8>, _, _>(byte::digit())),
        ))
        .map(|(re, repeat_digits)| {
            let repeat = parse_digits(&repeat_digits);
            RegExpr::Repeated {
                repeat_re: Box::new(re),
                at_least: Some(repeat),
                at_most: Some(repeat),
            }
        }),
        (
            atom(),
            between(
                byte(b'{'),
                byte(b'}'),
                (
                    many::<Vec<u8>, _, _>(byte::digit()),
                    byte(b','),
                    many::<Vec<u8>, _, _>(byte::digit()),
                ),
            ),
        )
            .map(
                |(re, (at_least_digits, _, at_most_digits))| RegExpr::Repeated {
                    repeat_re: Box::new(re),
                    at_least: if at_least_digits.is_empty() {
                        None
                    } else {
                        Some(parse_digits(&at_least_digits))
                    },
                    at_most: if at_most_digits.is_empty() {
                        None
                    } else {
                        Some(parse_digits(&at_most_digits))
                    },
                },
            ),
    ))
}

fn parse_digits(digits: &[u8]) -> usize {
    std::str::from_utf8(digits).unwrap().parse().unwrap()
}

#[cfg(test)]
mod tests {
    use crate::parser::{parse, RegExpr};
    use test_case::test_case;

    #[test_case("/h/", RegExpr::Char { c: b'h' }; "char")]
    #[test_case("/&/", RegExpr::Char { c: b'&' }; "not necessary to escape ampersand")]
    #[test_case("/;/", RegExpr::Char { c: b';' }; "not necessary to escape semicolon")]
    #[test_case("/:/", RegExpr::Char { c: b':' }; "not necessary to escape colon")]
    #[test_case("/,/", RegExpr::Char { c: b',' }; "not necessary to escape comma")]
    #[test_case("/`/", RegExpr::Char { c: b'`' }; "not necessary to escape backtick")]
    #[test_case("/~/", RegExpr::Char { c: b'~' }; "not necessary to escape tilde")]
    #[test_case("/-/", RegExpr::Char { c: b'-' }; "not necessary to escape minus")]
    #[test_case("/_/", RegExpr::Char { c: b'_' }; "not necessary to escape underscore")]
    #[test_case("/%/", RegExpr::Char { c: b'%' }; "not necessary to escape percentage")]
    #[test_case("/#/", RegExpr::Char { c: b'#' }; "not necessary to escape hashtag")]
    #[test_case("/@/", RegExpr::Char { c: b'@' }; "not necessary to escape at")]
    #[test_case("/!/", RegExpr::Char { c: b'!' }; "not necessary to escape exclamation")]
    #[test_case("/'/", RegExpr::Char { c: b'\'' }; "not necessary to escape single quote")]
    #[test_case("/\"/", RegExpr::Char { c: b'\"' }; "not necessary to escape double quote")]
    #[test_case("/\\h/", RegExpr::Char { c: b'h' }; "anything can be escaped")]
    #[test_case("/./", RegExpr::AnyChar; "any")]
    #[test_case("/abc/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Char { c: b'a' },
            RegExpr::Char { c: b'b' },
            RegExpr::Char { c: b'c' },
        ]};
        "abc")]
    #[test_case("/^abc/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Char { c: b'b' },
                RegExpr::Char { c: b'c' },
            ]},
        ]};
        "<sof>abc")]
    #[test_case("/abc$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Char { c: b'b' },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::Eof,
        ]};
        "abc<eof>")]
    #[test_case("/^abc$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Char { c: b'b' },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::Eof,
        ]};
        "<sof>abc<eof>")]
    #[test_case("/^ab?c$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Optional { opt_re: Box::new(RegExpr::Char { c: b'b' }) },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::Eof,
        ]};
        "<sof>ab<question>c<eof>")]
    #[test_case("/^ab*c$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Repeated {
                    repeat_re: Box::new(RegExpr::Char { c: b'b' }),
                    at_least: None,
                    at_most: None,
                },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::Eof,
        ]};
        "<sof>ab<star>c<eof>")]
    #[test_case("/^ab+c$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Repeated {
                    repeat_re: Box::new(RegExpr::Char { c: b'b' }),
                    at_least: Some(1),
                    at_most: None,
                },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::Eof,
        ]};
        "<sof>ab<plus>c<eof>")]
    #[test_case("/^ab{2}c$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Repeated {
                    repeat_re: Box::new(RegExpr::Char { c: b'b' }),
                    at_least: Some(2),
                    at_most: Some(2),
                },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::Eof,
        ]};
        "<sof>ab<twice>c<eof>")]
    #[test_case("/^ab{3,}c$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Repeated {
                    repeat_re: Box::new(RegExpr::Char { c: b'b' }),
                    at_least: Some(3),
                    at_most: None,
                },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::Eof,
        ]};
        "<sof>ab<atleast 3>c<eof>")]
    #[test_case("/^ab{2,4}c$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'a' },
                RegExpr::Repeated {
                    repeat_re: Box::new(RegExpr::Char { c: b'b' }),
                    at_least: Some(2),
                    at_most: Some(4),
                },
                RegExpr::Char { c: b'c' },
            ]},
            RegExpr::Eof,
        ]};
        "<sof>ab<between 2 and 4>c<eof>")]
    #[test_case("/^.$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::AnyChar,
            RegExpr::Eof,
        ]};
        "<sof><any><eof>")]
    #[test_case("/^[abc]$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Range { cs: vec![b'a', b'b', b'c'] },
            RegExpr::Eof,
        ]};
        "<sof><a or b or c><eof>")]
    #[test_case("/^[a-d]$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Between { from: b'a', to: b'd' },
            RegExpr::Eof,
        ]};
        "<sof><between a and d><eof>")]
    #[test_case("/^[^abc]$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Not { not_re: Box::new(RegExpr::Range { cs: vec![b'a', b'b', b'c'] })},
            RegExpr::Eof,
        ]};
        "<sof><not <a or b or c>><eof>")]
    #[test_case("/^[^a-d]$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Not { not_re: Box::new(RegExpr::Between { from: b'a', to: b'd' }) },
            RegExpr::Eof,
        ]};
        "<sof><not <between a and d>><eof>")]
    #[test_case("/^abc$/i",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Range { cs: vec![b'a', b'A'] },
                RegExpr::Range { cs: vec![b'b', b'B'] },
                RegExpr::Range { cs: vec![b'c', b'C'] },
            ]},
            RegExpr::Eof,
        ]};
        "<sof>abc<eof> (case insensitive)")]
    #[test_case("/^/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Seq { re_xs: vec![] }
        ]};
        "sof")]
    #[test_case("/$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Seq { re_xs: vec![] },
            RegExpr::Eof
        ]};
        "eof")]
    #[test_case("/a*/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Char { c: b'a' }),
            at_least: None,
            at_most: None,
        };
        "repeat unbounded (w/ *)")]
    #[test_case("/a+/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Char { c: b'a' }),
            at_least: Some(1),
            at_most: None,
        };
        "repeat bounded at least (w/ +)")]
    #[test_case("/a{104,}/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Char { c: b'a' }),
            at_least: Some(104),
            at_most: None,
        };
        "repeat bounded at least (w/ {x,}")]
    #[test_case("/a{,15}/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Char { c: b'a' }),
            at_least: None,
            at_most: Some(15),
        };
        "repeat bounded at most (w/ {,x}")]
    #[test_case("/a{12,15}/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Char { c: b'a' }),
            at_least: Some(12),
            at_most: Some(15),
        };
        "repeat bounded at least and at most (w/ {x,y}")]
    #[test_case("/(a|b)*/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Either {
                l_re: Box::new(RegExpr::Char { c: b'a' }),
                r_re: Box::new(RegExpr::Char { c: b'b' }),
            }),
            at_least: None,
            at_most: None,
        };
        "repeat complex unbounded")]
    #[test_case("/(a|b){3,7}/",
        RegExpr::Repeated {
            repeat_re: Box::new(RegExpr::Either {
                l_re: Box::new(RegExpr::Char { c: b'a' }),
                r_re: Box::new(RegExpr::Char { c: b'b' }),
            }),
            at_least: Some(3),
            at_most: Some(7),
        };
        "repeat complex bounded")]
    #[test_case("/^ab|cd/",
        RegExpr::Seq { re_xs: vec![
            RegExpr::Sof,
            RegExpr::Either {
                l_re: Box::new(RegExpr::Seq { re_xs: vec![
                    RegExpr::Char { c: b'a' },
                    RegExpr::Char { c: b'b' },
                ] }),
                r_re: Box::new(RegExpr::Seq { re_xs: vec![
                    RegExpr::Char { c: b'c' },
                    RegExpr::Char { c: b'd' },
                ]}),
            },
        ]};
        "Sof encapsulates full RHS")]
    #[test_case("/ab|cd$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Either {
                l_re: Box::new(RegExpr::Seq {re_xs: vec![
                    RegExpr::Char { c: b'a' },
                    RegExpr::Char { c: b'b' },
                ]}),
                r_re: Box::new(RegExpr::Seq {re_xs: vec![
                    RegExpr::Char { c: b'c' },
                    RegExpr::Char { c: b'd' },
                ]}),
            },
            RegExpr::Eof,
        ]};
        "Eof encapsulates full RHS" )]
    #[test_case("/^ab|cd$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Either {
                l_re: Box::new(RegExpr::Seq {re_xs: vec![
                    RegExpr::Char { c: b'a' },
                    RegExpr::Char { c: b'b' },
                ]}),
                r_re: Box::new(RegExpr::Seq {re_xs: vec![
                    RegExpr::Char { c: b'c' },
                    RegExpr::Char { c: b'd' },
                ]}),
            },
            RegExpr::Eof,
        ]};
        "Sof + Eof both encapsulate full center")]
    #[test_case("/\\^/",
        RegExpr::Char { c: b'^' };
        "escaping sof symbol")]
    #[test_case("/\\./",
        RegExpr::Char { c: b'.' };
        "escaping period symbol")]
    #[test_case("/\\*/",
        RegExpr::Char { c: b'*' };
        "escaping star symbol")]
    #[test_case("/^ca\\^b$/",
        RegExpr::Seq {re_xs: vec![
            RegExpr::Sof,
            RegExpr::Seq {re_xs: vec![
                RegExpr::Char { c: b'c' },
                RegExpr::Char { c: b'a' },
                RegExpr::Char { c: b'^' },
                RegExpr::Char { c: b'b' },
            ]},
            RegExpr::Eof,
        ]};
        "escaping, more realistic")]
    #[test_case("/8/",
        RegExpr::Char { c: b'8' };
        "able to match numbers")]
    #[test_case("/[7-9]/",
        RegExpr::Between { from: b'7', to: b'9' };
        "able to match a number range")]
    #[test_case("/[79]/",
        RegExpr::Range { cs: vec![b'7', b'9'] };
        "able to match a number range (part 2)")]
    fn test_parser(pattern: &str, exp: RegExpr) {
        match parse(pattern) {
            Ok(got) => assert_eq!(exp, got),
            Err(e) => panic!("got err: {}", e),
        }
    }
}
