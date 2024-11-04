mod test_common;
mod test_concat;
mod test_contains;
mod test_find_replace;
mod test_split;
mod test_up_low_case;
mod test_whitespace;

use std::time::Duration;

fn result_message<T>(str: &str, expected: T, dec: T, dur: Duration)
where
    T: std::fmt::Debug,
{
    println!(
        "\x1b[1;32m--------------------------------\x1b[0m\n\
        \x1b[1;32;1mString: \x1b[0m\x1b[0;33m{str:?}\x1b[0m\n\
        \x1b[1;32;1mClear API Result: \x1b[0m{expected:?}\n\
        \x1b[1;32;1mT-fhe API Result: \x1b[0m{dec:?}\n\
        \x1b[1;34mExecution Time: \x1b[0m{dur:?}\n\
        \x1b[1;32m--------------------------------\x1b[0m",
    );
}

fn result_message_pat<T>(str: &str, pat: &str, expected: T, dec: T, dur: Duration)
where
    T: std::fmt::Debug,
{
    println!(
        "\x1b[1;32m--------------------------------\x1b[0m\n\
        \x1b[1;32;1mString: \x1b[0m\x1b[0;33m{str:?}\x1b[0m\n\
        \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m{pat:?}\x1b[0m\n\
        \x1b[1;32;1mClear API Result: \x1b[0m{expected:?}\n\
        \x1b[1;32;1mT-fhe API Result: \x1b[0m{dec:?}\n\
        \x1b[1;34mExecution Time: \x1b[0m{dur:?}\n\
        \x1b[1;32m--------------------------------\x1b[0m",
    );
}

fn result_message_clear_pat<T>(str: &str, pat: &str, expected: T, dec: T, dur: Duration)
where
    T: std::fmt::Debug,
{
    println!(
        "\x1b[1;32m--------------------------------\x1b[0m\n\
        \x1b[1;32;1mString: \x1b[0m\x1b[0;33m{str:?}\x1b[0m\n\
        \x1b[1;32;1mPattern (clear): \x1b[0m\x1b[0;33m{pat:?}\x1b[0m\n\
        \x1b[1;32;1mClear API Result: \x1b[0m{expected:?}\n\
        \x1b[1;32;1mT-fhe API Result: \x1b[0m{dec:?}\n\
        \x1b[1;34mExecution Time: \x1b[0m{dur:?}\n\
        \x1b[1;32m--------------------------------\x1b[0m",
    );
}

fn result_message_rhs<T>(str: &str, pat: &str, expected: T, dec: T, dur: Duration)
where
    T: std::fmt::Debug,
{
    println!(
        "\x1b[1;32m--------------------------------\x1b[0m\n\
        \x1b[1;32;1mLhs: \x1b[0m\x1b[0;33m{str:?}\x1b[0m\n\
        \x1b[1;32;1mRhs: \x1b[0m\x1b[0;33m{pat:?}\x1b[0m\n\
        \x1b[1;32;1mClear API Result: \x1b[0m{expected:?}\n\
        \x1b[1;32;1mT-fhe API Result: \x1b[0m{dec:?}\n\
        \x1b[1;34mExecution Time: \x1b[0m{dur:?}\n\
        \x1b[1;32m--------------------------------\x1b[0m",
    );
}

fn result_message_clear_rhs<T>(str: &str, pat: &str, expected: T, dec: T, dur: Duration)
where
    T: std::fmt::Debug,
{
    println!(
        "\x1b[1;32m--------------------------------\x1b[0m\n\
        \x1b[1;32;1mLhs: \x1b[0m\x1b[0;33m{str:?}\x1b[0m\n\
        \x1b[1;32;1mRhs (clear): \x1b[0m\x1b[0;33m{pat:?}\x1b[0m\n\
        \x1b[1;32;1mClear API Result: \x1b[0m{expected:?}\n\
        \x1b[1;32;1mT-fhe API Result: \x1b[0m{dec:?}\n\
        \x1b[1;34mExecution Time: \x1b[0m{dur:?}\n\
        \x1b[1;32m--------------------------------\x1b[0m",
    );
}
