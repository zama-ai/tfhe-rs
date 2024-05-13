#[test]
fn tests() {
    let t = trybuild::TestCases::new();
    t.pass("tests/testcases/unit.rs");
    t.pass("tests/testcases/struct.rs");
    t.pass("tests/testcases/enum.rs");
}
