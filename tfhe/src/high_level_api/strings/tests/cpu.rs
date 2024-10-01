use crate::high_level_api::tests::setup_default_cpu;

#[test]
fn test_string_eq_ne() {
    let cks = setup_default_cpu();
    super::test_string_eq_ne(&cks);
}

#[test]
fn test_string_find_rfind() {
    let cks = setup_default_cpu();
    super::test_string_find_rfind(&cks);
}

#[test]
fn test_string_len_is_empty() {
    let cks = setup_default_cpu();
    super::test_string_len_is_empty(&cks);
}

#[test]
fn test_string_lower_upper() {
    let cks = setup_default_cpu();
    super::test_string_lower_upper(&cks);
}

#[test]
fn test_string_trim() {
    let cks = setup_default_cpu();
    super::test_string_trim(&cks);
}

#[test]
fn test_string_strip() {
    let cks = setup_default_cpu();
    super::test_string_strip(&cks);
}
