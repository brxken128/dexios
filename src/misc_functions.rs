pub fn strip_newline(input: &str) -> &str {
    input
        .strip_suffix("\n")
        .unwrap()
}