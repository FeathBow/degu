pub fn strip_sgr(input: &[u8]) -> Vec<u8> {
    let mut stripped = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'\x1b' && input.get(index + 1) == Some(&b'[') {
            let mut end = index + 2;
            while end < input.len() && input[end] != b'm' {
                end += 1;
            }
            if end < input.len() {
                index = end + 1;
                continue;
            }
        }
        stripped.push(input[index]);
        index += 1;
    }
    stripped
}
