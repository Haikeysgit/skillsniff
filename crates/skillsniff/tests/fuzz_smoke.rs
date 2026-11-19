//! Runs the fuzz entry points on hostile and degenerate inputs so they are
//! checked on every platform without a fuzzer.

use skillsniff::fuzzing::{fuzz_archive, fuzz_code_parse, fuzz_frontmatter, fuzz_review};

fn samples() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0xff; 64],
        b"---\n".to_vec(),
        b"---\r\nname: a\r\n".to_vec(),
        b"\xef\xbb\xbf---\nname: [unclosed\n---\n".to_vec(),
        b"---\nname: &a [*a]\n---\n".to_vec(),
        b"{}".to_vec(),
        b"{\"schema_version\":\"1\",\"additions\":[{}],\"raises\":[null]}".to_vec(),
        b"PK\x03\x04\x00\x00".to_vec(),
        b"\x1f\x8b\x08\x00garbage".to_vec(),
        b"((((((((((((((((((((((((((((((((((((".to_vec(),
        b"\"\"\"$(`${{{{[[[[".to_vec(),
    ];
    v.push((0..=255u8).collect());
    v.push(b"(".repeat(5000));
    v
}

#[test]
fn entry_points_survive_degenerate_inputs() {
    for s in samples() {
        for kind in 0..5u8 {
            let mut tagged = vec![kind];
            tagged.extend_from_slice(&s);
            fuzz_archive(&tagged);
            fuzz_code_parse(&tagged);
        }
        fuzz_frontmatter(&s);
        fuzz_review(&s);
    }
}
