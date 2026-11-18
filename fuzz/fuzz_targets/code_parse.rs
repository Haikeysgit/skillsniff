#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    skillsniff::fuzzing::fuzz_code_parse(data);
});
