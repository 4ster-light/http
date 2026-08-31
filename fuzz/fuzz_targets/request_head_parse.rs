//! Fuzz target for the HTTP request parser (SEC controls SEC-HTTP-001/003/004).
//!
//! Invariants under arbitrary bytes: no panic, no unbounded allocation, no
//! hang. Every outcome must be a `Result` (complete request, incomplete, or
//! a typed parse error).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = http::limits::Limits::default();
    match http::request::HttpRequest::parse(data, &limits) {
        Ok(Some((_request, consumed))) => {
            assert!(
                consumed <= data.len(),
                "parser consumed more bytes than provided"
            );
        }
        Ok(None) | Err(_) => {}
    }
});
