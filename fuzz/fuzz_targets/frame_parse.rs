//! Fuzz target for the WebSocket frame parser (SEC-WS-002/003/004/006).
//!
//! Invariants under arbitrary bytes: no panic, no unbounded allocation, no
//! hang, and the declared-length arithmetic stays sound (oversized frames
//! are rejected before payload buffering).

#![no_main]

use libfuzzer_sys::fuzz_target;
use websocket::limits::Limits;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();
    match websocket::frame::Frame::parse(data, &limits) {
        Ok((_frame, consumed)) => {
            assert!(
                consumed <= data.len(),
                "parser consumed more bytes than provided"
            );
        }
        Err(_) => {}
    }
});
