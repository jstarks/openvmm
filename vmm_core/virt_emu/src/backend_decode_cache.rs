// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test-only uncached comparison seam; production uses Strudel's cache directly.
pub use x86_decode::cache::DecodeDiagnostics;
use x86_system::execute::decode::{DecodeDecision, DecodeInput, DecodeWindow};

#[derive(Default)]
pub(super) struct DecodeCache {
    cache: x86_decode::cache::DecodeCache,
    pub(super) bypass: bool,
}

impl DecodeCache {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn diagnostics(&self) -> DecodeDiagnostics {
        self.cache.diagnostics()
    }

    pub(super) fn decode(&mut self, input: DecodeInput) -> DecodeDecision {
        if self.bypass {
            x86_decode::admit(input)
        } else {
            self.cache.decode(input)
        }
    }

    pub(super) fn decode_window(&mut self, window: DecodeWindow) -> (u8, DecodeDecision) {
        if !self.bypass {
            return self.cache.decode_window(window);
        }
        for length in window.input.length..=window.available {
            let decision = x86_decode::admit(DecodeInput {
                bytes: window.bytes,
                length,
                ..window.input
            });
            if !matches!(decision, DecodeDecision::More) {
                return (length, decision);
            }
        }
        (window.available, DecodeDecision::More)
    }
}
