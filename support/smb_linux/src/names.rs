// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use smb::spec::Status;
use std::ffi::CString;

fn needs_escape(c: char) -> bool {
    c < '\u{20}' || matches!(c, '"' | '*' | ':' | '<' | '>' | '?' | '\\' | '|')
}

pub(crate) fn project(name: &str) -> String {
    name.chars()
        .map(|c| {
            if needs_escape(c) {
                char::from_u32(0xf000 + u32::from(c)).expect("escaped ASCII is a valid codepoint")
            } else {
                c
            }
        })
        .collect()
}

pub(crate) fn component(name: &str) -> Result<CString, Status> {
    if name.is_empty() || name.chars().any(|c| needs_escape(c) || c == '/') {
        return Err(Status::OBJECT_NAME_INVALID);
    }
    let decoded: String = name
        .chars()
        .map(|c| {
            let value = u32::from(c);
            if (0xf000..=0xf0ff).contains(&value) {
                let ascii = char::from_u32(value - 0xf000).expect("ASCII projection");
                if needs_escape(ascii) {
                    return ascii;
                }
            }
            c
        })
        .collect();
    CString::new(decoded).map_err(|_| Status::OBJECT_NAME_INVALID)
}

pub(crate) fn target(target: &str) -> String {
    target
        .split('/')
        .map(project)
        .collect::<Vec<_>>()
        .join("\\")
}
