// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
// UNSAFETY: Manual pointer manipulation and transmutes to/from atomic types.
#![expect(unsafe_code)]
#![allow(clippy::undocumented_unsafe_blocks)]

pub mod shared;
