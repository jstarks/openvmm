// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Implementation of mesh port and node communication model.

#![no_std]
#![warn(clippy::std_instead_of_core)]
#![warn(clippy::std_instead_of_alloc)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod common;
pub mod local_node;
pub mod message;
pub mod resource;

#[cfg(feature = "std")]
use xrc::arc as rc;
#[cfg(not(feature = "std"))]
use xrc::rc;
