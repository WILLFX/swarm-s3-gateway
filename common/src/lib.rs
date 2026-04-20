#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
pub mod error;

pub mod ids;
pub mod types;

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub mod error;

pub mod ids;
pub mod types;
