//! Session layer: codec, identity, `Hello` bootstrap, signed frame chain, coin flip, driver.
//! Security-critical reference implementation; not independently audited.

#![forbid(unsafe_code)]

pub mod codec;
pub mod coin;
pub mod frame;
pub mod hello;
pub mod identity;
pub mod state;
pub mod verify;
