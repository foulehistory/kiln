//! `kiln-image`: content-addressed image format, Kilnfile builder, and OCI
//! registry client.

pub mod build;
pub mod error;
pub mod identity;
pub mod image;
pub mod kilnfile;
pub mod layer;
pub mod registry;
pub mod scan;
pub mod secrets;
pub mod signing;
pub mod store;

pub use error::{Error, Result};
