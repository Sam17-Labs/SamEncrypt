pub mod core;
pub mod curve;
pub mod sha256;

use std::fmt::{Display, Formatter, Result};

pub type ByteVector = Vec<u8>;

/// Custom library error messages
pub enum PREError {
    MessageCheckSumFailure(String),
    OverallCheckSumFailire(String),
}

impl Display for PREError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "{}",
            match self {
                PREError::MessageCheckSumFailure(msg) => format!("MessageCheckSumFailure: {}", msg),
                PREError::OverallCheckSumFailire(msg) => format!("OverallCheckSumFailure: {}", msg),
            }
        )
    }
}
