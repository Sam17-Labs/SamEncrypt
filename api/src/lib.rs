pub mod core;
pub mod curve;
pub mod hashing;
pub mod test_utils;

use std::fmt::{Display, Formatter, Result};

pub type ByteVector = Vec<u8>;

/// Custom library error messages
#[derive(Debug, Clone, PartialEq)]
pub enum PREError {
    MessageCheckSumFailure(String),
    OverallCheckSumFailure(String),
    DefaultError(String),
    HashingError(String),
}

impl Display for PREError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "{}",
            match self {
                PREError::MessageCheckSumFailure(msg) => format!("MessageCheckSumFailure: {}", msg),
                PREError::OverallCheckSumFailure(msg) => format!("OverallCheckSumFailure: {}", msg),
                PREError::DefaultError(msg) => format!("PREError: {}", msg),
                PREError::HashingError(msg) => format!("HashingError: {}", msg),
            }
        )
    }
}
