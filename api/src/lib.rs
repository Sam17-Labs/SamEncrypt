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

pub fn encrypt(
    input: ByteVector,
    key: ByteVector,
    nonce: Option<ByteVector>,
    authenticate: bool,
) -> Result<ByteVector, PREError> {
    let allocation_size = if authenticate { 12 } else { 16 };
    let mut iv = if nonce.is_some() {
        nonce.unwrap()
    } else {
        Vec::with_capacity(allocation_size)
    };

    let algorithm = if authenticate {
        "aes-256-gcm"
    } else {
        "aes-256-ctr"
    };

    

    Ok(vec![])
}
