pub mod core;
pub mod elliptic_curve;
pub mod hashing;
pub mod test_utils;

pub use cipher;

use std::fmt::{Display, Formatter};

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
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
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
    _input: ByteVector,
    _key: ByteVector,
    nonce: Option<ByteVector>,
    authenticate: bool,
) -> Result<ByteVector, PREError> {
    let allocation_size = if authenticate { 12 } else { 16 };
    let _iv = if nonce.is_some() {
        nonce.unwrap()
    } else {
        Vec::with_capacity(allocation_size)
    };

    let _algorithm = if authenticate {
        "aes-256-gcm"
    } else {
        "aes-256-ctr"
    };


    



    Ok(vec![])
}
