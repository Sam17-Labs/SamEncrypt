use aes_gcm_siv::aead::generic_array::typenum::U12;
pub use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, OsRng};
pub use aes_gcm_siv::Aes256GcmSiv;
pub use aes_gcm_siv::Nonce;

use lazy_static::lazy_static;
use rand::seq::SliceRandom;

use std::fmt::{Display, Formatter};

pub type ByteVector = Vec<u8>;
pub const AUTHENTICATION_BYTES: usize = 16;
pub const NONCE_SIZE: u8 = 12;

/// Custom library error messages
#[derive(Debug, Clone, PartialEq)]
pub enum PREError {
    MessageCheckSumFailure(String),
    OverallCheckSumFailure(String),
    DefaultError(String),
    HashingError(String),
    ZeroScalarError(String),
    ScalarDeserializationError(String),
    PointDeserializationError(String),
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
                PREError::ZeroScalarError(msg) => format!("ZeroScalarError: {}", msg),
                PREError::ScalarDeserializationError(msg) =>
                    format!("ScalarDeserializationError: {}", msg),
                PREError::PointDeserializationError(msg) =>
                    format!("PointDeserializationError: {}", msg),
            }
        )
    }
}

lazy_static! {
    static ref ALLOWED_CHARS: Vec<char> = "abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&&*()"
        .chars()
        .collect();
}

/// Generates a random nonce of size `NONCE_SIZE`
/// By default, NONCE_SIZE is set to 12 bytes in compliance
/// with Aes256GcmSiv cypher.
///
/// # Returns a nonce string slice with a static lifetime.
pub fn generate_random_nonce() -> &'static str {
    let mut random_number_generator = rand::thread_rng();
    let mut nonce = String::from("");

    for _ in 0..NONCE_SIZE {
        nonce.push(
            ALLOWED_CHARS
                .choose(&mut random_number_generator)
                .map(|&c| c as char)
                .unwrap(),
        )
    }
    Box::leak(nonce.into_boxed_str())
}

/// Encrypts the given input symmetrically under the given key
/// The symmetric encryption uses the Advanced Encryption Standard(AES)
/// with GCM
///
/// # Arguments
///
/// * `nonce` - a 96 bit (12 bytes) nonce. This should be unique per message
///          in order to avoid unintended consequences with this cryptographic
///          primitive.
/// * `key` - a 256 bit (16 bytes) secret key
///
/// # Returns a ciphertext representation.
/// # Throws an aes_gcm_siv::Error if unable to encrypt.
pub async fn encrypt(
    input: &[u8],
    key: &[u8],
    nonce: Option<&GenericArray<u8, U12>>,
    _authenticate: bool,
) -> Result<ByteVector, aes_gcm_siv::Error> {
    let cipher = <Aes256GcmSiv as aes_gcm_siv::KeyInit>::new(key.into());

    match nonce {
        Some(nonce_value) => {
            let ciphertext = cipher.encrypt(nonce_value, input)?;
            Ok(ciphertext)
        }
        None => {
            let nonce_value = Nonce::from_slice(generate_random_nonce().as_bytes());
            let ciphertext = cipher.encrypt(nonce_value, input)?;
            Ok(ciphertext)
        }
    }
}

/// Decrypts a given ciphertext symmetrically under the given key
/// The symmetric encryption uses the Advanced Encryption Standard(AES)
/// with GCM
///
/// # Arguments
///
/// * `nonce` - a 96 bit (12 bytes) nonce. This should be unique per message
///          in order to avoid unintended consequences with this cryptographic
///          primitive.
/// * `key` - a 256 bit (16 bytes) secret key
///
/// # Returns a byte vector representation of the original text.
/// # Throws an aes_gcm_siv::Error if unable to decrypt.
pub async fn decrypt(
    ciphertext: &[u8],
    key: &[u8],
    nonce: Option<&GenericArray<u8, U12>>,
    _authenticate: bool,
) -> Result<ByteVector, aes_gcm_siv::Error> {
    let cipher = <Aes256GcmSiv as aes_gcm_siv::KeyInit>::new(key.into());

    match nonce {
        Some(nonce_value) => {
            let decrypted_message = cipher.decrypt(nonce_value, ciphertext).unwrap();
            Ok(decrypted_message)
        }
        None => {
            let nonce_value = Nonce::from_slice(generate_random_nonce().as_bytes());
            let decrypted_message = cipher.decrypt(nonce_value, ciphertext).unwrap();
            Ok(decrypted_message)
        }
    }
}

#[cfg(test)]
mod test {

    use futures::executor::block_on;

    use super::*;

    fn generate_sample_messages() -> Vec<(&'static str, &'static str)> {
        vec![
            ("this is top secret stuff!", generate_random_nonce()),
            (
                "this is some other top secret stuff!",
                generate_random_nonce(),
            ),
        ]
    }

    #[test]
    fn test_aes_256_symmetric_encryption() {
        let messages_to_encrypt = generate_sample_messages();

        let key = <Aes256GcmSiv as aes_gcm_siv::KeyInit>::generate_key(&mut OsRng);

        for (message, nonce) in messages_to_encrypt.into_iter() {
            let _nonce: &GenericArray<u8, U12> = Nonce::from_slice(nonce.as_bytes());

            let ciphertext: Result<ByteVector, aes_gcm_siv::Error> = block_on(encrypt(
                message.as_bytes(),
                key.as_slice(),
                Some(_nonce),
                false,
            ));

            let decrypted_message = block_on(decrypt(
                ciphertext.unwrap().as_slice(),
                key.as_slice(),
                Some(_nonce),
                false,
            ));

            assert_eq!(decrypted_message.unwrap().as_slice(), message.as_bytes())
        }
    }
}
