use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

// In the help system, output author, version and
// program description
#[derive(Debug, Parser)]
#[clap(author, version, about)]
pub struct SamEncryptAPIArgs {
    #[clap(subcommand)]
    pub action: ActionType,
}

#[derive(Debug, Subcommand)]
pub enum ActionType {
    /// Initializes the state of a Proxy Self Re-Encryption Protocol
    Init(InitCommand),

    /// Self-Encrypt any file locally.
    SelfEncrypt(SelfEncryptCommand),

    /// Self-Decrypt any self-encrypted file
    SelfDecrypt(SelfDecryptCommand),

    /// Generate a re-encryption key
    GenerateReEncryptionKey(ReKeyGenCommand),

    /// Re-encrypt an encrypted file under a generated re-encryption key
    ReEncrypt(ReEncryptCommand),

    /// Decrypt a re-encrypted file
    ReDecrypt(ReDecryptCommand),
}

#[derive(Debug, Args, Serialize, Deserialize)]
pub struct InitCommand {
    /// The name of the user
    pub name: String,
}

#[derive(Debug, Args)]
pub struct SelfEncryptCommand {
    /// File path (pointer to the file to be self-encrypted)
    pub file_path: String,
}

#[derive(Debug, Args)]
pub struct SelfDecryptCommand {
    /// File path (pointer to the encrypted file on disk)
    pub file_path: String,
}

#[derive(Debug, Args)]
pub struct ReKeyGenCommand {
    /// Optional file path for where to serialize a re-encryption
    /// key. If not provided, the re-encryption key is serialized
    /// to a file named .env in the current working directory.
    pub file_path: String,

    /// Optional tag for generating the re-encryption key.
    /// If not supplied, an empty string is passed as tag
    pub tag: Option<String>,
}

#[derive(Debug, Args)]
pub struct ReEncryptCommand {
    /// File path to the ciphertext generated via a self-encryption
    /// protocol.
    pub ciphertext_path: String,

    /// Optional file_path for where to serialize the new
    /// cipher text re-encrypted under a re-encryption key.
    pub new_ciphertext_path: Option<String>,

    /// File path to the serialized re-encryption key.
    /// If not supplied, the default will be .env file in the current
    /// working directory. Re-encryption fails if file path does not
    /// exist.
    pub re_key_path: Option<String>,
}

#[derive(Debug, Args)]
pub struct ReDecryptCommand {
    /// File path to the re-encrypted file
    pub file_path: String,
}
