


use clap::{
    Args, 
    Parser, 
    Subcommand
};


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

#[derive(Debug, Args)]
pub struct InitCommand;

#[derive(Debug, Args)]
pub struct SelfEncryptCommand;

#[derive(Debug, Args)]
pub struct SelfDecryptCommand;

#[derive(Debug, Args)]
pub struct ReKeyGenCommand;

#[derive(Debug, Args)]
pub struct ReEncryptCommand;

#[derive(Debug, Args)]
pub struct ReDecryptCommand;