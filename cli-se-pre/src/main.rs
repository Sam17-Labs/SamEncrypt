mod cli;
use cli::SamEncryptAPIArgs;
use futures::executor::block_on;
use std::env;
use std::error::Error;
use std::fs::File;
use std::path::Path;

use clap::Parser;
use cli::ActionType::{
    GenerateReEncryptionKey, Init, ReDecrypt, ReEncrypt, SelfDecrypt, SelfEncrypt,
};
use sam_encrypt::{
    core::EncryptedMessage, core::PREState, core::ReEncryptedMessage, core::ReEncryptionKey,
    elliptic_curve,
};

fn main() -> Result<(), Box<dyn Error>> {
    let current_directory = env::current_dir()
        .unwrap()
        .into_os_string()
        .into_string()
        .unwrap();

    std::fs::create_dir_all(format!("{}/pre_state", &current_directory[..]))?;

    // parse command line arguments
    let args = SamEncryptAPIArgs::parse();

    // initialize the protocol
    let curve = elliptic_curve::Curve::new();
    let pre_state = PREState::new(curve);

    match args.action {
        Init(init_command) => {
            let pre_state_init_file = File::create("pre_state/init.cbor")?;

            serde_cbor::to_writer(pre_state_init_file, &init_command)?;
        }
        SelfEncrypt(command) => {
            let file_path = command.file_path;

            println!("self encrypting file...");
            println!("file path={:?}", file_path);

            let file_contents =
                std::fs::read_to_string(Path::new(&file_path[..])).expect("Failed to read file");

            let encrypted_file: EncryptedMessage = block_on(pre_state.self_encrypt(
                file_contents.as_bytes().to_vec(),
                String::from("dummy tag").into_bytes(),
            ))
            .expect("Failed to self encrypt file");

            // Serialize the ciphertext to disk
            let ciphertext_file_pathh = File::create("pre_state/ciphertext.cbor")?;

            serde_cbor::to_writer(ciphertext_file_pathh, &encrypted_file)?;
        }
        SelfDecrypt(_command) => {

            // let file_path = command.file_path;
            // load up encrypted file
            // let ciphertext = File::open(&file_path[..])?;

            // let encrypted_file: EncryptedMessage = serde_cbor::from_reader(ciphertext)?;

            // let decrypted_file: ByteVector =
            //     block_on(pre_state.self_decrypt(encrypted_file)).expect("failed to decrypt file");
        }
        GenerateReEncryptionKey(command) => {
            let file_path = command.file_path;
            let tag = match command.tag {
                Some(t) => t,
                None => String::from(""),
            };
            let public_key = pre_state.public_key.to_bytes();

            let re_encryption_key: ReEncryptionKey = pre_state
                .generate_re_encryption_key(&public_key, tag.into_bytes())
                .unwrap();

            // serialize re-encryption key to disk
            let re_key_file = File::create(file_path)?;
            serde_cbor::to_writer(re_key_file, &re_encryption_key)?;
        }
        ReEncrypt(command) => {
            let ciphertext_path = command.ciphertext_path;
            let new_ciphertext_path = match command.new_ciphertext_path {
                Some(path) => path,
                None => String::from("/pre_state/new_ciphertext_path.cbor"),
            };

            let re_key_path = match command.re_key_path {
                Some(path) => path,
                None => String::from("/pre_state/re_key.cbor"),
            };

            // load encrypted file
            let encrypted_file: EncryptedMessage = serde_cbor::from_reader(ciphertext_path)?;

            // load a serialized re-encryption key
            let re_key: ReEncryptionKey = serde_cbor::from_reader(re_key_path)?;

            // re-encrypt ciphertext

            let public_key = pre_state.public_key.to_bytes();
            let re_encrypted_file: ReEncryptedMessage = pre_state
                .re_encrypt(&public_key, encrypted_file, re_key, &curve)
                .expect("failed to re-encrypt test file");
        }
        ReDecrypt(_f) => println!(""),
    }

    Ok(())
}
