# SamEncrypt

[![](https://img.shields.io/crates/v/sam_encrypt.svg)](https://crates.io/crates/sam_encrypt) [![](https://docs.rs/sam_encrypt/badge.svg)](https://docs.rs/sam_encrypt) 

Rust implementation of the proxy self re-encryption protocol. This implementation is based on the original paper by Selvi et al. entitle [Sharing of Encrypted file in Blockchain Made Simpler](https://eprint.iacr.org/2019/418.pdf)


## What is Proxy Self Re-Encryption
Proxy self re-encryption builds on the existing proxy re-encryption (PRE) scheme, now a household name in the cryptography literature. On a high level, PRE is a cryptographic primitive that allows users to share data by re-encrypting ciphertexts towards authorized users via a semi-trusted proxy such that the proxies don't get hold of the underlying messages. 

The Proxy self re-encryption schemes adds a novel self-encryption scheme that is more efficient than the standard CPA secure [El Gamal encryption scheme](https://en.wikipedia.org/wiki/ElGamal_encryption).


## High-Level Design 
This crate relies on elliptic curve cryptography to implement the key exchange protocol. In particular, the curve of choice is the [Edwards 25519](https://docs.rs/curv-kzen/0.8.0/curv/elliptic/curves/enum.Ed25519.html). 
We provide `ECPoint` and `ECScalar` structs, which are wrappers around `Point<Ed25519>` and `Scalar<25519>` respectively. 

Currently, the implemented cryptographic primitives are provided as part of a stateful encryption-decryption pipeline. This state is controlled via the implementation of `core::PREState`. This means that a single user can use the available primitives to self-encrypt/self-decrypt files, generate re-encryption keys, and re-encrypt/re-decrypt files. Although all of these functionalities are currently available as part of a single state, they are robust enough that a user shouldn't have trouble, for instance, using them to implement an access control layer on top of an existing application. 


# Example Usage 
## Self-Encrypting Files
You can self-encrypt files as follows:
```
use sam_encrypt::{core::EncryptedMessage, core::PREState};
use sam_encrypt::elliptic_curve::Curve;
use std::fs::File;
use std::path::Path;
use std::error::Error;
use futures::executor::block_on;

fn self_encrypt_file() -> Result<(), Box<dyn Error>> {
    // By default uses the Ed25519 elliptic curve
    let curve = Curve::new();
    let pre_state = PREState::new(curve);
    let file_content = std::fs::read_to_string(Path::new("/file/path"))
                                    .expect("Failed to read file");
    let encrypted_file = block_on(pre_state.self_encrypt(
            file_content.as_bytes().to_vec(), 
            String::from("tag").into_bytes(),
            ))
            .expect("Failed to self-encrypt the given file");

    let ciphertext = File::create("encrypted_file.cbor")?;
    serde_cbor::to_writer(ciphertext, &encrypted_file)?;

    Ok(())
}
```

## Generating a Re-Encryption Key 
A re-encryption key is generated using a user's public key and an optional tag. 

```
use sam_encrypt::{core::ReEncryptionKey, core::PREState}
use sam_encrypt::elliptic_curve::Curve;
use std::error::Error;

fn get_re_encryption_keys() -> Result<(), Box<dyn Error>> {
    let curve = Curve::new();
    let pre_state = PREState::new(curve);
    
    let public_key = pre_state.public_key.to_bytes();
    let re_encryption_key = pre_state
          .generate_re_encryption_key(&public_key, String::from("tag").into_bytes())
          .unwrap();

    Ok(())
}
```

## Re-Encrypt Files 
A proxy can re-encrypt an already encrypted file as follows:

```
use sam_encrypt::{core::{EncryptedMessage, ReEncryptionKey, ReEncryptedMessage, PREState},
use sam_encrypt::elliptic_curve::Curve;
use std::error::Error;
use std::fs::File;

fn re_encrypt_file() -> Result<(), Box<dyn Error>> {

    let curve = Curve::new();
    let pre_state = PREState::new(curve.clone());
    let ciphertext_file_path = String::from("/file/path");
    let re_key_path = String::from("/re_encryption_key/path");

    // load up a serialized encrypted file
    let encrypted_file = serde_cbor::from_reader(File::open(ciphertext_file_path)?)?;
     
    // load up a serialized re-encryption key
    let re_key = serde_cbor::from_reader(File::open(re_key_path)?)?;
    let public_key = pre_state.public_key.to_bytes();
    let re_encrypted_file = pre_state
         .re_encrypt(&public_key, encrypted_file, re_key, &curve)
         .expect("failed to re-encrypt the input file");

    serde_cbor::to_writer(File::create(String::from("/re_encrypted_file/path"))?, &re_encrypted_file)?;
    Ok(())
}
```

## For Contributors
You will need a stable version of Rust. Nightly is not supported. 
```
$ cargo build
$ cargo test 
```

Library end-to-end benchmarks are currently in development. 

## Security
If you encounter any issues or difficulties using this library, please don't hesitate to contact the authors: [Blaise Muhirwa](blaise@sam17.co) and [Roberto Berwa](berwa@sam17.co)

## License
same_encrypt is licensed under the Apache 2.0 license. 


Copyright (c) 2022-present Sam17.co
All rights reserved.