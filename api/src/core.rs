use crate::elliptic_curve::{Curve, ECOp, ECPoint, ECScalar};
use crate::internals::Nonce;
use crate::internals::{decrypt, encrypt, generate_random_nonce, ByteVector, PREError};
use sha2::{Sha256, Sha512};

// use crate::decrypt;
// use crate::encrypt;
use crate::hashing::hash_input;

#[derive(Debug, Clone)]
pub(crate) struct ReEncryptionKey {
    r1: ByteVector,
    r2: ByteVector,
    r3: ByteVector,
}

#[derive(Debug, Clone)]
pub(crate) struct EncryptedMessage {
    tag: ByteVector,
    encrypted_key: ByteVector,
    message_check_sum: ByteVector,
    overall_check_sum: ByteVector,
    data: ByteVector,
}

//TODO: come up with descriptive field names. Haven't done it now because
// I'm not yet exactly sure what these vectors represent
#[allow(dead_code)]
pub(crate) struct ReEncryptedMessage {
    d1: ByteVector,
    d2: ByteVector,
    d3: ByteVector,
    d4: ByteVector,
    d5: ByteVector,
}

#[allow(dead_code)]
pub(crate) struct PREState {
    curve: Curve,
    private_key: ECScalar,
    public_key: ECPoint,
}

impl PREState {
    /// PREState constructor.
    ///
    /// # Arguments
    ///
    /// * `curve` - The specific elliptic curve required to generate public keys
    ///             By default, the protocol utilizes the EC25519 curve.
    #[allow(dead_code)]
    pub fn new(curve: Curve) -> Self {
        let private_key = Curve::get_random_scalar();
        let public_key = curve.base_point.multiply(&private_key);

        PREState {
            curve,
            private_key,
            public_key,
        }
    }

    /// Handles the generation of a re-encryption key.
    /// The re-encryption key is generated to translate a cyphertext of the first
    /// user to a cyphertext of the second user.
    ///
    /// # Arguments
    ///
    /// * `public_key` - A bytevector representing the public key of the first user
    /// * `tag` - A bytevector representing a certain short message associated with
    ///           the re-encryption key
    #[allow(dead_code)]
    fn generate_re_encryption_key(
        &self,
        pub_k: &ByteVector,
        tag: ByteVector,
    ) -> Result<ReEncryptionKey, PREError> {
        let public_key = self.curve.get_point_from_bytes(pub_k)?;
        let private_key = self.private_key.to_bytes();
        let random_scalar = Curve::get_random_scalar();

        let hash_output = hash_input::<Sha256, 32>(vec![tag.clone(), private_key.clone()])
            .expect("unable to hash (tag, private key) pair");

        let h = self.curve.get_scalar_from_bytes(&hash_output.to_vec())?;

        let factor = random_scalar.eval(Some(h), ECOp::Subtract).unwrap();
        Ok(ReEncryptionKey {
            r1: self.curve.base_point.multiply(&factor).to_bytes(),
            r2: public_key.multiply(&random_scalar).to_bytes(),
            r3: self
                .curve
                .get_scalar_from_hash(&vec![tag.clone(), private_key])
                .unwrap()
                .to_bytes(),
        })
    }

    /// Symmetric encryption protocol.
    /// By default, we use the AES(Advanced Encryption Stantard) encryption.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to encrypt symmetrically
    /// * `key_hash` - The hash value of the secret key with which to encrypt
    ///
    /// # Returns a byte vector representing the encryption of data under the given secret key
    ///
    /// TODO(blaise): Figure out what the authenticate boolean variable means.

    #[allow(dead_code)]
    async fn encrypt_symmetric(&self, data: &ByteVector, key_hash: &ByteVector) -> ByteVector {
        let key: &[u8] = &key_hash[0..32];
        let nonce: &str = generate_random_nonce();

        let cipher_text: ByteVector =
            encrypt(data, key, Some(Nonce::from_slice(nonce.as_bytes())), false)
                .await
                .unwrap();

        cipher_text
    }

    /// Decrypt symmetrically
    ///
    /// # Arguments
    ///
    /// * `data` - The data to encrypt symmetrically
    /// * `key_hash` - The hash value of the secret key with which to encrypt
    ///
    /// # Returns a byte vector representing the decrypted ciphertext under the given secret key
    ///
    #[allow(dead_code)]
    async fn decrypt_symmetric(
        &self,
        ciphertext: &ByteVector,
        key_hash: &ByteVector,
    ) -> ByteVector {
        let key: &[u8] = &key_hash[0..32];
        let nonce: &str = generate_random_nonce();

        let original_plain_text: ByteVector = decrypt(
            ciphertext,
            key,
            Some(Nonce::from_slice(nonce.as_bytes())),
            false,
        )
        .await
        .unwrap();

        original_plain_text
    }

    /// Handles the self-encryption of the original message
    ///
    /// # Arguments
    ///
    /// * `message` - A bytevector representing the original message to be
    ///     self-encrypted.
    /// * `tag` - A bytevector representing the tag with which to self-encrypt
    ///     the message.
    #[allow(dead_code)]
    async fn self_encrypt(
        &self,
        message: ByteVector,
        tag: ByteVector,
    ) -> Result<EncryptedMessage, PREError> {
        // TODO: Remove clones as much as possible by using references where
        // necessary
        let random_scalar: ECScalar = Curve::get_random_scalar();
        let public_key: ECPoint = self.curve.base_point.multiply(&random_scalar);

        // hash 1
        let private_key_vector: Vec<u8> = self.private_key.to_bytes();
        let tag_private_key_hash: [u8; 32] =
            hash_input::<Sha256, 32>(vec![tag.clone(), private_key_vector.clone()])?;

        let scalar_tag_private_key: ECScalar = self
            .curve
            .get_scalar_from_bytes(&(tag_private_key_hash.to_vec()))?;

        let hg: ECPoint = self.curve.base_point.multiply(&scalar_tag_private_key);

        let encrypted_key: Vec<u8> = public_key.eval(&hg, ECOp::Add).unwrap().to_bytes();

        // encrypt msg using key
        let symmetric_encryption_key: [u8; 64] =
            hash_input::<Sha512, 64>(vec![public_key.to_bytes()])?;

        let data: Vec<u8> = self
            .encrypt_symmetric(&message, &symmetric_encryption_key.to_vec())
            .await;

        let message_check_sum: [u8; 64] =
            hash_input::<Sha512, 64>(vec![message, public_key.to_bytes()]).unwrap();

        let alp: Vec<u8> = self
            .curve
            .get_scalar_from_hash(&vec![tag.clone(), self.private_key.to_bytes()])
            .unwrap()
            .to_bytes();

        let overall_check_sum: [u8; 64] = hash_input::<Sha512, 64>(vec![
            encrypted_key.clone(),
            data.clone(),
            message_check_sum.to_vec(),
            alp,
        ])?;

        Ok(EncryptedMessage {
            tag,
            encrypted_key,
            message_check_sum: message_check_sum.to_vec(),
            overall_check_sum: overall_check_sum.to_vec(),
            data,
        })
    }

    /// Handles the self-decryption of the original ciphertext.
    /// Decrypts the files previously encrypted by the user using
    /// the user's private key.
    ///
    /// # Arguments
    ///
    /// * `encrypted_message` - EncryptedMessage representing the ciphertext to be
    ///     self-decrypted.
    #[allow(dead_code)]
    pub async fn self_decrypt(
        &self,
        encrypted_message: EncryptedMessage,
    ) -> Result<ByteVector, PREError> {
        // TODO: Remove clones as much as possible by using references where
        // necessary
        let private_key: Vec<u8> = self.private_key.to_bytes();
        let alp: Vec<u8> = self
            .curve
            .get_scalar_from_hash(&vec![encrypted_message.tag.clone(), private_key.clone()])?
            .to_bytes();

        let first_check: [u8; 64] = hash_input::<Sha512, 64>(vec![
            encrypted_message.encrypted_key.clone(),
            encrypted_message.data.clone(),
            encrypted_message.message_check_sum.clone(),
            alp.clone(),
        ])?;

        let size: usize = encrypted_message.overall_check_sum.len();

        // Check number of matching elements in the two vectors
        let mut matching_values: usize = encrypted_message
            .overall_check_sum
            .iter()
            .zip(&first_check.to_vec())
            .filter(|&(x, y)| x == y)
            .count();

        if matching_values != size {
            return Err(PREError::OverallCheckSumFailure(String::from(
                "self-decrypt: overall checksum failure.\n",
            )));
        }

        // hash1
        let tag_private_key_hash: [u8; 32] =
            hash_input::<Sha256, 32>(vec![encrypted_message.tag, private_key])?;
        let scalar_tag_private_key: ECScalar = self
            .curve
            .get_scalar_from_bytes(&tag_private_key_hash.to_vec())?;

        let hg: ECPoint = self.curve.base_point.multiply(&scalar_tag_private_key);

        let encrypted_key: ECPoint = self
            .curve
            .get_point_from_bytes(&encrypted_message.encrypted_key)?;

        let key: [u8; 64] = hash_input::<Sha512, 64>(vec![encrypted_key
            .eval(&hg, ECOp::Subtract)
            .unwrap()
            .to_bytes()])
        .unwrap();

        let data: Vec<u8> = self
            .decrypt_symmetric(&encrypted_message.data, &key.to_vec())
            .await;

        // hash3
        let check2: [u8; 64] = hash_input::<Sha512, 64>(vec![data.clone(), key.to_vec()])?;

        matching_values = encrypted_message
            .message_check_sum
            .iter()
            .zip(&check2.to_vec())
            .filter(|&(x, y)| x == y)
            .count();

        if matching_values != encrypted_message.message_check_sum.len() {
            return Err(PREError::MessageCheckSumFailure(String::from(
                "self-decrypt: message checksum failure.\n",
            )));
        }

        Ok(data)
    }

    /// Re-encrypts the original plaintext.
    ///
    /// # Arguments
    ///
    /// * `public_key` - A ByteVector representing the public key with which to re-encrypt
    /// * `message` - EncryptedMessage (ciphertext) to be re-encrypted
    /// * `re_encryption_key` - A re-encryption key required to re-encrypt the message
    /// * `curve` - A specific choice for an elliptic curve.
    #[allow(dead_code)]
    pub fn re_encrypt(
        &self,
        public_key: &ByteVector,
        message: EncryptedMessage,
        re_encryption_key: ReEncryptionKey,
        _curve: &Curve,
    ) -> Result<ReEncryptedMessage, PREError> {
        let check1 = hash_input::<Sha512, 64>(vec![
            message.encrypted_key.clone(),
            message.data.clone(),
            message.message_check_sum.clone(),
            re_encryption_key.r3,
        ])?;

        let matching_values = message
            .overall_check_sum
            .iter()
            .zip(&check1.to_vec())
            .filter(|&(x, y)| x == y)
            .count();

        if matching_values != message.overall_check_sum.len() {
            return Err(PREError::OverallCheckSumFailure(String::from("")));
        }

        let p = self.curve.get_point_from_bytes(public_key)?;
        let t = Curve::get_random_scalar();

        let txg = p.multiply(&t);

        // hash 7
        // TODO (blaise): Remove these clones by using pass by reference
        let bet = self
            .curve
            .get_scalar_from_hash(&vec![
                txg.to_bytes(),
                message.data.clone(),
                message.message_check_sum.clone(),
                re_encryption_key.r2.clone(),
                self.curve.base_point.multiply(&t).to_bytes(),
            ])
            .unwrap();

        let r1 = self.curve.get_point_from_bytes(&re_encryption_key.r1)?;
        let encrypted_key = self
            .curve
            .get_point_from_bytes(&message.encrypted_key)
            .unwrap()
            .eval(&r1, ECOp::Add)?;

        Ok(ReEncryptedMessage {
            d1: encrypted_key.multiply(&bet).to_bytes(),
            d2: message.data,
            d3: message.message_check_sum,
            d4: re_encryption_key.r2,
            d5: self.curve.base_point.multiply(&t).to_bytes(),
        })
    }

    /// Decrypts a re-encypted message under a re-encryption key.
    ///
    /// # Arguments
    ///
    /// * `re_encrypted_message` - A ByteVector representing the re-encrypted
    ///     message.
    #[allow(dead_code)]
    pub async fn re_decrypt(
        &self,
        re_encrypted_message: ReEncryptedMessage,
    ) -> Result<ByteVector, PREError> {
        let d1 = self.curve.get_point_from_bytes(&re_encrypted_message.d1)?;
        let d4 = self.curve.get_point_from_bytes(&re_encrypted_message.d4)?;
        let d5 = self.curve.get_point_from_bytes(&re_encrypted_message.d5)?;

        let txg = d5.multiply(&self.private_key);

        let b_inv = self
            .curve
            .get_scalar_from_hash(&vec![
                txg.to_bytes(),
                re_encrypted_message.d2.clone(),
                re_encrypted_message.d3.clone(),
                re_encrypted_message.d4,
                re_encrypted_message.d5,
            ])
            .unwrap()
            .eval(None, ECOp::Invert)?;

        let private_key_inv = self.private_key.eval(None, ECOp::Invert)?;
        let t1 = d1.multiply(&b_inv);
        let t2 = d4.multiply(&private_key_inv);

        let t_buf = t1.eval(&t2, ECOp::Subtract)?.to_bytes();
        let key = hash_input::<Sha512, 64>(vec![t_buf.clone()])?;
        let data = self
            .decrypt_symmetric(&re_encrypted_message.d2, &key.to_vec())
            .await;

        //hash 3
        let check2 = hash_input::<Sha512, 64>(vec![data.clone(), t_buf])?;
        let matching_values = re_encrypted_message
            .d3
            .iter()
            .zip(&check2.to_vec())
            .filter(|&(x, y)| x == y)
            .count();

        if matching_values != re_encrypted_message.d3.len() {
            //TODO: figure out what the 181 error means in the original codebase
            return Err(PREError::DefaultError(String::from("181?")));
        }

        Ok(data)
    }
}

#[cfg(test)]
mod self_encryption_tests {
    use super::*;
    use futures::executor::block_on;
    use std::fs;
    use std::io::prelude::*;
    use std::path::Path;

    const NUM_TEST_FILES: usize = 5;
    const TEST_DIR_PATH: &str = "test-files";

    fn generate_test_files() {
        fs::create_dir_all(TEST_DIR_PATH).unwrap();

        for i in 0..NUM_TEST_FILES {
            match fs::File::create(format!("test-files/file{}.txt", i)) {
                Ok(mut file) => {
                    let buffer = format!("This is test file {}", i + 1);
                    file.write_all(buffer.as_bytes())
                        .expect("failed to write to test file");
                }
                Err(_e) => {
                    panic!(
                        "{}",
                        format!("failed to create test file: file{}.txt", i + 1)
                    );
                }
            }
        }
    }

    fn remove_test_files() {
        fs::remove_dir_all(TEST_DIR_PATH).unwrap();
    }

    // Produce a byte vector representation for a given file path
    #[cfg(unix)]
    fn path_to_bytes<P: AsRef<Path>>(path: P) -> Vec<u8> {
        use std::os::unix::ffi::OsStrExt;

        path.as_ref().as_os_str().as_bytes().to_vec()
    }

    fn generate_plaintext_messages() -> Vec<(&'static str, &'static str)> {
        let messages = vec![
            ("first message to encrypt", "tag1"),
            ("second message to encrypt", "tag2"),
            ("third message to encrypt", "tag3"),
        ];
        messages
    }

    // #[test]
    // fn test_self_encryption() {
    //     let plaintext_messages = generate_plaintext_messages();
    //     let curve: Curve = Curve::new();
    //     let pre_state = PREState::new(curve);

    //     for (message, tag) in plaintext_messages {
    //         let message_as_bytes = message.as_bytes();
    //         let encrypted_message: EncryptedMessage =
    //             block_on(pre_state.self_encrypt(message_as_bytes.into(), tag.as_bytes().into()))
    //                 .unwrap();

    //         let decrypted_ciphertext: ByteVector =
    //             block_on(pre_state.self_decrypt(encrypted_message.clone())).unwrap();

    //         // check equality of the original text and the decrypted text
    //         assert_eq!(decrypted_ciphertext.as_slice(), message_as_bytes);

    //         // check equality of the tag used
    //         assert_eq!(tag.as_bytes(), encrypted_message.tag.as_slice());
    //     }
    // }

    #[test]
    fn test_file_self_encrypt() {
        generate_test_files();

        for dir_entry in fs::read_dir(TEST_DIR_PATH).unwrap() {
            let path_buf = dir_entry.unwrap().path();
            // let _file = fs::OpenOptions::new().read(true).open(path_buf).expect("Failed to read test file");

            let bytes: ByteVector = path_to_bytes(path_buf.as_path());

            let pre_state: PREState = PREState::new(Curve::new());
            let encrypted_file: EncryptedMessage = block_on(
                pre_state.self_encrypt(bytes.clone(), String::from("dummy tag").into_bytes()),
            )
            .expect("failed to encrypt file");

            let decrypted_file: ByteVector =
                block_on(pre_state.self_decrypt(encrypted_file)).expect("failed to decrypt file");

            assert_eq!(decrypted_file.as_slice(), bytes.as_slice());
        }

        remove_test_files();
    }
}
