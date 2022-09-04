use crate::elliptic_curve::{Curve, Point, Scalar};
use crate::{ByteVector, PREError};
use sha2::{Sha256, Sha512};

use crate::hashing::hash_input;

// TODO: Remove the allow(dead_code) macro after impl

//#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct ReEncryptionKey {
    r1: ByteVector,
    r2: ByteVector,
    r3: ByteVector,
}

//#[derive(Debug, Clone)]
#[allow(dead_code)]
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
    private_key: Scalar,
    public_key: Point,
}

impl PREState {
    #[allow(dead_code)]
    pub fn new(private_key: ByteVector, curve: Curve) -> Result<Self, PREError> {
        match curve.get_scalar_from_byte_vector(&private_key) {
            Ok(secret) => {
                let public_key: Point = curve.get_basepoint().multiply(&secret);
                Ok(PREState {
                    curve,
                    private_key: secret,
                    public_key,
                })
            }
            Err(error) => Err(PREError::DefaultError(format!(
                "Unable to create Proxy Re-Encryption State: {:?}",
                error
            ))),
        }
    }

    #[allow(dead_code)]
    pub fn generate_re_encryption_key(
        &self,
        public_key: &ByteVector,
        tag: ByteVector,
    ) -> Result<ReEncryptionKey, PREError> {
        let p = self.curve.get_point_from_byte_vector(public_key)?;
        let xb = self.private_key.to_byte_vector()?;
        let r = self.curve.get_random_scalar();

        let hash_output = hash_input::<Sha256, 32>(vec![tag.clone(), xb.clone()])?;

        let h = self
            .curve
            .get_scalar_from_byte_vector(&hash_output.to_vec())?;

        Ok(ReEncryptionKey {
            r1: self
                .curve
                .get_basepoint()
                .multiply(&r.subtract(&h).unwrap())
                .to_byte_vector()
                .unwrap(),
            r2: p.multiply(&r).to_byte_vector().unwrap(),
            r3: self
                .curve
                .get_scalar_from_hash(&vec![tag, xb])
                .unwrap()
                .to_byte_vector()
                .unwrap(),
        })
    }

    #[allow(dead_code)]
    fn encrypt_symmetric(
        &self,
        _data: &ByteVector,
        key_hash: &ByteVector,
    ) -> Result<ByteVector, PREError> {
        let _key = &key_hash[0..32];
        let _nonce = &key_hash[32..32 + 12];

        Ok(vec![])
    }

    #[allow(dead_code)]
    fn decrypt_symmetric(
        &self,
        _data: &ByteVector,
        _key_hash: &ByteVector,
    ) -> Result<ByteVector, PREError> {
        Ok(vec![])
    }

    #[allow(dead_code)]
    pub fn self_encrypt(
        &self,
        message: ByteVector,
        tag: ByteVector,
    ) -> Result<EncryptedMessage, PREError> {
        // TODO: Remove clones as much as possible by using references where
        // necessary
        let t = self.curve.get_random_scalar();
        let tt = self.curve.get_basepoint().multiply(&t);

        // hash 1
        let private_key_vector = self.private_key.to_byte_vector()?;
        let sha256_output = hash_input::<Sha256, 32>(vec![tag.clone(), private_key_vector])?;
        let h = self
            .curve
            .get_scalar_from_byte_vector(&(sha256_output.to_vec()))?;

        let hg = self.curve.get_basepoint().multiply(&h);

        let encrypted_key = tt.add(&hg).unwrap().to_byte_vector()?;

        // encrypt msg using key
        let key = hash_input::<Sha512, 64>(vec![tt.to_byte_vector().unwrap()])?;

        let data = self.encrypt_symmetric(&message, &key.to_vec())?;

        let message_check_sum =
            hash_input::<Sha512, 64>(vec![message, tt.to_byte_vector().unwrap()]).unwrap();

        let alp = self
            .curve
            .get_scalar_from_hash(&vec![
                tag.clone(),
                self.private_key.to_byte_vector().unwrap(),
            ])
            .unwrap()
            .to_byte_vector()?;

        let overall_check_sum = hash_input::<Sha512, 64>(vec![
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

    #[allow(dead_code)]
    pub fn self_decrypt(&self, message: EncryptedMessage) -> Result<ByteVector, PREError> {
        // TODO: Remove clones as much as possible by using references where
        // necessary
        let xb = self.private_key.to_byte_vector()?;
        let alp = self
            .curve
            .get_scalar_from_hash(&vec![message.tag.clone(), xb.clone()])?;

        let check1 = hash_input::<Sha512, 64>(vec![
            message.encrypted_key.clone(),
            message.data.clone(),
            message.message_check_sum.clone(),
            alp.to_byte_vector().unwrap(),
        ])?;

        let size = message.overall_check_sum.len();

        // Check number of matching elements in the two vectors
        let mut matching_values = message
            .overall_check_sum
            .iter()
            .zip(&check1.to_vec())
            .filter(|&(x, y)| x == y)
            .count();

        if matching_values != size {
            return Err(PREError::OverallCheckSumFailure(String::from("")));
        }

        // hash1
        let sha_256_output = hash_input::<Sha256, 32>(vec![message.tag, xb])?;
        let h = self
            .curve
            .get_scalar_from_byte_vector(&sha_256_output.to_vec())?;

        let hg = self.curve.get_basepoint().multiply(&h);

        let encrypted_key = self
            .curve
            .get_point_from_byte_vector(&message.encrypted_key)?;

        let key = hash_input::<Sha512, 64>(vec![encrypted_key
            .subtract(&hg)
            .unwrap()
            .to_byte_vector()
            .unwrap()])
        .unwrap();
        let data = self.decrypt_symmetric(&message.data, &key.to_vec())?;

        // hash3
        let check2 = hash_input::<Sha512, 64>(vec![data.clone(), key.to_vec()])?;

        matching_values = message
            .message_check_sum
            .iter()
            .zip(&check2.to_vec())
            .filter(|&(x, y)| x == y)
            .count();

        if matching_values != message.message_check_sum.len() {
            return Err(PREError::OverallCheckSumFailure(String::from("")));
        }

        Ok(data)
    }

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

        let p = self.curve.get_point_from_byte_vector(public_key)?;
        let t = self.curve.get_random_scalar();

        let txg = p.multiply(&t);

        // hash 7
        // TODO (blaise): Remove these clones by using pass by reference
        let bet = self
            .curve
            .get_scalar_from_hash(&vec![
                txg.to_byte_vector().unwrap(),
                message.data.clone(),
                message.message_check_sum.clone(),
                re_encryption_key.r2.clone(),
                self.curve
                    .get_basepoint()
                    .multiply(&t)
                    .to_byte_vector()
                    .unwrap(),
            ])
            .unwrap();

        let r1 = self
            .curve
            .get_point_from_byte_vector(&re_encryption_key.r1)?;
        let encrypted_key = self
            .curve
            .get_point_from_byte_vector(&message.encrypted_key)
            .unwrap()
            .add(&r1)?;

        Ok(ReEncryptedMessage {
            d1: encrypted_key.multiply(&bet).to_byte_vector().unwrap(),
            d2: message.data,
            d3: message.message_check_sum,
            d4: re_encryption_key.r2,
            d5: self
                .curve
                .get_basepoint()
                .multiply(&t)
                .to_byte_vector()
                .unwrap(),
        })
    }

    #[allow(dead_code)]
    pub fn re_decrypt(&self, d: ReEncryptedMessage) -> Result<ByteVector, PREError> {
        let d1 = self.curve.get_point_from_byte_vector(&d.d1)?;
        let d4 = self.curve.get_point_from_byte_vector(&d.d4)?;
        let d5 = self.curve.get_point_from_byte_vector(&d.d5)?;

        let txg = d5.multiply(&self.private_key);

        let b_inv = self
            .curve
            .get_scalar_from_hash(&vec![
                txg.to_byte_vector().unwrap(),
                d.d2.clone(),
                d.d3.clone(),
                d.d4,
                d.d5,
            ])
            .unwrap()
            .inverse()?;

        let private_key_inv = self.private_key.inverse()?;
        let t1 = d1.multiply(&b_inv);
        let t2 = d4.multiply(&private_key_inv);

        let t_buf = t1.subtract(&t2).unwrap().to_byte_vector()?;
        let key = hash_input::<Sha512, 64>(vec![t_buf.clone()])?;
        let data = self.decrypt_symmetric(&d.d2, &key.to_vec())?;

        //hash 3
        let check2 = hash_input::<Sha512, 64>(vec![data.clone(), t_buf])?;
        let matching_values =
            d.d3.iter()
                .zip(&check2.to_vec())
                .filter(|&(x, y)| x == y)
                .count();

        if matching_values != d.d3.len() {
            //TODO: figure out what the 181 error means in the original codebase
            return Err(PREError::DefaultError(String::from("181?")));
        }

        Ok(data)
    }
}

#[cfg(test)]
mod test {}
