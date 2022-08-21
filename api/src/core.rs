use crate::curve::{Curve, Point, Scalar};
use crate::{ByteVector, PREError};

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

    pub fn self_encrypt(
        &self,
        message: ByteVector,
        tag: ByteVector,
    ) -> Result<EncryptedMessage, PREError> {
        let t = self.curve.get_random_scalar();
        let T = self.curve.get_basepoint().multiply(&t);

        // hash 1
        let private_key_vector = self.private_key.to_byte_vector()?;
        // let sha256_output = sha256(tag, private_key_vector);
        // let h = self.curve.get_scalar_from_byte_vector(byte_vector)

        Ok(EncryptedMessage {})
    }
}

#[cfg(test)]
mod test {}
