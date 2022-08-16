

use crate::ByteVector;






//#[derive(Debug, Clone)]
#[warn(dead_code)]
pub(crate) struct ReEncryptionKey {
    r1: ByteVector,
    r2: ByteVector,
    r3: ByteVector,
}

//#[derive(Debug, Clone)]
#[warn(dead_code)]
pub(crate) struct EncryptedMessage {
    tag: ByteVector,
    encrypted_key: ByteVector,
    message_check_sum: ByteVector,
    overall_check_sum: ByteVector,
    data: ByteVector,
}

#[warn(dead_code)]
pub(crate) struct ReEncryptedMessage {
    d1: ByteVector,
    d2: ByteVector,
    d3: ByteVector,
    d4: ByteVector,
    d5: ByteVector,
}

// TODO(blaise, berwa): Impls for Curve, Scalar, Point 
#[warn(dead_code)]
pub(crate) struct PREState {
    //curve: Curve,
    //private_key: Scalar,
    //public_key: Point,
}

