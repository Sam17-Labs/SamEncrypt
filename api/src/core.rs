use crate::curve::{Curve, Point, Scalar};
use crate::ByteVector;

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
    // TODO(blaise, berwa)
}
