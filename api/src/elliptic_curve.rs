use crate::hashing::hash_input;
use crate::internals::{ByteVector, PREError};
use serde::{Deserialize, Serialize};

pub use curv::elliptic::curves::Ed25519;
pub use curv::elliptic::curves::EncodedPoint;
pub use curv::elliptic::curves::EncodedScalar;
pub use curv::elliptic::curves::Point;
pub use curv::elliptic::curves::Scalar;
use sha2::Sha256;

// use crate::hashing::hash_input;
// use sha2::Sha256;

pub trait CurveParameter {
    fn name(&self) -> &'static str;
}

#[derive(Clone, Debug)]
pub(crate) struct ECScalar {
    value: Scalar<Ed25519>,
}

#[derive(Clone, Debug)]
pub(crate) struct ECPoint {
    value: Point<Ed25519>,
}

#[derive(Debug, Clone)]
pub(crate) struct Curve {
    pub base_point: ECPoint,
}

impl CurveParameter for ECScalar {
    fn name(&self) -> &'static str {
        return "scalar";
    }
}

impl CurveParameter for ECPoint {
    fn name(&self) -> &'static str {
        return "point";
    }
}

// Reference to different operation on both scalars and points
// on an elliptic curve.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum ECOp {
    Add,
    Multiply,
    Subtract,
    Invert,
}

impl ECScalar {
    pub fn new(scalar: Scalar<Ed25519>) -> Self {
        ECScalar { value: scalar }
    }

    // Carries out basic scalar operations
    // TODO: remove the overhead of creating a new object every time we evaluate
    // We can make it no return type, and panic when conditions are not met.
    // Then do self.value = self.value + scalar.value for instance.
    pub fn eval(&self, scalar: Option<ECScalar>, operation: ECOp) -> Result<Self, PREError> {
        match operation {
            ECOp::Add => Ok(Self::new(self.value.clone() + scalar.unwrap().value)),
            ECOp::Subtract => Ok(Self::new(self.value.clone() - scalar.unwrap().value)),
            ECOp::Multiply => Ok(Self::new(self.value.clone() * scalar.unwrap().value)),
            ECOp::Invert => {
                assert_eq!(scalar.is_none(), true);
                match self.value.invert() {
                    Some(inverse) => Ok(Self::new(inverse)),
                    None => Err(PREError::ZeroScalarError(String::from(""))),
                }
            }
        }
    }

    // Serializes the scalar value to bytes
    pub fn to_bytes(&self) -> ByteVector {
        let bytes: EncodedScalar<Ed25519> = self.value.to_bytes();
        (*bytes).to_vec()
    }
    // Deserializes the scalar value from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<ECScalar, PREError> {
        let raw_scalar = Scalar::from_bytes(bytes);
        match raw_scalar {
            Ok(scalar) => Ok(Self::new(scalar)),
            Err(_error) => Err(PREError::ScalarDeserializationError(format!(
                "failed to deserialize a scalar from bytes"
            ))),
        }
    }

    // Generates a random non-zero scalar
    pub fn random() -> Self {
        Self::new(Scalar::random())
    }

    pub fn equals(&self, scalar: &ECScalar) -> bool {
        self.value == scalar.value
    }
}

impl ECPoint {
    pub fn new(point: Point<Ed25519>) -> Self {
        ECPoint { value: point }
    }

    pub fn eval(&self, point: &ECPoint, operation: ECOp) -> Result<Self, PREError> {
        match operation {
            ECOp::Add => Ok(Self::new(self.value.clone() + point.value.clone())),
            ECOp::Subtract => Ok(Self::new(self.value.clone() - point.value.clone())),
            ECOp::Multiply => Err(PREError::DefaultError(format!(
                "Invalid Operation: EC25519 can only be multiplied by scalars"
            ))),
            ECOp::Invert => Err(PREError::DefaultError(format!(
                "Invalid Operation: cannot invert a point on an elliptic curve"
            ))),
        }
    }
    // Refactor the code to avoid unnecessary clones
    pub fn multiply(&self, scalar: &ECScalar) -> Self {
        Self::new(self.value.clone() * scalar.value.clone())
    }

    // Serializes the point to bytes
    pub fn to_bytes(&self) -> ByteVector {
        let bytes = self.value.to_bytes(true);
        (*bytes).to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<ECPoint, PREError> {
        let raw_point = Point::from_bytes(bytes);
        match raw_point {
            Ok(point) => Ok(Self::new(point)),
            Err(_error) => Err(PREError::ScalarDeserializationError(format!(
                "failed to deserialize a point from bytes"
            ))),
        }
    }

    pub fn equals(&self, point: &ECPoint) -> bool {
        self.value == point.value
    }
}

impl Curve {
    pub fn new() -> Self {
        Curve {
            base_point: Self::get_basepoint(),
        }
    }
    fn get_basepoint() -> ECPoint {
        ECPoint::new(Point::base_point2().clone())
    }

    pub fn get_point_from_bytes(&self, bytes: &[u8]) -> Result<ECPoint, PREError> {
        ECPoint::from_bytes(bytes)
    }

    pub fn get_scalar_from_bytes(&self, bytes: &[u8]) -> Result<ECScalar, PREError> {
        ECScalar::from_bytes(bytes)
    }

    pub fn get_random_scalar() -> ECScalar {
        ECScalar::new(Scalar::random())
    }

    pub fn get_scalar_from_hash(&self, hashable: Vec<ByteVector>) -> Result<ECScalar, PREError> {
        let hash_output = hash_input::<Sha256, 32>(hashable)?;
        let scalar = ECScalar::from_bytes(&hash_output);
        scalar
    }
}

#[cfg(test)]
mod test {}
