use crate::ByteVector;
use crate::PREError;

/// TODO(blaise, berwa): Implement the following structs
/// Implementations for the corresponding Typescript interfaces can be found here:
/// https://github.com/future-tense/curve25519-elliptic/blob/master/src/index.ts
///

#[allow(dead_code)]
pub(crate) struct Scalar {
    //TODO: struct definition
}

#[allow(dead_code)]
pub(crate) struct Point {
    //TODO: struct definition
}

#[allow(dead_code)]
pub(crate) struct Curve {
    //TODO: struct definition
}

#[allow(dead_code)]
impl Scalar {
    fn new() -> Self {
        //TODO
        Scalar {}
    }
    fn add(&self, _scalar: &Scalar) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
    fn subtract(&self, _scalar: &Scalar) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
    fn multiply(&self, _scalar: &Scalar) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }

    fn copy(&self) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
    fn inverse(&self) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
    fn to_byte_vector(&self) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
    fn equals(&self, _scalar: &Scalar) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
}

#[allow(dead_code)]
impl Point {
    fn new() -> Self {
        //TODO
        Point {}
    }
    fn add(&self, _point: &Point) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
    fn subtract(&self, _point: &Point) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
    fn multiply(&self, _factor: &Scalar) -> Result<Scalar, PREError> {
        //TODO
        Ok(Scalar {})
    }

    fn to_byte_vector(&self) -> Result<ByteVector, PREError> {
        //TODO
        Ok(vec![])
    }

    // The last two methods need not be implemented. We can just derive cloneable and Equals or PartialEq
    fn copy(&self) -> Result<Scalar, PREError> {
        //TODO
        Ok(Scalar {})
    }
    fn equals(&self, _point: &Point) -> Result<bool, PREError> {
        //TODO
        Ok(false)
    }
}

#[allow(dead_code)]
impl Curve {
    fn new() -> Self {
        //TODO
        Curve {}
    }
    fn get_basepoint() -> Point {
        //TODO
        Point {}
    }

    fn get_point_from_byte_vector(&self, _byte_vector: &ByteVector) -> Result<Point, PREError> {
        //TODO
        Ok(Point {})
    }

    fn get_scalar_from_byte_vector(&self, _byte_vector: &ByteVector) -> Result<Scalar, PREError> {
        //TODO
        Ok(Scalar {})
    }

    fn get_scalar_from_hash(&self, _array: &[ByteVector]) -> Result<Scalar, PREError> {
        //TODO
        Ok(Scalar {})
    }
    fn get_random_scalar() -> Scalar {
        //TODO
        Scalar {}
    }
}
