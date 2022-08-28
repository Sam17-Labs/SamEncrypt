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
    pub fn new() -> Self {
        //TODO
        Scalar {}
    }
    pub fn add(&self, _scalar: &Scalar) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
    pub fn subtract(&self, _scalar: &Scalar) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
    pub fn multiply(&self, _scalar: &Scalar) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }

    pub fn copy(&self) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
    pub fn inverse(&self) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
    pub fn to_byte_vector(&self) -> Result<ByteVector, PREError> {
        //TODO
        Ok(vec![])
    }
    pub fn equals(&self, _scalar: &Scalar) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
}

#[allow(dead_code)]
impl Point {
    pub fn new() -> Self {
        //TODO
        Point {}
    }
    pub fn add(&self, _point: &Point) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
    pub fn subtract(&self, _point: &Point) -> Result<Self, PREError> {
        //TODO
        Ok(Self {})
    }
    pub fn multiply(&self, _factor: &Scalar) -> Self {
        //TODO
        Self {}
    }

    pub fn to_byte_vector(&self) -> Result<ByteVector, PREError> {
        //TODO
        Ok(vec![])
    }

    // The last two methods need not be implemented. We can just derive cloneable and Equals or PartialEq
    pub fn copy(&self) -> Result<Scalar, PREError> {
        //TODO
        Ok(Scalar {})
    }
    pub fn equals(&self, _point: &Point) -> Result<bool, PREError> {
        //TODO
        Ok(false)
    }
}

#[allow(dead_code)]
impl Curve {
    pub fn new() -> Self {
        //TODO
        Curve {}
    }
    pub fn get_basepoint(&self) -> Point {
        //TODO
        Point {}
    }

    pub fn get_point_from_byte_vector(&self, _byte_vector: &ByteVector) -> Result<Point, PREError> {
        //TODO
        Ok(Point {})
    }

    pub fn get_scalar_from_byte_vector(
        &self,
        _byte_vector: &ByteVector,
    ) -> Result<Scalar, PREError> {
        //TODO
        Ok(Scalar {})
    }

    pub fn get_scalar_from_hash(&self, _array: &[ByteVector]) -> Result<Scalar, PREError> {
        //TODO
        Ok(Scalar {})
    }
    pub fn get_random_scalar(&self) -> Scalar {
        //TODO
        Scalar {}
    }
}

#[cfg(test)]
mod test {}
