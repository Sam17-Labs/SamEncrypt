use crate::ByteVector;
use crate::PREError;
pub use sha2::{Digest, Sha256};
use std::mem::MaybeUninit;

/// It appears that the sha256 function takes in a tag and a private key byte
/// vector. https://github.com/future-tense/proxy-reencryption/blob/master/src/hash.ts
///
/// $ cargo clean && cargo build --release && hyperfine --warmup 4 -r 10
/// "target/release/bin /storage/ISOs/alpine-standard-3.14.3-x86_64.iso"
///
/// $ cargo run --release -- test_data/test_512.bin
/// To trace the number of system calls (debugging for speed), use strace
/// $ strace ./target/release/bin /storage/ISOs/alpine-standard-3.14.3-x86_64.iso 2>&1 | wc

pub fn hash_input<D: Digest, const N: usize>(
    message: Vec<ByteVector>,
) -> Result<[u8; N], PREError> {
    let mut concatenated_input: ByteVector = Vec::new();
    for (index, bytes) in message.iter_mut().enumerate() {
        concatenated_input.append(bytes);
    }
    let mut hasher = D::new();
    hasher.update(concatenated_input.as_slice());

    let mut hash = hasher.finalize();

    let mut bytes_hash: [u8; N] = unsafe { MaybeUninit::uninit().assume_init() };
    bytes_hash.copy_from_slice(&hash);

    Ok(bytes_hash)
}

mod tests {
    use super::*;
    use crate::test_utils::hex_to_string;

    // size that sha256sum reads from file over over again
    const SIZE: usize = 0x8000;

    fn test_sha256() {
        // let mut file_data = vec![0; SIZE];
        // loop {
        //     let amt_data_read = file.read(&mut file_data)?;
        //     if amt_data_read == SIZE {
        //         hasher.update(&file_data);
        //     } else {
        //         hasher.update(&file_data[0..amt_data_read]);
        //         break;
        // }
        // }

        // let hash = sha256sum::<Sha256, 32>(ByteVector::new()).expect("didn't hash properly");
        // let hash_string = hex_to_string(&hash);
    }
}

pub fn testing() {
    let mut hasher = Sha256::new();

    hasher.update("Testing!");
}
