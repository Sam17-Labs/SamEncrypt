use crate::ByteVector;
use crate::PREError;
pub use sha2::{Digest, Sha256, Sha512};
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
    mut message: Vec<ByteVector>,
) -> Result<[u8; N], PREError> {
    let mut concatenated_input: ByteVector = Vec::new();
    for (_index, bytes) in message.iter_mut().enumerate() {
        concatenated_input.append(bytes);
    }
    let mut hasher = D::new();
    hasher.update(concatenated_input.as_slice());

    let hash = hasher.finalize();

    let mut bytes_hash: [u8; N] = unsafe { MaybeUninit::uninit().assume_init() };
    bytes_hash.copy_from_slice(&hash);

    Ok(bytes_hash)
}

// The testing messages are retrieved from the SHA test vectors for hashing
// byte-oriented messages found here
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;

    fn get_sha256_test_messages() -> Vec<&'static str> {
        vec![
            "c299209682",
            "74cb9381d89f5aa73368",
            "76ed24a0f40a41221ebfcf",
            "8620b86fbcaace4ff3c2921b8466ddd7bacae07eefef693cf17762dcabb89a84010fc9a0fb76c\
            e1c26593ad637a61253f224d1b14a05addccabe",
            "0546f7b8682b5b95fd32385faf25854cb3f7b40cc8fa229fbd52b16934aab388a7",
        ]
    }

    fn get_expected_sha256_outputs() -> Vec<&'static str> {
        vec![
            "f0887fe961c9cd3beab957e8222494abb969b1ce4c6557976df8b0f6d20e9166",
            "73d6fad1caaa75b43b21733561fd3958bdc555194a037c2addec19dc2d7a52bd",
            "044cef802901932e46dc46b2545e6c99c0fc323a0ed99b081bda4216857f38ac",
            "dba490256c9720c54c612a5bd1ef573cd51dc12b3e7bd8c6db2eabe0aacb846b",
            "b31ad3cd02b10db282b3576c059b746fb24ca6f09fef69402dc90ece7421cbb7",
        ]
    }

    fn get_sha512_test_messages() -> Vec<&'static str> {
        vec![
            "38667f39277b",
            "b39f71aaa8a108",
            "6213e10a4420e0d9b77037",
            "0a78b16b4026f7ec063db4e7b77c42a298e524e268093c5038853e217dcd65f66428650165fca0\
            6a1b4c9cf1537fb5d463630ff3bd71cf32c3538b1fdda3fed5c9f601203319b7e1869a",
            "995c8f747ea418f7d63aba2260b34ac3c7dceebb78438ca4b1f982b7db9798ec1a7f32622264cb\
            024c0d9e60e955a6e1d677c923518851990a459b767d0f13cd803460f61870db3391b44693",
        ]
    }

    fn get_expected_sha512_outputs() -> Vec<&'static str> {
        vec![
            "85708b8ff05d974d6af0801c152b95f5fa5c06af9a35230c5bea2752f031f9bd84bd844717b3add\
            308a70dc777f90813c20b47b16385664eefc88449f04f2131",
            "258b8efa05b4a06b1e63c7a3f925c5ef11fa03e3d47d631bf4d474983783d8c0b09449009e842fc\
            9fa15de586c67cf8955a17d790b20f41dadf67ee8cdcdfce6",
            "9982dc2a04dff165567f276fd463efef2b369fa2fbca8cee31ce0de8a79a2eb0b53e437f7d9d1f4\
            1c71d725cabb949b513075bad1740c9eefbf6a5c6633400c7",
            "6095c3df5b9db7ce524d76123f77421ce888b86a477ae8c6db1d0be8d326d22c852915ab03c0c81\
            a5b7ac71e2c14e74bda17a78d2b10585fa214f6546eb710a0",
            "a00a601edeaca83041dc452d438a8de549594e25d843c2cf60a0e009fb92d87abe28a72690ab657\
            c8d35b43cd02d22ec0755de229d1f922fa6ca18a6d6c2aaae",
        ]
    }

    fn run_test<D: Digest + 'static>() {
        let test_messages: Vec<&str>;
        let expected_output: Vec<&str>;

        let digest_is_sha256 = TypeId::of::<D>() == TypeId::of::<Sha256>();

        if digest_is_sha256 {
            test_messages = get_sha256_test_messages();
            expected_output = get_expected_sha256_outputs();
        } else {
            test_messages = get_sha512_test_messages();
            expected_output = get_expected_sha512_outputs();
        }

        for (message, output) in test_messages.into_iter().zip(expected_output) {
            let byte_encoding =
                hex::decode(message).expect("Hex Decoding Error: Failed to decode test message");
            let checksum: Vec<u8>;

            if digest_is_sha256 {
                checksum = hash_input::<Sha256, 32>(vec![byte_encoding])
                    .unwrap()
                    .into();
            } else {
                checksum = hash_input::<Sha512, 64>(vec![byte_encoding])
                    .unwrap()
                    .into();
            }
            assert_eq!(output.to_string(), hex::encode(checksum));
        }
    }

    #[test]
    fn test_hash_input() {
        run_test::<Sha256>();
        run_test::<Sha512>();
    }
}
