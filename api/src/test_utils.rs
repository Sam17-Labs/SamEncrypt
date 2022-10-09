use std::fs;
use std::io::Write;
use std::str;

const NUM_TEST_FILES: usize = 5;
const TEST_DIR_PATH: &str = "test-files";

///A bunch of utility functions for testing

pub fn hex_to_string(data: &[u8]) -> String {
    let mut output = String::new();
    for item in data {
        let hex_formatted_str = format!("{:02x}", item);
        output.push_str(&hex_formatted_str);
    }
    output
}

pub fn bytes_to_str_utf8(bytes: &[u8]) -> &str {
    let string = match str::from_utf8(bytes) {
        Ok(value) => value,
        Err(error) => {
            panic!("Invalid UTF-8 sequence: {}", error);
        }
    };
    string
}

pub(crate) fn generate_test_files() {
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

pub(crate) fn remove_test_files() {
    fs::remove_dir_all(TEST_DIR_PATH).unwrap();
}
