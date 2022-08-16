use sha2::{Digest, Sha256};


pub fn testing() {
    let mut hasher = Sha256::new();

    hasher.update("Testing!");
}
