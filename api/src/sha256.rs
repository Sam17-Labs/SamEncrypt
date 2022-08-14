

use sha2::{Sha256, Digest};


pub fn testing() {
    let mut hasher = Sha256::new();

    hasher.update("Testing!");
}