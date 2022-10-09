// use sam_encrypt::*;

mod cli; 

use cli::SamEncryptAPIArgs;
use clap::Parser;



fn main() {
    let args = SamEncryptAPIArgs::parse();

}
