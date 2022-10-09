#!/bin/bash


if [ "$#"  == 1 ]; then
	BACKTRACE_VERBOSITY=$1
fi


# Configure the RUST_BACKTRACE environment variable to display 
# more information when tests fail

if [ $BACKTRACE_VERBOSITY == "full_backtrace" ]; then 
	echo "Printing Full Rust Backtrace"
	export RUST_BACKTRACE=full 
else
	export RUST_BACKTRACE=1
fi

# Build the package
cargo build

# Run all package unit tests. --nocapture allows for printing
# to stdout even with unit tests that pass 
cargo test -- --nocapture