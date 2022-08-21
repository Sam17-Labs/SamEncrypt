///A bunch of utility functions for testing

pub fn hex_to_string(data: &[u8]) -> String {
    let mut output = String::new();
    for item in data {
        let hex_formatted_str = format!("{:02x}", item);
        output.push_str(&hex_formatted_str);
    }
    output
}
