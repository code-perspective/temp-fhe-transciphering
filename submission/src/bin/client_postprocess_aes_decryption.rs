use std::{env, fs};

use submission::help_fun::get_size_string;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <size>", args[0]);
        std::process::exit(1); 
    }
    let size = args[1].clone();
    let io_dir = "io/".to_owned() + get_size_string(size.parse::<usize>()?);
    let intermediate_output_path = format!("{}/intermediate", io_dir);
    let input_path = format!("{}/decoded_result_aes.txt", intermediate_output_path);
    let output_path = format!("{}/result_aes.txt", io_dir);
    
    
    let decrypted_result: Vec<u64> = bincode::deserialize(&fs::read(&input_path)?)?;
    // Pack 128 bits into 8 u16 values and save one per line (decimal)
    if decrypted_result.len() % 16 != 0 {
        return Err("decrypted_result length is not a multiple of 16".into());
    }
    let mut packed: Vec<u16> = Vec::with_capacity(decrypted_result.len() / 16);
    for chunk in decrypted_result.chunks(16) {
        let mut value: u16 = 0;
        for &bit in chunk {
            value = (value << 1) | ((bit as u16) & 1);
        }
        packed.push(value);
    }
    let mut result_str = packed
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    result_str.push('\n');
    fs::write(&output_path, result_str)?;
    Ok(())
}