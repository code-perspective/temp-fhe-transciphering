use std::env;

use submission::help_fun::get_size_string;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <size>", args[0]);
        std::process::exit(1); 
    }
    let size = args[1].clone();
    let io_dir = "io/".to_owned() + get_size_string(size.parse::<usize>()?);
    
    // TODO: Add implementation.
    println!("Implement code in server_preprocess_dataset.rs");

    Ok(())
}