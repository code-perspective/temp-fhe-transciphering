use std::env;
use std::fs;

use submission::help_fun::decrypt_decode_lwe_list;
use submission::help_fun::get_size_string;
use tfhe::core_crypto::prelude::{LweCiphertextList, LweSecretKey};


pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <size>", args[0]);
        std::process::exit(1); 
    }
    
    let size = args[1].clone();
    let io_dir = "io/".to_owned() + get_size_string(size.parse::<usize>()?);

    // Load secret key
    let secret_keys_dir = format!("{}/secret_keys", io_dir);
    let lwe_sk_path = format!("{}/lwe_sk.bin", secret_keys_dir);
    let lwe_sk_bytes = fs::read(&lwe_sk_path)?;
    let lwe_sk: LweSecretKey<Vec<u64>> = bincode::deserialize(&lwe_sk_bytes)?;

    // Load encrypted result from ciphertexts_download
    let ciphertexts_download_dir = format!("{}/ciphertext_aes_download", io_dir);
    let result_path = format!("{}/result.bin", ciphertexts_download_dir);
    let result_bytes = fs::read(&result_path)?;
    let lwe_ciphertext_list: LweCiphertextList<Vec<u64>> = bincode::deserialize(&result_bytes)?;

    // Decrypt and decode
    let decrypted_result = decrypt_decode_lwe_list(&lwe_sk, &lwe_ciphertext_list);

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

    let output_path = format!("{}/result_aes.txt", io_dir);
    let mut result_str = packed
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    result_str.push('\n');
    fs::write(&output_path, result_str)?;

    Ok(())
}