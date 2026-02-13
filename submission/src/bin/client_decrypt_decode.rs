use std::env;
use std::fs;

use submission::help_fun::decrypt_decode_lwe_list;
use submission::help_fun::get_size_string;
use tfhe::core_crypto::prelude::{Container, ContiguousEntityContainer, LweCiphertext, LweCiphertextList, LweSecretKey, UnsignedInteger, decrypt_lwe_ciphertext};

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
    let ciphertexts_download_dir = format!("{}/ciphertexts_download", io_dir);
    let result_path = format!("{}/result.bin", ciphertexts_download_dir);
    let result_bytes = fs::read(&result_path)?;
    let lwe_ciphertext_list: LweCiphertextList<Vec<u64>> = bincode::deserialize(&result_bytes)?;

    // Decrypt and decode
    let decrypted_result = decrypt_decode_lwe_list(&lwe_sk, &lwe_ciphertext_list);
    // intermediate output
    let intermediate_output_path = format!("{}/intermediate", io_dir);
    fs::create_dir_all(&intermediate_output_path)?;
    let output_path = format!("{}/decoded_result.txt", intermediate_output_path);
    
    let bytes = bincode::serialize(&decrypted_result)?;
    fs::write(&output_path, bytes)?;




    Ok(())
}