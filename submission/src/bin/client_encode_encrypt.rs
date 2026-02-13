use std::{env, fs};

use auto_base_conv::{AES_TIGHT, AesParam};
use submission::{aes_manager::Aes128Manager, data_struct::{AllRdKeys, get_0_round_key, get_8_to_1_round_key, get_10_9_round_key}, help_fun::get_size_string};
use tfhe::core_crypto::{prelude::{ActivatedRandomGenerator, EncryptionRandomGenerator, GlweSecretKey, SecretRandomGenerator}, seeders::new_seeder};




pub fn gen_transciphering_keys(
    param: &AesParam<u64>,
    glwe_sk: &GlweSecretKey<Vec<u64>>,
    aes_key: &[u8; 16],
    encryption_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
) -> AllRdKeys {
    let aes = Aes128Manager::new(aes_key);
    AllRdKeys {
        _10_9_round_key: get_10_9_round_key(param, glwe_sk, &aes, encryption_generator),
        _8_to_1_round_key: get_8_to_1_round_key(param, glwe_sk, &aes, encryption_generator),
        _0_round_key: get_0_round_key(param, glwe_sk, &aes, encryption_generator),
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <size>", args[0]);
        std::process::exit(1);
    }

    let size = args[1].clone();
    let io_dir = "io/".to_owned() + get_size_string(size.parse::<usize>()?);
    let data_dir = "datasets/".to_owned() + get_size_string(size.parse::<usize>()?);

    let aes_key_path = format!("{}/aes_key.hex", data_dir);
    let hex_string = fs::read_to_string(&aes_key_path)?.trim().to_string();

    let mut aes_key: [u8; 16] = [0u8; 16];
    for (i, byte) in aes_key.iter_mut().enumerate() {
        let hex_pair = &hex_string[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(hex_pair, 16)?;
    }

    let secret_keys_dir = format!("{}/secret_keys", io_dir);
    let glwe_sk_path = format!("{}/glwe_sk.bin", secret_keys_dir);
    let glwe_sk_bytes = fs::read(&glwe_sk_path)?;
    let glwe_sk: GlweSecretKey<Vec<u64>> = bincode::deserialize(&glwe_sk_bytes)?;

    let param = &*AES_TIGHT;
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    
    let trans_key = gen_transciphering_keys(param, &glwe_sk, &aes_key, &mut encryption_generator);

    let ciphertext_upload_dir = format!("{}/ciphertexts_upload", io_dir);
    fs::create_dir_all(&ciphertext_upload_dir)?;
    
    let trans_key_path = format!("{}/trans_key.bin", ciphertext_upload_dir);
    fs::write(&trans_key_path, bincode::serialize(&trans_key)?)?;
    
    println!("Transciphering keys saved to {}", ciphertext_upload_dir);

    Ok(())
}
