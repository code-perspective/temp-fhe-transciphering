use std::{env, fs};

use auto_base_conv::{AES_SET_2, AesParam, generate_vec_keyed_lut_accumulator};
use submission::{
    aes_manager::Aes128Manager,
    aes_ref::*,
    data_struct::{AllRdKeys, AllRdKeys2, get_0_round_key, get_8_to_1_round_key, get_10_9_round_key},
    help_fun::get_size_string,
};
use tfhe::core_crypto::{
    algorithms::encrypt_lwe_ciphertext_list,
    commons::parameters::{LweCiphertextCount, LweSize},
    entities::{LweCiphertextList, LweCiphertextListOwned, PlaintextList},
    prelude::{
        ActivatedRandomGenerator, EncryptionRandomGenerator, GlweSecretKey,
    },
    seeders::new_seeder,
};

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

pub fn gen_transciphering_keys_2(
    param: &AesParam<u64>,
    glwe_sk: &GlweSecretKey<Vec<u64>>,
    aes_key: &[u8; 16],
    encryption_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
) -> AllRdKeys2 {
    let aes = Aes128Ref::new(&aes_key);
    let large_lwe_size = LweSize(param.glwe_dimension().0 * param.polynomial_size().0 + 1);
    let round_keys = aes.get_round_keys();
    let mut he_round_keys = Vec::<LweCiphertextListOwned<u64>>::with_capacity(NUM_ROUNDS + 1);
    for r in 0..=NUM_ROUNDS {
        let mut lwe_list_rk = LweCiphertextList::new(
            0u64,
            large_lwe_size,
            LweCiphertextCount(BLOCKSIZE_IN_BIT),
            param.ciphertext_modulus(),
        );

        let rk = PlaintextList::from_container(
            (0..BLOCKSIZE_IN_BIT)
                .map(|i| {
                    let byte_idx = i / BYTESIZE;
                    let bit_idx = i % BYTESIZE;
                    let round_key_byte = round_keys[r][byte_idx];
                    let round_key_bit = (round_key_byte & (1 << bit_idx)) >> bit_idx;
                    (round_key_bit as u64) << 63
                })
                .collect::<Vec<u64>>(),
        );
        encrypt_lwe_ciphertext_list(
            &glwe_sk.clone().into_lwe_secret_key(),
            &mut lwe_list_rk,
            &rk,
            param.glwe_modular_std_dev(),
            encryption_generator,
        );

        he_round_keys.push(lwe_list_rk);
    }
    let vec_keyed_sbox_round_1 = generate_vec_keyed_lut_accumulator(
        aes.get_keyed_sbox(0),
        u64::BITS as usize - 1,
        &glwe_sk,
        param.glwe_modular_std_dev(),
        param.ciphertext_modulus(),
        encryption_generator,
    );
    let vec_keyed_sbox_round_1_mult_by_2 = generate_vec_keyed_lut_accumulator(
        aes.get_keyed_sbox_mult_by_2(0),
        u64::BITS as usize - 1,
        &glwe_sk,
        param.glwe_modular_std_dev(),
        param.ciphertext_modulus(),
        encryption_generator,
    );
    let vec_keyed_sbox_round_1_mult_by_3 = generate_vec_keyed_lut_accumulator(
        aes.get_keyed_sbox_mult_by_3(0),
        u64::BITS as usize - 1,
        &glwe_sk,
        param.glwe_modular_std_dev(),
        param.ciphertext_modulus(),
        encryption_generator,
    );
    AllRdKeys2 {
        _0_round_key: vec![vec_keyed_sbox_round_1, vec_keyed_sbox_round_1_mult_by_2, vec_keyed_sbox_round_1_mult_by_3],
        other_round_keys: he_round_keys,
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

    let secret_keys_dir = format!("{}/secret_keys", io_dir);
    let glwe_sk_path = format!("{}/glwe_sk.bin", secret_keys_dir);
    let glwe_sk_bytes = fs::read(&glwe_sk_path)?;
    let glwe_sk: GlweSecretKey<Vec<u64>> = bincode::deserialize(&glwe_sk_bytes)?;

    let param = AES_SET_2.clone(); //AES_TIGHT
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    if size == "0" {
        for (i, byte) in aes_key.iter_mut().enumerate() {
            let hex_pair = &hex_string[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(hex_pair, 16)?;
        }
        let trans_key =
            gen_transciphering_keys(&param, &glwe_sk, &aes_key, &mut encryption_generator);

        let ciphertext_upload_dir = format!("{}/ciphertexts_upload", io_dir);
        fs::create_dir_all(&ciphertext_upload_dir)?;

        let trans_key_path = format!("{}/trans_key.bin", ciphertext_upload_dir);
        fs::write(&trans_key_path, bincode::serialize(&trans_key)?)?;

        println!("Transciphering keys saved to {}", ciphertext_upload_dir);
    } else if size == "1" || size == "2" || size == "3" {
        for (i, byte) in aes_key.iter_mut().enumerate() {
            let hex_pair = &hex_string[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(hex_pair, 16)?;
        }
        let trans_keys_2 =
            gen_transciphering_keys_2(&param, &glwe_sk, &aes_key, &mut encryption_generator);
        let ciphertext_upload_dir = format!("{}/ciphertexts_upload", io_dir);
        fs::create_dir_all(&ciphertext_upload_dir)?;

        let trans_key_path = format!("{}/trans_key.bin", ciphertext_upload_dir);
        fs::write(&trans_key_path, bincode::serialize(&trans_keys_2)?)?;

        println!("Transciphering keys saved to {}", ciphertext_upload_dir);
    } else {
        return Err(Box::from(format!("Unexpected size {}", size)));
    }

    Ok(())
}
