use submission::help_fun::get_size_string;
use std::{collections::HashMap, env};
use std::fs;

use aligned_vec::ABox;
use auto_base_conv::{AES_TIGHT, AesParam, AutomorphKey, AutomorphKeySerializable, GlweKeyswitchKeyOwned, gen_all_auto_keys, generate_scheme_switching_key, keygen_pbs_with_glwe_ks};
use tfhe::core_crypto::{prelude::{ActivatedRandomGenerator, EncryptionRandomGenerator, GgswCiphertextList, GlweSecretKeyOwned, LweBootstrapKeyOwned, LweSecretKeyOwned, SecretRandomGenerator}, seeders::new_seeder};
use tfhe::core_crypto::fft_impl::fft64::c64;

pub fn generate_fhe_keys(
    param: &AesParam<u64>,
    secret_generator: &mut SecretRandomGenerator<ActivatedRandomGenerator>,
    encryption_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
) -> (
    LweSecretKeyOwned<u64>,
    GlweSecretKeyOwned<u64>,
    LweBootstrapKeyOwned<u64>,
    GlweKeyswitchKeyOwned<u64>,
    HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    GgswCiphertextList<Vec<u64>>,
) {
    let lwe_dimension = param.lwe_dimension();
    let lwe_modular_std_dev = param.lwe_modular_std_dev();
    let glwe_dimension = param.glwe_dimension();
    let polynomial_size = param.polynomial_size();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let pbs_base_log = param.pbs_base_log();
    let pbs_level = param.pbs_level();
    let glwe_ds_base_log = param.glwe_ds_base_log();
    let glwe_ds_level = param.glwe_ds_level();
    let common_polynomial_size = param.common_polynomial_size();
    let fft_type_ds = param.fft_type_ds();
    let auto_base_log = param.auto_base_log();
    let auto_level = param.auto_level();
    let fft_type_auto = param.fft_type_auto();
    let ss_base_log = param.ss_base_log();
    let ss_level = param.ss_level();
    let ciphertext_modulus = param.ciphertext_modulus();

    // Generate keys
    let (lwe_sk, glwe_sk, _lwe_sk_after_ks, bsk, ksk) = keygen_pbs_with_glwe_ks(
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        lwe_modular_std_dev,
        glwe_modular_std_dev,
        pbs_base_log,
        pbs_level,
        glwe_ds_base_log,
        glwe_ds_level,
        common_polynomial_size,
        fft_type_ds,
        ciphertext_modulus,
        secret_generator,
        encryption_generator,
    );
    
    let ss_key = generate_scheme_switching_key(
        &glwe_sk,
        ss_base_log,
        ss_level,
        glwe_modular_std_dev,
        ciphertext_modulus,
        encryption_generator,
    );
    // let ss_key = ss_key.as_view();

    let auto_keys = gen_all_auto_keys(
        auto_base_log,
        auto_level,
        fft_type_auto,
        &glwe_sk,
        glwe_modular_std_dev,
        encryption_generator,
    );

    (lwe_sk, glwe_sk, bsk, ksk, auto_keys, ss_key)
}


pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <size>", args[0]);
        std::process::exit(1); 
    }
    let size = args[1].clone();
    let io_dir = "io/".to_owned() + get_size_string(size.parse::<usize>()?);
   
    let param = &*AES_TIGHT;
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    let fhe_keys =
        generate_fhe_keys(param, &mut secret_generator, &mut encryption_generator);
    
    let (lwe_sk, glwe_sk, bsk, ksk, auto_keys, ss_key) = fhe_keys;
    let serialize_auto_keys = auto_keys
        .into_iter()
        .map(|(k, v)| (k, v.to_serializable()))
        .collect::<HashMap<usize, AutomorphKeySerializable>>();

    
    // create secret keys directory
    let secret_keys_dir = format!("{}/secret_keys", io_dir);
    let public_keys_dir = format!("{}/public_keys", io_dir);
    fs::create_dir_all(&secret_keys_dir)?;
    fs::create_dir_all(&public_keys_dir)?;
    
    // save secret keys
    let lwe_sk_path = format!("{}/lwe_sk.bin", secret_keys_dir);
    let glwe_sk_path = format!("{}/glwe_sk.bin", secret_keys_dir);
    fs::write(&lwe_sk_path, bincode::serialize(&lwe_sk)?)?;
    fs::write(&glwe_sk_path, bincode::serialize(&glwe_sk)?)?;
    
    // save public/evaluation keys
    let bsk_path = format!("{}/bsk.bin", public_keys_dir);
    let ksk_path = format!("{}/ksk.bin", public_keys_dir);
    let auto_keys_path = format!("{}/auto_keys.bin", public_keys_dir);
    let ss_key_path = format!("{}/ss_key.bin", public_keys_dir);
    
    fs::write(&bsk_path, bincode::serialize(&bsk)?)?;
    fs::write(&ksk_path, bincode::serialize(&ksk)?)?;
    fs::write(&auto_keys_path, bincode::serialize(&serialize_auto_keys)?)?;
    fs::write(&ss_key_path, bincode::serialize(&ss_key)?)?;
        

    Ok(())
}