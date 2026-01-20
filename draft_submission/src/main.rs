mod aes_manager;
mod client;
mod harness;
mod server;

use std::{
    fs::File,
    io::{Read, Write},
};

use aes_manager::AesPlain;
use auto_base_conv::{lwe_ciphertext_list_add_assign, AesParam, AES_TIGHT, BLOCKSIZE_IN_BYTE};
use bincode::{deserialize, serialize};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tfhe::core_crypto::prelude::*;

fn main() {
    let param = &*AES_TIGHT;
    let mut rng = rand::thread_rng();
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    let msg = harness::gen_msg(&mut rng);
    println!("original msg: {:x?}", msg);
    let aes_key = harness::gen_aes_key(&mut rng);
    let aes_cipher = harness::encrypt_aes(&msg, &aes_key);

    let fhe_keys =
        client::generate_fhe_keys(param, &mut secret_generator, &mut encryption_generator);
    let (lwe_sk, glwe_sk, fft_bsk, fft_ksk, auto_keys, ss_key) = fhe_keys;

    let trans_key =
        client::gen_transciphering_keys(param, &glwe_sk, &aes_key, &mut encryption_generator);

    let mut after_trans = server::aes_to_lwe_trasnciphering(
        &aes_cipher,
        param,
        trans_key,
        fft_bsk,
        fft_ksk,
        auto_keys,
        ss_key,
    );

    println!(
        "harness check result: {}",
        harness::check_transciphering_result(&after_trans, &lwe_sk, &msg)
    );

    let mut data1 = after_trans.clone();
    server::workload_tiny_1(&mut data1);
    println!(
        "workload 1 check result: {}",
        harness::check_workload_1_result(&data1, &lwe_sk, &msg)
    );

    let mut data2 = after_trans.clone();
    server::workload_tiny_2(&mut data2);
    println!(
        "workload 2 check result: {}",
        harness::check_workload_2_result(&data2, &lwe_sk, &msg)
    );

    let decrypted = client::decrypt_decode_lwe_list(&lwe_sk, &after_trans);
    let final_result = client::post_process(&decrypted);
    println!("final result: {:x?}", final_result);
}
