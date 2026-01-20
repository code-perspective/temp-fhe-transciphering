use aes::cipher::{BlockEncrypt, KeyInit};
use rand::{rngs::ThreadRng, Rng};
use tfhe::core_crypto::prelude::{decrypt_lwe_ciphertext, Container, ContiguousEntityContainer, LweCiphertext, LweCiphertextList, LweSecretKey, UnsignedInteger};

use crate::client;


pub fn gen_msg(rng: &mut ThreadRng) -> [u8; 16] {
    let mut message = [0u8; 16];
    for i in 0..16 {
        message[i] = rng.gen();
    }
    message
}

pub fn gen_aes_key(rng: &mut ThreadRng) -> [u8; 16] {
    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = rng.gen();
    }
    key
}

pub fn encrypt_aes(msg: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let cipher = aes::Aes128::new_from_slice(key).unwrap();
    let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(msg);
    cipher.encrypt_block(&mut block);
    let mut encrypted = [0u8; 16];
    encrypted.copy_from_slice(&block);
    encrypted
}

pub fn check_transciphering_result(result: &LweCiphertextList<Vec<u64>>, key: &LweSecretKey<Vec<u64>>, expected: &[u8; 16]) -> bool {
    let decrypted = decrypt_decode_lwe_list(key, result.clone());
    if decrypted.len() < 128 {
        return false;
    }

    let mut decrypted_bytes = [0u8; 16];
    for i in 0..16 {
        let mut byte: u8 = 0;
        for j in 0..8 {
            let bit_idx = i * 8 + j;
            let bit = (decrypted[bit_idx] & 1) as u8;
            byte |= bit << (7 - j);
        }
        decrypted_bytes[i] = byte;
    }
    &decrypted_bytes == expected
}

pub fn check_workload_1_result(result: &LweCiphertextList<Vec<u64>>, key: &LweSecretKey<Vec<u64>>, message: &[u8; 16]) -> bool {
    let decrypted = decrypt_decode_lwe_list(key, result.clone());
    if decrypted.len() < 128 {
        return false;
    }

    let mut decrypted_bytes = [0u8; 16];
    for i in 0..16 {
        let mut byte: u8 = 0;
        for j in 0..8 {
            let bit_idx = i * 8 + j;
            let bit = (decrypted[bit_idx] & 1) as u8;
            byte |= bit << (7 - j);
        }
        decrypted_bytes[i] = byte;
    }


    let mut expected_bytes = [0u8; 8];
    for i in 0..8 {
        expected_bytes[i] = message[i] ^ message[i + 8];
    }
    // println!("decrypted: {:?}", decrypted_bytes[0..8].iter().map(|b| format!("{:08b}", b)).collect::<Vec<_>>());
    // println!("expected:  {:?}", expected_bytes.iter().map(|b| format!("{:08b}", b)).collect::<Vec<_>>());
    &decrypted_bytes[0..8] == &expected_bytes
}

pub fn check_workload_2_result(result: &LweCiphertextList<Vec<u64>>, key: &LweSecretKey<Vec<u64>>, message: &[u8; 16]) -> bool {
    let decrypted = decrypt_decode_lwe_list(key, result.clone());
    if decrypted.len() < 128 {
        return false;
    }

    let mut decrypted_bytes = [0u8; 16];
    for i in 0..16 {
        let mut byte: u8 = 0;
        for j in 0..8 {
            let bit_idx = i * 8 + j;
            let bit = (decrypted[bit_idx] & 1) as u8;
            byte |= bit << (7 - j);
        }
        decrypted_bytes[i] = byte;
    }

    let mut expected_bytes = [0u8; 16];
    for i in 0..16 {
        expected_bytes[i] = message[i] ^ 255_u8;
    }
    // println!("decrypted: {:?}", decrypted_bytes.iter().map(|b| format!("{:08b}", b)).collect::<Vec<_>>());
    // println!("expected:  {:?}", expected_bytes.iter().map(|b| format!("{:08b}", b)).collect::<Vec<_>>());
    &decrypted_bytes == &expected_bytes
}


fn decrypt_decode_lwe_list(
    lwe_sk: &LweSecretKey<Vec<u64>>,
    ciphertext: LweCiphertextList<Vec<u64>>,
) -> Vec<u64> {
    let delta = 1_u64 << 63;
    let mut result: Vec<u64> = Vec::new();
    for c in ciphertext.iter() {
        result.push(decrypt(&lwe_sk, &c, delta));
    }
    result
}

pub fn post_process(data: &[u64]) -> [u8; 16] {
    let mut decrypted_bytes = [0u8; 16];
    for i in 0..16 {
        let mut byte: u8 = 0;
        for j in 0..8 {
            let bit_idx = i * 8 + j;
            let bit = (data[bit_idx] & 1) as u8;
            byte |= bit << (7 - j);
        }
        decrypted_bytes[i] = byte;
    }
    decrypted_bytes
}

//////////////////////////////local helpers//////////////////////////////
fn decrypt<C, KeyCont, Scalar>(
    lwe_sk: &LweSecretKey<KeyCont>,
    lwe_ctxt: &LweCiphertext<C>,
    delta: Scalar,
) -> Scalar
where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    C: Container<Element = Scalar>,
{
    let scaling = lwe_ctxt
        .ciphertext_modulus()
        .get_power_of_two_scaling_to_native_torus();

    let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &lwe_ctxt).0;
    let decrypted = decrypted * scaling;
    let rounding = (decrypted & (delta >> 1)) << 1;
    let decoded = (decrypted.wrapping_add(rounding)) / delta;
    return decoded;
}

