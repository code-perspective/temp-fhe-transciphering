use tfhe::core_crypto::prelude::{Container, ContiguousEntityContainer, LweCiphertext, LweCiphertextList, LweSecretKey, UnsignedInteger, decrypt_lwe_ciphertext};

pub fn get_size_string(position: usize) -> &'static str {
    match position {
        0 => "toy",
        1 => "small",
        2 => "medium",
        _ => "unknown",
    }
}

pub fn decrypt_decode_lwe_list(
    lwe_sk: &LweSecretKey<Vec<u64>>,
    ciphertext: &LweCiphertextList<Vec<u64>>,
) -> Vec<u64> {
    let delta = 1_u64 << 63;
    let mut result: Vec<u64> = Vec::new();
    for c in ciphertext.iter() {
        result.push(decrypt(&lwe_sk, &c, delta));
    }
    result
}

pub fn decrypt<C, KeyCont, Scalar>(
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