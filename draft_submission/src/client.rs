use std::collections::HashMap;

use crate::aes_manager::{Aes128Manager, BYTESIZE};
use aligned_vec::ABox;
use auto_base_conv::{
    gen_all_auto_keys, generate_scheme_switching_key, generate_vec_keyed_lut_accumulator,
    keygen_pbs_with_glwe_ds, AesParam, AutomorphKey, FourierGlweKeyswitchKey,
};
use serde::{Deserialize, Serialize};
use tfhe::core_crypto::fft_impl::fft64::c64;
use tfhe::core_crypto::prelude::{
    allocate_and_trivially_encrypt_new_glwe_ciphertext, decrypt_lwe_ciphertext,
    ActivatedRandomGenerator, CastInto, Container, ContiguousEntityContainer,
    EncryptionRandomGenerator, FourierGgswCiphertextList, FourierLweBootstrapKey, GlweCiphertext,
    GlweCiphertextList, GlweSecretKey, GlweSecretKeyOwned, LweCiphertext, LweCiphertextList,
    LweSecretKey, LweSecretKeyOwned, PlaintextList, SecretRandomGenerator, UnsignedInteger,
};

pub fn generate_fhe_keys(
    param: &AesParam<u64>,
    secret_generator: &mut SecretRandomGenerator<ActivatedRandomGenerator>,
    encryption_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
) -> (
    LweSecretKeyOwned<u64>,
    GlweSecretKeyOwned<u64>,
    FourierLweBootstrapKey<ABox<[c64]>>,
    FourierGlweKeyswitchKey<ABox<[c64]>>,
    HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    FourierGgswCiphertextList<Vec<c64>>,
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
    let (lwe_sk, glwe_sk, _lwe_sk_after_ks, fourier_bsk, fourier_ksk) = keygen_pbs_with_glwe_ds(
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
    // let fourier_bsk = fourier_bsk.as_view();

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

    (lwe_sk, glwe_sk, fourier_bsk, fourier_ksk, auto_keys, ss_key)
}

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

/////////////////////// Data Structures ///////////////////////
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AllRdKeys {
    pub _10_9_round_key: (
        Vec<GlweCiphertextList<Vec<u64>>>,
        Vec<GlweCiphertextList<Vec<u64>>>,
        Vec<GlweCiphertextList<Vec<u64>>>,
        Vec<GlweCiphertextList<Vec<u64>>>,
    ),

    pub _8_to_1_round_key: Vec<(
        Vec<Vec<GlweCiphertext<Vec<u64>>>>,
        Vec<Vec<GlweCiphertext<Vec<u64>>>>,
        Vec<Vec<GlweCiphertext<Vec<u64>>>>,
        Vec<Vec<GlweCiphertext<Vec<u64>>>>,
    )>,
    pub _0_round_key: Vec<Vec<GlweCiphertext<Vec<u64>>>>,
}

///////////////////////////// local helper functions /////////////////////////////

fn get_10_9_round_key(
    param: &AesParam<u64>,
    glwe_sk: &GlweSecretKey<Vec<u64>>,
    aes: &Aes128Manager,
    encryption_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
) -> (
    Vec<GlweCiphertextList<Vec<u64>>>,
    Vec<GlweCiphertextList<Vec<u64>>>,
    Vec<GlweCiphertextList<Vec<u64>>>,
    Vec<GlweCiphertextList<Vec<u64>>>,
) {
    let (times_14, times_11, times_13, times_9) = aes.get_10_9_round_lut();
    let glwe_modular_std_dev = param.glwe_modular_std_dev();
    let ciphertext_modulus = param.ciphertext_modulus();
    let round_10_9_he_lut_times14 = generate_vec_keyed_lut_accumulator(
        times_14,
        u64::BITS as usize - 1,
        &glwe_sk,
        glwe_modular_std_dev,
        ciphertext_modulus,
        encryption_generator,
    );
    let round_10_9_he_lut_times11 = generate_vec_keyed_lut_accumulator(
        times_11,
        u64::BITS as usize - 1,
        &glwe_sk,
        glwe_modular_std_dev,
        ciphertext_modulus,
        encryption_generator,
    );
    let round_10_9_he_lut_times13 = generate_vec_keyed_lut_accumulator(
        times_13,
        u64::BITS as usize - 1,
        &glwe_sk,
        glwe_modular_std_dev,
        ciphertext_modulus,
        encryption_generator,
    );
    let round_10_9_he_lut_times9 = generate_vec_keyed_lut_accumulator(
        times_9,
        u64::BITS as usize - 1,
        &glwe_sk,
        glwe_modular_std_dev,
        ciphertext_modulus,
        encryption_generator,
    );
    (
        round_10_9_he_lut_times9,
        round_10_9_he_lut_times11,
        round_10_9_he_lut_times13,
        round_10_9_he_lut_times14,
    )
}

fn get_8_to_1_round_key(
    param: &AesParam<u64>,
    glwe_sk: &GlweSecretKey<Vec<u64>>,
    aes: &Aes128Manager,
    encryption_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
) -> Vec<(
    Vec<Vec<GlweCiphertext<Vec<u64>>>>,
    Vec<Vec<GlweCiphertext<Vec<u64>>>>,
    Vec<Vec<GlweCiphertext<Vec<u64>>>>,
    Vec<Vec<GlweCiphertext<Vec<u64>>>>,
)> {
    let mut all_rk: Vec<(
        Vec<Vec<GlweCiphertext<Vec<u64>>>>,
        Vec<Vec<GlweCiphertext<Vec<u64>>>>,
        Vec<Vec<GlweCiphertext<Vec<u64>>>>,
        Vec<Vec<GlweCiphertext<Vec<u64>>>>,
    )> = Vec::new();
    for round in 1..=8 {
        let (he_lut_times9, he_lut_times11, he_lut_times13, he_lut_times14) =
            get_round_keys(param, aes, round);
        all_rk.push((
            he_lut_times9,
            he_lut_times11,
            he_lut_times13,
            he_lut_times14,
        ));
    }

    all_rk
}
fn get_round_keys(
    param: &AesParam<u64>,
    aes: &Aes128Manager,
    round: usize,
) -> (
    Vec<Vec<GlweCiphertext<Vec<u64>>>>,
    Vec<Vec<GlweCiphertext<Vec<u64>>>>,
    Vec<Vec<GlweCiphertext<Vec<u64>>>>,
    Vec<Vec<GlweCiphertext<Vec<u64>>>>,
) {
    //16 * 2 accumulator
    let (times_14, times_11, times_13, times_9) = aes.get_round_lut(round);
    let mut he_lut_times14: Vec<Vec<GlweCiphertext<Vec<u64>>>> = Vec::new();
    let mut he_lut_times11: Vec<Vec<GlweCiphertext<Vec<u64>>>> = Vec::new();
    let mut he_lut_times13: Vec<Vec<GlweCiphertext<Vec<u64>>>> = Vec::new();
    let mut he_lut_times9: Vec<Vec<GlweCiphertext<Vec<u64>>>> = Vec::new();
    let num_accumulator = 2;
    let log_scale = 63;
    let num_par_lut = 4;

    for lut_9 in times_9.iter() {
        let mut temp_vec: Vec<GlweCiphertext<Vec<u64>>> = Vec::new();
        for acc_idx in 0..num_accumulator {
            let accumulator = (0..param.polynomial_size().0)
                .map(|i| {
                    let lut_idx = acc_idx * num_par_lut + i / (1 << BYTESIZE);
                    (((lut_9[i % (1 << BYTESIZE)] & (1 << lut_idx)) as usize)
                        << (log_scale - lut_idx))
                        .cast_into()
                })
                .collect::<Vec<u64>>();
            let accumulator_plaintext = PlaintextList::from_container(accumulator);
            let accumulator: GlweCiphertext<Vec<u64>> =
                allocate_and_trivially_encrypt_new_glwe_ciphertext(
                    param.glwe_dimension().to_glwe_size(),
                    &accumulator_plaintext,
                    param.ciphertext_modulus(),
                );
            temp_vec.push(accumulator);
        }
        he_lut_times9.push(temp_vec);
    }

    for lut_11 in times_11.iter() {
        let mut temp_vec: Vec<GlweCiphertext<Vec<u64>>> = Vec::new();
        for acc_idx in 0..num_accumulator {
            let accumulator = (0..param.polynomial_size().0)
                .map(|i| {
                    let lut_idx = acc_idx * num_par_lut + i / (1 << BYTESIZE);
                    (((lut_11[i % (1 << BYTESIZE)] & (1 << lut_idx)) as usize)
                        << (log_scale - lut_idx))
                        .cast_into()
                })
                .collect::<Vec<u64>>();
            let accumulator_plaintext = PlaintextList::from_container(accumulator);
            let accumulator: GlweCiphertext<Vec<u64>> =
                allocate_and_trivially_encrypt_new_glwe_ciphertext(
                    param.glwe_dimension().to_glwe_size(),
                    &accumulator_plaintext,
                    param.ciphertext_modulus(),
                );
            temp_vec.push(accumulator);
        }
        he_lut_times11.push(temp_vec);
    }

    for lut_13 in times_13.iter() {
        let mut temp_vec: Vec<GlweCiphertext<Vec<u64>>> = Vec::new();
        for acc_idx in 0..num_accumulator {
            let accumulator = (0..param.polynomial_size().0)
                .map(|i| {
                    let lut_idx = acc_idx * num_par_lut + i / (1 << BYTESIZE);
                    (((lut_13[i % (1 << BYTESIZE)] & (1 << lut_idx)) as usize)
                        << (log_scale - lut_idx))
                        .cast_into()
                })
                .collect::<Vec<u64>>();
            let accumulator_plaintext = PlaintextList::from_container(accumulator);
            let accumulator: GlweCiphertext<Vec<u64>> =
                allocate_and_trivially_encrypt_new_glwe_ciphertext(
                    param.glwe_dimension().to_glwe_size(),
                    &accumulator_plaintext,
                    param.ciphertext_modulus(),
                );
            temp_vec.push(accumulator);
        }
        he_lut_times13.push(temp_vec);
    }

    for lut_14 in times_14.iter() {
        let mut temp_vec: Vec<GlweCiphertext<Vec<u64>>> = Vec::new();
        for acc_idx in 0..num_accumulator {
            let accumulator = (0..param.polynomial_size().0)
                .map(|i| {
                    let lut_idx = acc_idx * num_par_lut + i / (1 << BYTESIZE);
                    (((lut_14[i % (1 << BYTESIZE)] & (1 << lut_idx)) as usize)
                        << (log_scale - lut_idx))
                        .cast_into()
                })
                .collect::<Vec<u64>>();
            let accumulator_plaintext = PlaintextList::from_container(accumulator);
            let accumulator: GlweCiphertext<Vec<u64>> =
                allocate_and_trivially_encrypt_new_glwe_ciphertext(
                    param.glwe_dimension().to_glwe_size(),
                    &accumulator_plaintext,
                    param.ciphertext_modulus(),
                );
            temp_vec.push(accumulator);
        }
        he_lut_times14.push(temp_vec);
    }

    (
        he_lut_times9,
        he_lut_times11,
        he_lut_times13,
        he_lut_times14,
    )
}

fn get_0_round_key(
    param: &AesParam<u64>,
    glwe_sk: &GlweSecretKey<Vec<u64>>,
    aes: &Aes128Manager,
    encryption_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
) -> Vec<Vec<GlweCiphertext<Vec<u64>>>> {
    let plain_lut = aes.get_0_round_lut();
    let mut he_lut: Vec<Vec<GlweCiphertext<Vec<u64>>>> = Vec::new();
    let num_accumulator = 2;
    let log_scale = 63;
    let num_par_lut = 4;

    for lut_1 in plain_lut.iter() {
        let mut temp_vec: Vec<GlweCiphertext<Vec<u64>>> = Vec::new();
        for acc_idx in 0..num_accumulator {
            let accumulator = (0..param.polynomial_size().0)
                .map(|i| {
                    let lut_idx = acc_idx * num_par_lut + i / (1 << BYTESIZE);
                    (((lut_1[i % (1 << BYTESIZE)] & (1 << lut_idx)) as usize)
                        << (log_scale - lut_idx))
                        .cast_into()
                })
                .collect::<Vec<u64>>();
            let accumulator_plaintext = PlaintextList::from_container(accumulator);
            let accumulator: GlweCiphertext<Vec<u64>> =
                allocate_and_trivially_encrypt_new_glwe_ciphertext(
                    param.glwe_dimension().to_glwe_size(),
                    &accumulator_plaintext,
                    param.ciphertext_modulus(),
                );
            temp_vec.push(accumulator);
        }
        he_lut.push(temp_vec);
    }
    he_lut
}

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
