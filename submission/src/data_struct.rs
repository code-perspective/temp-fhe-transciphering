use auto_base_conv::{AesParam, generate_vec_keyed_lut_accumulator};
use serde::{Deserialize, Serialize};
use tfhe::core_crypto::prelude::{ActivatedRandomGenerator, CastInto, EncryptionRandomGenerator, GlweCiphertext, GlweCiphertextList, GlweSecretKey, PlaintextList, allocate_and_trivially_encrypt_new_glwe_ciphertext};

use crate::aes_manager::{Aes128Manager, BYTESIZE};



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

pub fn get_10_9_round_key(
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

pub fn get_8_to_1_round_key(
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

pub fn get_0_round_key(
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

