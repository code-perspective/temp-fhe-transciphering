use std::collections::HashMap;
use std::env;
use std::fs;

use aligned_vec::ABox;
use auto_base_conv::{
    byte_array_to_mat, byte_mat_to_array, convert_standard_glwe_keyswitch_key_to_fourier,
    get_he_state_byte, get_he_state_byte_mut, glwe_ciphertext_monic_monomial_div_assign,
    keyswitch_lwe_ciphertext_by_glwe_keyswitch, known_rotate_keyed_lut,
    lwe_ciphertext_list_add_assign, lwe_msb_bit_to_glev_by_trace_with_preprocessing, switch_scheme,
    AesParam, AutomorphKey, AutomorphKeySerializable, FftType, FourierGlweKeyswitchKey,
    GlweKeyswitchKeyOwned, AES_TIGHT,
};
use submission::{
    aes_manager::{StateByteMat, BLOCKSIZE_IN_BIT, BYTESIZE, NUM_COLUMNS, NUM_ROWS},
    data_struct::AllRdKeys,
    help_fun::get_size_string,
};
use tfhe::core_crypto::fft_impl::fft64::{
    c64,
    crypto::{
        bootstrap::FourierLweBootstrapKeyView,
        ggsw::{FourierGgswCiphertextListMutView, FourierGgswCiphertextListView},
    },
};
use tfhe::core_crypto::prelude::*;

pub fn aes_to_lwe_trasnciphering<KSKeyCont>(
    ciphertext: &[u8; 16],
    parms: &AesParam<u64>,
    all_rd_key: AllRdKeys,
    fft_bsk: FourierLweBootstrapKey<ABox<[c64]>>,
    fft_ksk: FourierGlweKeyswitchKey<KSKeyCont>,
    auto_key: HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: FourierGgswCiphertextList<Vec<c64>>,
) -> LweCiphertextList<Vec<u64>>
where
    KSKeyCont: Container<Element = c64>,
{
    let fft_bsk_lwe_size = fft_bsk.clone().output_lwe_dimension().to_lwe_size();
    let ciphertext_modulus = parms.ciphertext_modulus();

    let rd_key_10_9 = all_rd_key._10_9_round_key;
    let rd_key_8_to_1 = all_rd_key._8_to_1_round_key;
    let rd_key_0 = all_rd_key._0_round_key;
    // prepare containers
    let mut he_state = LweCiphertextList::new(
        0u64,
        fft_bsk_lwe_size,
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );

    let mut he_state_ks = LweCiphertextList::new(
        0u64,
        parms.lwe_dimension().to_lwe_size(),
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );

    let mut he_state_times_9 = LweCiphertextList::new(
        0u64,
        fft_bsk_lwe_size,
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );

    let mut he_state_times_11 = LweCiphertextList::new(
        0u64,
        fft_bsk_lwe_size,
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );

    let mut he_state_times_13 = LweCiphertextList::new(
        0u64,
        fft_bsk_lwe_size,
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );

    let mut he_state_times_14 = LweCiphertextList::new(
        0u64,
        fft_bsk_lwe_size,
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        ciphertext_modulus,
    );

    let mut temp = byte_array_to_mat(*ciphertext);
    inv_shift_rows(&mut temp);
    let ciphertext = byte_mat_to_array(temp);
    let (
        round_10_9_he_lut_cipher_times_9,
        round_10_9_he_lut_cipher_times_11,
        round_10_9_he_lut_cipher_times_13,
        round_10_9_he_lut_cipher_times_14,
    ) = rd_key_10_9;

    known_rotate_keyed_lut(
        ciphertext,
        &round_10_9_he_lut_cipher_times_9,
        &mut he_state_times_9,
    );
    known_rotate_keyed_lut(
        ciphertext,
        &round_10_9_he_lut_cipher_times_11,
        &mut he_state_times_11,
    );
    known_rotate_keyed_lut(
        ciphertext,
        &round_10_9_he_lut_cipher_times_13,
        &mut he_state_times_13,
    );
    known_rotate_keyed_lut(
        ciphertext,
        &round_10_9_he_lut_cipher_times_14,
        &mut he_state_times_14,
    );

    he_inv_mix_columns_precomp(
        &mut he_state,
        &he_state_times_9,
        &he_state_times_11,
        &he_state_times_13,
        &he_state_times_14,
    );

    he_inv_shift_rows(&mut he_state);
    // 8,7,6,5,4,3,2,1
    for round in (1..=8).into_iter().rev() {
        for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
            keyswitch_lwe_ciphertext_by_glwe_keyswitch(&lwe, &mut lwe_ks, &fft_ksk);
        }
        let (he_lut_times9, he_lut_times11, he_lut_times13, he_lut_times14) =
            rd_key_8_to_1[round - 1].clone(); //序号是0到7,但轮数是1到8
        he_inv_keyes_sbox_8_to_32_by_patched_wwlp_cbs(
            &he_state_ks,
            &mut he_state_times_9,
            &mut he_state_times_11,
            &mut he_state_times_13,
            &mut he_state_times_14,
            he_lut_times9,
            he_lut_times11,
            he_lut_times13,
            he_lut_times14,
            fft_bsk.as_view(),
            &auto_key,
            ss_key.clone().as_view(),
            parms.cbs_base_log(),
            parms.cbs_level(),
            parms.log_lut_count(),
        );

        he_inv_mix_columns_precomp(
            &mut he_state,
            &he_state_times_9,
            &he_state_times_11,
            &he_state_times_13,
            &he_state_times_14,
        );

        he_inv_shift_rows(&mut he_state);
    }

    // 最后一轮，只有查表
    for (lwe, mut lwe_ks) in he_state.iter().zip(he_state_ks.iter_mut()) {
        keyswitch_lwe_ciphertext_by_glwe_keyswitch(&lwe, &mut lwe_ks, &fft_ksk);
    }

    he_inv_keyes_sbox_8_to_8_by_patched_wwlp_cbs(
        &he_state_ks,
        &mut he_state,
        rd_key_0,
        fft_bsk.as_view(),
        &auto_key,
        ss_key.clone().as_view(),
        parms.cbs_base_log(),
        parms.cbs_level(),
        parms.log_lut_count(),
    );

    for mut chunk in he_state.chunks_exact_mut(BYTESIZE) {
        let mut tmp: Vec<Vec<u64>> = chunk.iter().map(|ct| ct.as_ref().to_vec()).collect();

        for i in 0..BYTESIZE {
            let src = &tmp[BYTESIZE - 1 - i];
            chunk.get_mut(i).as_mut().clone_from_slice(src.as_ref());
        }
    }
    he_state
}

///////////////////////////// local helper functions /////////////////////////////

fn he_inv_mix_columns_precomp<Scalar, Cont, ContMut>(
    he_state: &mut LweCiphertextList<ContMut>,
    he_state_mult_by_9: &LweCiphertextList<Cont>,
    he_state_mult_by_11: &LweCiphertextList<Cont>,
    he_state_mult_by_13: &LweCiphertextList<Cont>,
    he_state_mult_by_14: &LweCiphertextList<Cont>,
) where
    Scalar: UnsignedInteger,
    Cont: Container<Element = Scalar>,
    ContMut: ContainerMut<Element = Scalar>,
{
    let mut buf = LweCiphertextList::new(
        Scalar::ZERO,
        he_state.lwe_size(),
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        he_state.ciphertext_modulus(),
    );
    buf.as_mut().clone_from_slice(he_state.as_ref());

    for row in 0..NUM_ROWS {
        for col in 0..NUM_COLUMNS {
            let mut tmp = LweCiphertextList::new(
                Scalar::ZERO,
                he_state.lwe_size(),
                LweCiphertextCount(BYTESIZE),
                he_state.ciphertext_modulus(),
            );

            tmp.as_mut()
                .clone_from_slice(get_he_state_byte(&he_state_mult_by_14, row, col).as_ref());
            lwe_ciphertext_list_add_assign(
                &mut tmp,
                get_he_state_byte(&he_state_mult_by_11, (row + 1) % 4, col),
            );
            lwe_ciphertext_list_add_assign(
                &mut tmp,
                get_he_state_byte(&he_state_mult_by_13, (row + 2) % 4, col),
            );
            lwe_ciphertext_list_add_assign(
                &mut tmp,
                get_he_state_byte(&he_state_mult_by_9, (row + 3) % 4, col),
            );

            get_he_state_byte_mut(he_state, row, col)
                .as_mut()
                .clone_from_slice(tmp.as_ref());
        }
    }
}

fn he_inv_shift_rows<Scalar, Cont>(he_state: &mut LweCiphertextList<Cont>)
where
    Scalar: UnsignedInteger,
    Cont: ContainerMut<Element = Scalar>,
{
    let mut buf = LweCiphertextList::new(
        Scalar::ZERO,
        he_state.lwe_size(),
        LweCiphertextCount(BLOCKSIZE_IN_BIT),
        he_state.ciphertext_modulus(),
    );
    buf.as_mut().clone_from_slice(he_state.as_ref());

    for row in 1..4 {
        for col in 0..4 {
            let mut dst = get_he_state_byte_mut(he_state, row, col);
            let src = get_he_state_byte(&buf, row, (4 - row + col) % 4);
            dst.as_mut().clone_from_slice(src.as_ref());
        }
    }
}

fn he_inv_keyes_sbox_8_to_32_by_patched_wwlp_cbs(
    he_state_input: &LweCiphertextList<Vec<u64>>,
    he_state_output_mult_by_9: &mut LweCiphertextList<Vec<u64>>,
    he_state_output_mult_by_11: &mut LweCiphertextList<Vec<u64>>,
    he_state_output_mult_by_13: &mut LweCiphertextList<Vec<u64>>,
    he_state_output_mult_by_14: &mut LweCiphertextList<Vec<u64>>,
    rd_keyed_lut_times_9: Vec<Vec<GlweCiphertext<Vec<u64>>>>,
    rd_keyed_lut_times_11: Vec<Vec<GlweCiphertext<Vec<u64>>>>,
    rd_keyed_lut_times_13: Vec<Vec<GlweCiphertext<Vec<u64>>>>,
    rd_keyed_lut_times_14: Vec<Vec<GlweCiphertext<Vec<u64>>>>,
    fft_bsk: FourierLweBootstrapKeyView,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: FourierGgswCiphertextListView,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
) {
    for (
        i,
        (
            (((input, mut output_mult_by_9), mut output_mult_by_11), mut output_mult_by_13),
            mut output_mult_by_14,
        ),
    ) in he_state_input
        .chunks_exact(BYTESIZE)
        .zip(he_state_output_mult_by_9.chunks_exact_mut(BYTESIZE))
        .zip(he_state_output_mult_by_11.chunks_exact_mut(BYTESIZE))
        .zip(he_state_output_mult_by_13.chunks_exact_mut(BYTESIZE))
        .zip(he_state_output_mult_by_14.chunks_exact_mut(BYTESIZE))
        .enumerate()
    {
        he_inv_keyed_sbox_8_to_32_eval_by_patched_wwlp_cbs(
            &input,
            &mut output_mult_by_9,
            &mut output_mult_by_11,
            &mut output_mult_by_13,
            &mut output_mult_by_14,
            rd_keyed_lut_times_9[i].clone(),
            rd_keyed_lut_times_11[i].clone(),
            rd_keyed_lut_times_13[i].clone(),
            rd_keyed_lut_times_14[i].clone(),
            fft_bsk,
            auto_keys,
            ss_key,
            ggsw_base_log,
            ggsw_level,
            log_lut_count,
        );
    }
}

fn he_inv_keyes_sbox_8_to_8_by_patched_wwlp_cbs(
    he_state_input: &LweCiphertextList<Vec<u64>>,
    he_state_output_mult_by_1: &mut LweCiphertextList<Vec<u64>>,

    rd_keyed_lut_times_1: Vec<Vec<GlweCiphertext<Vec<u64>>>>,

    fft_bsk: FourierLweBootstrapKeyView,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: FourierGgswCiphertextListView,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
) {
    for (i, (input, mut output_mult_by_1)) in he_state_input
        .chunks_exact(BYTESIZE)
        .zip(he_state_output_mult_by_1.chunks_exact_mut(BYTESIZE))
        .enumerate()
    {
        he_inv_keyed_sbox_8_to_8_eval_by_patched_wwlp_cbs(
            &input,
            &mut output_mult_by_1,
            rd_keyed_lut_times_1[i].clone(),
            fft_bsk,
            auto_keys,
            ss_key,
            ggsw_base_log,
            ggsw_level,
            log_lut_count,
        );
    }
}

fn he_inv_keyed_sbox_8_to_32_eval_by_patched_wwlp_cbs(
    input: &LweCiphertextListView<u64>,
    output_mult_by_9: &mut LweCiphertextListMutView<u64>,
    output_mult_by_11: &mut LweCiphertextListMutView<u64>,
    output_mult_by_13: &mut LweCiphertextListMutView<u64>,
    output_mult_by_14: &mut LweCiphertextListMutView<u64>,

    mut rd_keyed_lut_times_9: Vec<GlweCiphertext<Vec<u64>>>,
    mut rd_keyed_lut_times_11: Vec<GlweCiphertext<Vec<u64>>>,
    mut rd_keyed_lut_times_13: Vec<GlweCiphertext<Vec<u64>>>,
    mut rd_keyed_lut_times_14: Vec<GlweCiphertext<Vec<u64>>>,

    fft_bsk: FourierLweBootstrapKeyView,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: FourierGgswCiphertextListView,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
) {
    let glwe_size = fft_bsk.glwe_size();
    let polynomial_size = fft_bsk.polynomial_size();
    let ciphertext_modulus = output_mult_by_9.ciphertext_modulus();

    let mut vec_glev = vec![
        GlweCiphertextList::new(
            0,
            glwe_size,
            polynomial_size,
            GlweCiphertextCount(ggsw_level.0),
            ciphertext_modulus,
        );
        BYTESIZE
    ];
    for (input_bit, glev) in input.iter().zip(vec_glev.iter_mut()) {
        let glev_mut_view = GlweCiphertextListMutView::from_container(
            glev.as_mut(),
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        );

        lwe_msb_bit_to_glev_by_trace_with_preprocessing(
            input_bit.as_view(),
            glev_mut_view,
            fft_bsk,
            auto_keys,
            ggsw_base_log,
            ggsw_level,
            log_lut_count,
        );
    }

    let mut ggsw_bit_list = GgswCiphertextList::new(
        0,
        glwe_size,
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
        GgswCiphertextCount(vec_glev.len()),
        ciphertext_modulus,
    );
    for (mut ggsw, glev) in ggsw_bit_list.iter_mut().zip(vec_glev.iter()) {
        switch_scheme(&glev, &mut ggsw, ss_key);
    }

    let mut fourier_ggsw_bit_list = FourierGgswCiphertextList::new(
        vec![
            c64::default();
            BYTESIZE
                * polynomial_size.to_fourier_polynomial_size().0
                * glwe_size.0
                * glwe_size.0
                * ggsw_level.0
        ],
        BYTESIZE,
        glwe_size,
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
    );
    for (mut fourier_ggsw, ggsw) in fourier_ggsw_bit_list
        .as_mut_view()
        .into_ggsw_iter()
        .zip(ggsw_bit_list.iter())
    {
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    }

    evaluate_8_to_8_cipher_lut(
        fourier_ggsw_bit_list.as_mut_view(),
        output_mult_by_9,
        &mut rd_keyed_lut_times_9,
    );

    evaluate_8_to_8_cipher_lut(
        fourier_ggsw_bit_list.as_mut_view(),
        output_mult_by_11,
        &mut rd_keyed_lut_times_11,
    );

    evaluate_8_to_8_cipher_lut(
        fourier_ggsw_bit_list.as_mut_view(),
        output_mult_by_13,
        &mut rd_keyed_lut_times_13,
    );

    evaluate_8_to_8_cipher_lut(
        fourier_ggsw_bit_list.as_mut_view(),
        output_mult_by_14,
        &mut rd_keyed_lut_times_14,
    );
}

fn he_inv_keyed_sbox_8_to_8_eval_by_patched_wwlp_cbs(
    input: &LweCiphertextListView<u64>,
    output_mult_by_1: &mut LweCiphertextListMutView<u64>,
    mut rd_keyed_lut_times_1: Vec<GlweCiphertext<Vec<u64>>>,
    fft_bsk: FourierLweBootstrapKeyView,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: FourierGgswCiphertextListView,
    ggsw_base_log: DecompositionBaseLog,
    ggsw_level: DecompositionLevelCount,
    log_lut_count: LutCountLog,
) {
    let glwe_size = fft_bsk.glwe_size();
    let polynomial_size = fft_bsk.polynomial_size();
    let ciphertext_modulus = output_mult_by_1.ciphertext_modulus();

    let mut vec_glev = vec![
        GlweCiphertextList::new(
            0,
            glwe_size,
            polynomial_size,
            GlweCiphertextCount(ggsw_level.0),
            ciphertext_modulus,
        );
        BYTESIZE
    ];
    for (input_bit, glev) in input.iter().zip(vec_glev.iter_mut()) {
        let glev_mut_view = GlweCiphertextListMutView::from_container(
            glev.as_mut(),
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        );

        lwe_msb_bit_to_glev_by_trace_with_preprocessing(
            input_bit.as_view(),
            glev_mut_view,
            fft_bsk,
            auto_keys,
            ggsw_base_log,
            ggsw_level,
            log_lut_count,
        );
    }

    let mut ggsw_bit_list = GgswCiphertextList::new(
        0,
        glwe_size,
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
        GgswCiphertextCount(vec_glev.len()),
        ciphertext_modulus,
    );
    for (mut ggsw, glev) in ggsw_bit_list.iter_mut().zip(vec_glev.iter()) {
        switch_scheme(&glev, &mut ggsw, ss_key);
    }

    let mut fourier_ggsw_bit_list = FourierGgswCiphertextList::new(
        vec![
            c64::default();
            BYTESIZE
                * polynomial_size.to_fourier_polynomial_size().0
                * glwe_size.0
                * glwe_size.0
                * ggsw_level.0
        ],
        BYTESIZE,
        glwe_size,
        polynomial_size,
        ggsw_base_log,
        ggsw_level,
    );
    for (mut fourier_ggsw, ggsw) in fourier_ggsw_bit_list
        .as_mut_view()
        .into_ggsw_iter()
        .zip(ggsw_bit_list.iter())
    {
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    }

    evaluate_8_to_8_cipher_lut(
        fourier_ggsw_bit_list.as_mut_view(),
        output_mult_by_1,
        &mut rd_keyed_lut_times_1,
    );
}

fn evaluate_8_to_8_cipher_lut(
    fourier_ggsw_bit_list: FourierGgswCiphertextListMutView,
    output: &mut LweCiphertextListMutView<u64>,
    cipher_lut: &mut Vec<GlweCiphertext<Vec<u64>>>,
) {
    // println!("glwe_size {}",glwe_size.0);
    let polynomial_size = fourier_ggsw_bit_list.polynomial_size();
    let num_par_lut = polynomial_size.0 / (1 << BYTESIZE);
    let num_accumulator = if BYTESIZE % num_par_lut == 0 {
        BYTESIZE / num_par_lut
    } else {
        BYTESIZE / num_par_lut + 1
    };
    for acc_idx in 0..num_accumulator {
        let mut accumulator = &mut cipher_lut[acc_idx];

        for (i, fourier_ggsw_bit) in fourier_ggsw_bit_list
            .as_view()
            .into_ggsw_iter()
            .into_iter()
            .enumerate()
        {
            let mut buf = accumulator.clone();
            glwe_ciphertext_monic_monomial_div_assign(&mut buf, MonomialDegree(1 << i));
            glwe_ciphertext_sub_assign(&mut buf, &accumulator);
            add_external_product_assign(&mut accumulator, &fourier_ggsw_bit, &buf);
        }

        for i in 0..num_par_lut {
            let bit_idx = acc_idx * num_par_lut + i;
            let mut lwe_out = output.get_mut(bit_idx);
            extract_lwe_sample_from_glwe_ciphertext(
                &accumulator,
                &mut lwe_out,
                MonomialDegree(i * (1 << BYTESIZE)),
            );
        }
    }
}

fn inv_shift_rows(state: &mut StateByteMat) {
    let buf = state.clone();
    for row in 0..NUM_ROWS {
        for col in 0..NUM_COLUMNS {
            state[col][row] = buf[(NUM_COLUMNS + col - row) % NUM_COLUMNS][row];
        }
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

    // Load AES ciphertext from hex file
    let aes_cipher_hex_path = format!("{}/db.hex", data_dir);
    let hex_string = fs::read_to_string(&aes_cipher_hex_path)?.trim().to_string();

    let mut aes_cipher: [u8; 16] = [0u8; 16];
    for (i, byte) in aes_cipher.iter_mut().enumerate() {
        let hex_pair = &hex_string[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(hex_pair, 16)?;
    }

    // Load keys from directories
    let public_keys_dir = format!("{}/public_keys", io_dir);
    let ciphertext_upload_dir = format!("{}/ciphertexts_upload", io_dir);

    let bsk_bytes = fs::read(format!("{}/bsk.bin", public_keys_dir))?;
    let ksk_bytes = fs::read(format!("{}/ksk.bin", public_keys_dir))?;
    let auto_keys_bytes = fs::read(format!("{}/auto_keys.bin", public_keys_dir))?;
    let ss_key_bytes = fs::read(format!("{}/ss_key.bin", public_keys_dir))?;
    let trans_key_bytes = fs::read(format!("{}/trans_key.bin", ciphertext_upload_dir))?;

    // Deserialize keys
    let bsk: LweBootstrapKeyOwned<u64> = bincode::deserialize(&bsk_bytes)?;
    let ksk: GlweKeyswitchKeyOwned<u64> = bincode::deserialize(&ksk_bytes)?;
    let ss_key: GgswCiphertextListOwned<u64> = bincode::deserialize(&ss_key_bytes)?;
    let auto_keys_serialize: HashMap<usize, AutomorphKeySerializable> =
        bincode::deserialize(&auto_keys_bytes)?;
    let trans_key: AllRdKeys = bincode::deserialize(&trans_key_bytes)?;

    let param = &*AES_TIGHT;

    // Convert serializable automorph keys back to standard form
    let auto_keys: HashMap<usize, AutomorphKey<ABox<[c64]>>> = auto_keys_serialize
        .into_iter()
        .map(|(k, v)| (k, AutomorphKey::from_serializable(v, param.fft_type_auto())))
        .collect();

    // Convert keys to Fourier domain
    let mut fourier_glwe_ksk = FourierGlweKeyswitchKey::new(
        ksk.input_glwe_dimension().to_glwe_size(),
        ksk.output_glwe_dimension().to_glwe_size(),
        ksk.polynomial_size(),
        ksk.decomp_base_log(),
        ksk.decomp_level_count(),
        param.fft_type_ds(),
    );
    convert_standard_glwe_keyswitch_key_to_fourier(&ksk, &mut fourier_glwe_ksk);

    let mut fourier_bsk = FourierLweBootstrapKey::new(
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
    );
    convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);

    let mut fourier_ss_key = FourierGgswCiphertextList::new(
        vec![
            c64::default();
            ss_key.glwe_size().to_glwe_dimension().0
                * ss_key.polynomial_size().to_fourier_polynomial_size().0
                * ss_key.glwe_size().0
                * ss_key.glwe_size().0
                * ss_key.decomposition_level_count().0
        ],
        ss_key.glwe_size().to_glwe_dimension().0,
        ss_key.glwe_size(),
        ss_key.polynomial_size(),
        ss_key.decomposition_base_log(),
        ss_key.decomposition_level_count(),
    );

    for (mut fourier_ggsw, ggsw) in fourier_ss_key
        .as_mut_view()
        .into_ggsw_iter()
        .zip(ss_key.iter())
    {
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    }

    let mut result = aes_to_lwe_trasnciphering(
        &aes_cipher,
        param,
        trans_key,
        fourier_bsk,
        fourier_glwe_ksk,
        auto_keys,
        fourier_ss_key,
    );

    // Create output directory and save result
    let ciphertext_download_dir = format!("{}/ciphertext_aes_download", io_dir);
    fs::create_dir_all(&ciphertext_download_dir)?;

    let result_path = format!("{}/result.bin", ciphertext_download_dir);
    fs::write(&result_path, bincode::serialize(&result)?)?;

    Ok(())
}
