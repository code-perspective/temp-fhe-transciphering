use std::collections::HashMap;
use std::env;
use std::fs;

use aes::cipher;
use aligned_vec::ABox;
use auto_base_conv::convert_lwe_to_glwe_const;
use auto_base_conv::fourier_glev_ciphertext;
use auto_base_conv::glwe_keyswitch;
use auto_base_conv::keyswitch_lwe_ciphertext_by_glwe_keyswitch;
use auto_base_conv::lwe_msb_bit_to_glev_by_trace_with_preprocessing;
use auto_base_conv::switch_scheme;
use auto_base_conv::{
    convert_standard_glwe_keyswitch_key_to_fourier, AutomorphKey, AutomorphKeySerializable,
    FourierGlweKeyswitchKey, GlweKeyswitchKeyOwned, AES_TIGHT,
};
use bincode::de;
use itertools::izip;
use submission::{
    aes_manager::{StateByteMat, BLOCKSIZE_IN_BIT, BYTESIZE, NUM_COLUMNS, NUM_ROWS},
    data_struct::AllRdKeys,
    help_fun::get_size_string,
};
use tfhe::core_crypto::fft_impl::fft128::crypto::ggsw::cmux;
use tfhe::core_crypto::fft_impl::fft64::{
    c64,
    crypto::{
        bootstrap::FourierLweBootstrapKeyView,
        ggsw::{FourierGgswCiphertextListMutView, FourierGgswCiphertextListView},
    },
};
use tfhe::core_crypto::prelude::*;

fn max_of_two<Scalar, Cont, MutCont>(
    input_a: &GgswCiphertextList<Cont>,
    input_b: &GgswCiphertextList<Cont>,
    lwe_a_list: &LweCiphertextList<Cont>,
    lwe_b_list: &LweCiphertextList<Cont>,
    output: &mut LweCiphertextList<MutCont>,
) where
    Scalar: UnsignedInteger + UnsignedTorus,
    Cont: Container<Element = Scalar>,
    MutCont: ContainerMut<Element = Scalar>,
{
    let glwe_size = input_a.glwe_size();
    let polynomial_size = input_a.polynomial_size();
    let ciphertext_modulus = input_a.ciphertext_modulus();
    let decomposition_base_log = input_a.decomposition_base_log();
    let decomposition_level_count = input_a.decomposition_level_count();
    let mut glwe_a =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut glwe_b =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut glwe_e =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut glwe_mid_0 =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut glwe_mid_1 =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut glwe_temp =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut fourier_ggsw_a = FourierGgswCiphertext::new(
        glwe_size,
        polynomial_size,
        decomposition_base_log,
        decomposition_level_count,
    );
    let mut fourier_ggsw_b = FourierGgswCiphertext::new(
        glwe_size,
        polynomial_size,
        decomposition_base_log,
        decomposition_level_count,
    );

    for (lwe_a, lwe_b, mut output_lwe) in
        izip!(lwe_a_list.iter(), lwe_b_list.iter(), output.iter_mut())
    {
        convert_lwe_to_glwe_const(&lwe_a, &mut glwe_b);
        convert_lwe_to_glwe_const(&lwe_b, &mut glwe_a);
        convert_lwe_to_glwe_const(&lwe_b, &mut glwe_a);
        for (ggsw_a, ggsw_b) in input_a.iter().rev().zip(input_b.iter().rev()) {
            convert_standard_ggsw_ciphertext_to_fourier(&ggsw_a, &mut fourier_ggsw_a);
            convert_standard_ggsw_ciphertext_to_fourier(&ggsw_b, &mut fourier_ggsw_b);

            glwe_mid_0.clone_from(&glwe_e);
            glwe_temp.clone_from(&glwe_a);
            cmux_assign(&mut glwe_mid_0, &mut glwe_temp, &fourier_ggsw_b);

            glwe_mid_1.clone_from(&glwe_b);
            glwe_temp.clone_from(&glwe_e);
            cmux_assign(&mut glwe_mid_1, &mut glwe_temp, &fourier_ggsw_b);

            glwe_e.clone_from(&glwe_mid_0);
            cmux_assign(&mut glwe_e, &mut glwe_mid_1, &fourier_ggsw_a);
        }
        extract_lwe_sample_from_glwe_ciphertext(&glwe_e, &mut output_lwe, MonomialDegree(0));
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

    let target_dir = format!("{}/ciphertexts_download", io_dir);

    // Create target directory if it doesn't exist
    fs::create_dir_all(&target_dir)?;

    // load params
    let param = &*AES_TIGHT;
    let glwe_size = param.glwe_dimension().to_glwe_size();
    let polynomial_size = param.polynomial_size();
    let ks_base_log = param.glwe_ds_base_log();
    let ks_level = param.glwe_ds_level();
    let base_log = param.cbs_base_log();
    let level = param.cbs_level();
    let ciphertext_modulus = param.ciphertext_modulus();
    let log_lut_count = param.log_lut_count();

    // Load encrypted result from aes_ciphertexts_download
    let ciphertexts_download_dir = format!("{}/ciphertext_aes_download", io_dir);
    let aes_result_path = format!("{}/result.bin", ciphertexts_download_dir);
    let aes_result_bytes = fs::read(&aes_result_path)?;
    let lwe_ciphertext_list: LweCiphertextList<Vec<u64>> = bincode::deserialize(&aes_result_bytes)?;

    // Load computation keys
    let public_keys_dir = format!("{}/public_keys", io_dir);

    let bsk_bytes = fs::read(format!("{}/bsk.bin", public_keys_dir))?;
    let ksk_bytes = fs::read(format!("{}/ksk.bin", public_keys_dir))?;
    let auto_keys_bytes = fs::read(format!("{}/auto_keys.bin", public_keys_dir))?;
    let ss_key_bytes = fs::read(format!("{}/ss_key.bin", public_keys_dir))?;

    // Deserialize keys
    let bsk: LweBootstrapKeyOwned<u64> = bincode::deserialize(&bsk_bytes)?;
    let ksk: GlweKeyswitchKeyOwned<u64> = bincode::deserialize(&ksk_bytes)?;
    let ss_key: GgswCiphertextListOwned<u64> = bincode::deserialize(&ss_key_bytes)?;
    let auto_keys_serialize: HashMap<usize, AutomorphKeySerializable> =
        bincode::deserialize(&auto_keys_bytes)?;

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
    let fourier_bsk = fourier_bsk.as_view();

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
    let mut lwe_buffer = LweCiphertext::new(
        0,
        bsk.input_lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );
    for (mut fourier_ggsw, ggsw) in fourier_ss_key
        .as_mut_view()
        .into_ggsw_iter()
        .zip(ss_key.iter())
    {
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw, &mut fourier_ggsw);
    }
    let fourier_ss_key = fourier_ss_key.as_view();

    let total_bits = lwe_ciphertext_list.lwe_ciphertext_count().0;
    if total_bits % 16 != 0 {
        return Err("lwe_ciphertext_list length is not a multiple of 16".into());
    }
    let num_chunks = total_bits / 16;
    if num_chunks != 8 {
        return Err("expected 8 chunks of 16 bits".into());
    }

    let mut ggsw_chunks: Vec<GgswCiphertextList<Vec<u64>>> = Vec::with_capacity(num_chunks);
    for input_chunk in lwe_ciphertext_list.chunks_exact(16) {
        let mut vec_glev = vec![
            GlweCiphertextList::new(
                0,
                glwe_size,
                polynomial_size,
                GlweCiphertextCount(level.0),
                ciphertext_modulus,
            );
            16
        ];
        for (input_bit, glev) in input_chunk.iter().zip(vec_glev.iter_mut()) {
            let glev_mut_view = GlweCiphertextListMutView::from_container(
                glev.as_mut(),
                glwe_size,
                polynomial_size,
                ciphertext_modulus,
            );

            keyswitch_lwe_ciphertext_by_glwe_keyswitch(
                &input_bit.as_view(),
                &mut lwe_buffer,
                &fourier_glwe_ksk,
            );

            lwe_msb_bit_to_glev_by_trace_with_preprocessing(
                lwe_buffer.as_view(),
                glev_mut_view,
                fourier_bsk,
                &auto_keys,
                base_log,
                level,
                log_lut_count,
            );
        }

        let mut ggsw_bit_list = GgswCiphertextList::new(
            0,
            glwe_size,
            polynomial_size,
            base_log,
            level,
            GgswCiphertextCount(16),
            ciphertext_modulus,
        );
        for (mut ggsw, glev) in ggsw_bit_list.iter_mut().zip(vec_glev.iter()) {
            switch_scheme(&glev, &mut ggsw, fourier_ss_key);
        }

        ggsw_chunks.push(ggsw_bit_list);
    }

    let mut lwe_chunks: Vec<LweCiphertextList<Vec<u64>>> = Vec::new();
    for lwe_chunk in lwe_ciphertext_list.chunks_exact(16) {
        let mut list = LweCiphertextList::new(
            0u64,
            lwe_ciphertext_list.lwe_size(),
            LweCiphertextCount(16),
            ciphertext_modulus,
        );
        list.as_mut().clone_from_slice(lwe_chunk.as_ref());
        lwe_chunks.push(list);
    }

    let mut mid_lwe_list = LweCiphertextList::new(
        0u64,
        lwe_ciphertext_list.lwe_size(),
        LweCiphertextCount(16),
        ciphertext_modulus,
    );

    let mut mid_lwe_list_2 = mid_lwe_list.clone();

    let mut mid_ggsw_list = GgswCiphertextList::new(
        0,
        glwe_size,
        polynomial_size,
        base_log,
        level,
        GgswCiphertextCount(16),
        ciphertext_modulus,
    );

    max_of_two(
        &ggsw_chunks[0],
        &ggsw_chunks[1],
        &lwe_chunks[0],
        &lwe_chunks[1],
        &mut mid_lwe_list_2,
    );
    for i in 2_usize..8 {
        let mut vec_glev = vec![
            GlweCiphertextList::new(
                0,
                glwe_size,
                polynomial_size,
                GlweCiphertextCount(level.0),
                ciphertext_modulus,
            );
            16
        ];
        mid_lwe_list.clone_from(&mid_lwe_list_2);
        for (input_bit, glev) in mid_lwe_list.iter().zip(vec_glev.iter_mut()) {
            let glev_mut_view = GlweCiphertextListMutView::from_container(
                glev.as_mut(),
                glwe_size,
                polynomial_size,
                ciphertext_modulus,
            );

            keyswitch_lwe_ciphertext_by_glwe_keyswitch(
                &input_bit.as_view(),
                &mut lwe_buffer,
                &fourier_glwe_ksk,
            );

            lwe_msb_bit_to_glev_by_trace_with_preprocessing(
                lwe_buffer.as_view(),
                glev_mut_view,
                fourier_bsk,
                &auto_keys,
                base_log,
                level,
                log_lut_count,
            );
        }

        for (mut ggsw, glev) in mid_ggsw_list.iter_mut().zip(vec_glev.iter()) {
            switch_scheme(&glev, &mut ggsw, fourier_ss_key);
        }

        max_of_two(
            &mid_ggsw_list,
            &ggsw_chunks[i],
            &mid_lwe_list,
            &lwe_chunks[i],
            &mut mid_lwe_list_2,
        );
    }

    // Save final result
    let final_result_path = format!("{}/result.bin", target_dir);
    let final_result_bytes = bincode::serialize(&mid_lwe_list_2)?;
    fs::write(&final_result_path, final_result_bytes)?;

    Ok(())
}
