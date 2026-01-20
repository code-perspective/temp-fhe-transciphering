# AES Transciphering (TFHE) — Minimal Demo

A compact Rust demo that **transciphers AES‑128 ciphertext into 128 LWE bit‑ciphertexts** using TFHE‑style bootstrapping and then runs two tiny homomorphic workloads with plaintext correctness checks. The demo is organized into five files:

```
src/
├─ aes_manager.rs   # Plain AES-128 (S-Box/InvSBox, key schedule, round LUT construction)
├─ client.rs        # Key generation for FHE + transciphering keys/LUTs; LWE decrypt/decode helper
├─ server.rs        # AES→LWE transciphering pipeline + tiny workloads (workload 1/2)
├─ harness.rs       # Random message/key generation, reference AES encrypt, result checkers
└─ main.rs          # End-to-end flow: keygen → transcipher → workloads → verification
```

---

## 1) What this demo does

1. **Generate a random 16‑byte message** and a random **AES‑128 key**.
2. **Encrypt** the message with a **reference AES implementation** to obtain an AES ciphertext.
3. **Generate FHE keys** (LWE/GLWE secret keys, Fourier BSK, GLWE→LWE KSK, automorphism keys, scheme‑switching key) for the chosen parameter set.
4. **Build round‑specific LUTs and “transciphering keys”** from the AES key (keyed inverse SBox tables and related precomputation for the first/last and middle rounds).
5. **Transcipher** the 16‑byte AES ciphertext into **128 LWE bit‑ciphertexts**.
6. Run two **tiny workloads** on the LWE list and **verify** their plaintext expectations:
   - **workload 1:** add the left and right halves of the bit list (XOR‑like effect per bit) → check that the first 8 bytes equal `msg[0..8] XOR msg[8..16]`.
   - **workload 2:** add `q/2` (MSB encoding) to each LWE (bit flip) → check that the 16 bytes equal `msg XOR 0xFF`.

---

## 2) Quick start

1. Place the five source files into your binary crate’s `src/` directory (or merge into your project).
2. Make sure `Cargo.toml` contains the dependencies above and compiles successfully with your local environment.
3. Build & run:

   ```bash
   cargo run --release
   ```

### Sample console output

```

harness check result: true
workload 1 check result: true
workload 2 check result: true
```

---

## 3) File-by-file

### `client.rs`

- `generate_fhe_keys(param, secret_rng, enc_rng)` →
  `(LweSK, GlweSK, Fourier BSK, Fourier GLWE→LWE KSK, automorph keys, scheme‑switch key)`.
- `gen_transciphering_keys(param, &glwe_sk, &aes_key, enc_rng)` → `AllRdKeys`.
- `decrypt_decode_lwe_list(lwe_sk, &LweCiphertextList) -> Vec<u64>`: LWE decode helper for debugging/verification.

### `server.rs`

- Core transcipher function (used by `main.rs`):

  ```rust
  // returns LweCiphertextList<Vec<u64>> with 128 bit-ciphertexts
  aes_to_lwe_trasnciphering(
      aes_cipher: &[u8; 16],
      param: &AesParam<u64>,
      rd_10_9, rd_8_to_1, rd_0,           // from AllRdKeys
      fft_bsk, fft_ksk, auto_keys, ss_key // FHE keys
  )
  ```

- Tiny workloads:
  - `workload_tiny_1(input)` — add right half into left half (XOR‑like).
  - `workload_tiny_2(input)` — add `Plaintext(1 << 63)` to every LWE (bit flip).

### `harness.rs`

- `gen_msg()` / `gen_aes_key()` random generators.
- `encrypt_aes(msg, key)` reference encryption to produce the AES ciphertext.
- `check_workload_1_result(...)`, `check_workload_2_result(...)` and (optionally) a top‑level transciphering correctness check.

### `main.rs`

- Wires everything together:
  - choose parameters (e.g., `AES_TIGHT`),
  - call `client::generate_fhe_keys`,
  - call `client::gen_transciphering_keys`,
  - call `server::aes_to_lwe_trasnciphering`,
  - run **workload 1/2** and print checks.

---
