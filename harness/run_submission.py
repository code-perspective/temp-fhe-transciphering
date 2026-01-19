#!/usr/bin/env python3

# Copyright (c) 2025 HomomorphicEncryption.org
# All rights reserved.
#
# This software is licensed under the terms of the Apache v2 License.
# See the LICENSE.md file for details.

"""
run_submission.py - run the entire submission process, from build to verify
"""

import subprocess
import sys
import numpy as np
import utils
from params import instance_name

def main():
    """
    Run the entire submission process, from build to verify
    """
    
    # 0. Prepare running
    # Get the arguments
    size, params, seed, num_runs, clrtxt = utils.parse_submission_arguments('Run the add-two-values FHE benchmark.')
    test = instance_name(size)
    print(f"\n[harness] Running submission for {test} dataset")

    # Ensure the required directories exist
    utils.ensure_directories(params.rootdir)

    # # Build the submission if not built already
    # utils.build_submission(params.rootdir/"scripts")

    # The harness scripts are in the 'harness' directory,
    # the executables are in the directory submission/build
    harness_dir = params.rootdir/"harness"
    exec_dir = params.rootdir/"submission"/"target"/"release"

    # Remove and re-create IO directory
    io_dir = params.iodir()
    if io_dir.exists():
        subprocess.run(["rm", "-rf", str(io_dir)], check=True)
    io_dir.mkdir(parents=True)
    utils.log_step(0, "Init", True)

    # 1. Client-side: Generate the datasets (message to be encrypted with AES)
    cmd = ["python3", harness_dir/"generate_dataset.py", str(size)]
    # Use seed if provided
    if seed is not None:
        rng = np.random.default_rng(seed)
        gendata_seed = rng.integers(0,0x7fffffff)
        cmd.extend(["--seed", str(gendata_seed)])
    subprocess.run(cmd, check=True)
    utils.log_step(1, "Dataset generation")

    # 2. Client-side: Generate AES Key and encrypt the messages using the generated key
    cmd = ["python3", harness_dir/"aes_keygen_and_encrypt.py", str(size)]
    subprocess.run(cmd, check=True)
    utils.log_step(2, "AES Key generation and message encryption with AES")

    # Intermediate: Test correctness of cleartext implementation
    cmd = ["python3", harness_dir/"cleartext_impl.py", str(size)]
    subprocess.run(cmd, check=True)
    utils.log_step(2, "Cleartext implementation")

    # 3. Client-side: Preprocess the data using exec_dir/client_preprocess
    subprocess.run([exec_dir/"client_preprocess", str(size)], check=True)
    utils.log_step(3, "Client side preprocessing")

    # 4. Client-side: Generate the cryptographic keys 
    # Note: this does not use the rng seed above, it lets the implementation
    #   handle its own prg needs. It means that even if called with the same
    #   seed multiple times, the keys and ciphertexts will still be different.
    subprocess.run([exec_dir/"client_key_generation", str(size)], check=True)
    utils.log_step(4, "FHE Key Generation")

    # 5. Client-side: Encode and encrypt the aes key
    subprocess.run([exec_dir/"client_encode_encrypt", str(size)], check=True)
    utils.log_step(5, "AES key encoding and encryption")

    # Report size of keys and encrypted data
    utils.log_size(io_dir / "public_keys", "Public and evaluation keys")
    db_size = utils.log_size(io_dir / "ciphertexts_upload", "Encrypted aes-encrypted dataset")

    # 6. Server-side: Preprocess the (encrypted) dataset using exec_dir/server_preprocess_dataset
    subprocess.run(exec_dir/"server_preprocess_dataset", check=True)
    utils.log_step(6, "(Encrypted) dataset preprocessing")    

    # 7. Server side: Run aes_decryption 
    subprocess.run([exec_dir/"server_encrypted_aes_decryption", str(size)], check=True)
    utils.log_step(7, "Encrypted aes decryption")
    utils.log_size(io_dir / "ciphertexts_download", "Encrypted results")

    # 8. Server side: Run the encrypted processing run exec_dir/server_encrypted_compute
    subprocess.run([exec_dir/"server_encrypted_compute", str(size)], check=True)
    utils.log_step(8, "Encrypted computation of mini workload")
    utils.log_size(io_dir / "ciphertexts_download", "Encrypted results")

    # 9. Client-side: decrypt
    subprocess.run([exec_dir/"client_decrypt_decode_aes_decryption", str(size)], check=True)
    utils.log_step(9, "Result decryption")

    # 10. Client-side: post-process
    subprocess.run([exec_dir/"client_postprocess_aes_decryption", str(size)], check=True)
    utils.log_step(10, "Result postprocessing")

    # 11. Client-side: decrypt
    subprocess.run([exec_dir/"client_decrypt_decode", str(size)], check=True)
    utils.log_step(11, "Result decryption")

    # 12. Client-side: post-process
    subprocess.run([exec_dir/"client_postprocess", str(size)], check=True)
    utils.log_step(12, "Result postprocessing")

    # 13. Verify aes_decryption result
    aes_expected_file = params.datadir() / "expected_aes.txt"
    aes_result_file = io_dir / "result_aes.txt"

    if not aes_result_file.exists():
        print(f"Error: Result file {aes_result_file} not found")
        sys.exit(1)

    subprocess.run(["python3", harness_dir/"verify_aes_decryption.py",
            str(aes_expected_file), str(aes_result_file)], check=False)
    
    # 14. Verify the final result
    expected_file = params.datadir() / "expected.txt"
    result_file = io_dir / "result.txt"

    if not result_file.exists():
        print(f"Error: Result file {result_file} not found")
        sys.exit(1)

    subprocess.run(["python3", harness_dir/"verify_result.py",
            str(expected_file), str(result_file)], check=False)
    
    # 15. Store measurements
    run_path = params.measuredir() / f"results.json"
    run_path.parent.mkdir(parents=True, exist_ok=True)
    utils.save_run(run_path)

    print(f"\nAll steps completed for the {instance_name(size)} dataset!")

if __name__ == "__main__":
    main()