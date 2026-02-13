#!/usr/bin/env python3

# Copyright (c) 2025 HomomorphicEncryption.org
# All rights reserved.
#
# This software is licensed under the terms of the Apache v2 License.
# See the LICENSE.md file for details.
#============================================================================

"""
Cleartext reference for the "AES Transciphering" workload.
For each test case:
    - Reads the dataset containing the encrypted AES block(s)
    - Performs AES decryption to get the plaintext block(s)
    - Writes the result to expected.txt for each test case (# datasets/xxx/expected.txt)
"""
import struct
import pyaes
from utils import parse_submission_arguments

def main():

    __, params, __, __, __, __ = parse_submission_arguments('Generate dataset for FHE benchmark.')
    DATASET_ENC_PATH = params.datadir() / f"db.hex"
    AES_KEY_PATH = params.datadir() / f"aes_key.hex"
    IV_PATH = params.datadir() / f"aes_iv.hex"
    OUT_PATH = params.datadir() / f"expected_aes.txt"
    MAX_PATH = params.datadir() / f"max_value.txt"
    IP_PATH = params.datadir() / f"inner_product.txt"

    with open(AES_KEY_PATH, "r") as f:
        aes_key = bytes.fromhex(f.read().strip())

    # 1) load dataset containing the encrypted AES block
    with open(DATASET_ENC_PATH, "r") as f:
        ciphertext_blocks = bytes.fromhex(f.read().strip())

    if params.get_size() == 0:
        # 2) Decrypt using AES ECB mode
        aes_dec = pyaes.AES(aes_key)
        decrypted_block = aes_dec.decrypt(ciphertext_blocks)

    else:
        # 2) Decrypt using AES CTR mode
        # Read IV from file
        with open(IV_PATH, "r") as f:
            IV = bytes.fromhex(f.read().strip())

        aes_dec = pyaes.AESModeOfOperationCTR(aes_key, counter=pyaes.Counter(int.from_bytes(IV, byteorder='big')))
        decrypted_block = aes_dec.decrypt(ciphertext_blocks)

    # 3) Unpack the 16-byte blocks back into integers
    decrypted_bytes = bytes(decrypted_block)
    packer = struct.Struct('>' + 'H' * params.get_db_bound())
    result = packer.unpack(decrypted_bytes)

    # 4) write to expected.txt (overwrites if it already exists)
    result = '\n'.join(str(value) for value in result)
    OUT_PATH.write_text(result + '\n', encoding="utf-8")

    # 5) Miniworkload #1: compute the maximum value in the decrypted database
    max_value = max(int(line) for line in result.split('\n') if line.strip())
    MAX_PATH.write_text(f"{max_value}\n", encoding="utf-8")

    # 6) Miniworkload #2: compute the inner product of the decrypted database with itself
    values = [int(line) for line in result.split('\n') if line.strip()]
    first_half = values[:len(values)//2]
    second_half = values[len(values)//2:len(values)]
    inner_product = sum((x*y) % (2**16) for x,y in zip(first_half, second_half)) % (2**16)
    IP_PATH.write_text(f"{inner_product}\n", encoding="utf-8")


if __name__ == "__main__":
    main()