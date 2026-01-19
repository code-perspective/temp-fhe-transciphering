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

    __, params, __, __, __ = parse_submission_arguments('Generate dataset for FHE benchmark.')
    DATASET_ENC_PATH = params.datadir() / f"db.hex"
    AES_KEY_PATH = params.datadir() / f"aes_key.hex"
    OUT_PATH = params.datadir() / f"expected.txt"
    MAX_PATH = params.datadir() / f"max_value.txt"
    IP_PATH = params.datadir() / f"inner_product.txt"

    with open(AES_KEY_PATH, "r") as f:
            aes_key = bytes.fromhex(f.read().strip())

    if params.get_size() == 0:
        # 1) load dataset containing the encrypted AES block
        with open(DATASET_ENC_PATH, "r") as f:
            ctxt = bytes.fromhex(f.read().strip())

        # 2) Decrypt using AES ECB mode
        aes_dec = pyaes.AES(aes_key)
        decrypted_block = aes_dec.decrypt(ctxt)
        
        # 3) Unpack the 16-byte block back into 8 integers
        decrypted_bytes = bytes(decrypted_block)
        result = struct.unpack('>HHHHHHHH', decrypted_bytes)

    else:
        print('Not implemented yet for size > toy')

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