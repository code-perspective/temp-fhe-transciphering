#!/usr/bin/env python3

# Copyright (c) 2025 HomomorphicEncryption.org
# All rights reserved.
#
# This software is licensed under the terms of the Apache v2 License.
# See the LICENSE.md file for details.

"""
Generate AES key and encrypt the dataset messages using that key. Use pyaes for simplicity not performance.
"""
import pyaes
import hashlib
import struct
from pathlib import Path
from utils import parse_submission_arguments

def main():
    """
    Generate random AES key of fixed 128-bit size (for the moment), store it, and
    encrypt the dataset messages using that key.
    """
    __, params, seed, __, __ = parse_submission_arguments('Generate dataset for FHE benchmark.')
    DATASET_PATH = params.datadir() / f"db.txt"
    AES_KEY_PATH = params.datadir() / f"aes_key.hex"
    AES_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    DATASET_ENC_PATH = params.datadir() / f"db.hex"

    print(DATASET_PATH)

    # 1) Generate a 128-bit AES key from an integer seed
    # We convert the int to string/bytes then hash it to get a 16-byte key
    aes_key = hashlib.sha256(str(seed).encode()).digest()[:16]
    print(aes_key.hex())
    
    # 1) Load database 
    db = [int(line) for line in DATASET_PATH.read_text().strip().split('\n')]

    if params.get_size() == 0:
        # Do ECB encryption for toy instance
        if len(db) != 8:
            raise ValueError("File must contain exactly 8 16-bit integers, otherwise we need to pad.")
        # 2) Encode into a plaintext block (16 bytes)
        # 'H' is 2 bytes (16 bits) in struct. >HHHHHHHH is big-endian
        plaintext_block = struct.pack('>HHHHHHHH', *db)

        # 3) Encrypt using AES ECB mode
        aes = pyaes.AES(aes_key)
        ciphertext_block = aes.encrypt(plaintext_block)
    else:
        # Do CTR encryption for larger instances
        print('Not implemented yet for size > toy')

    # 4) Store the AES key and the ciphertext
    AES_KEY_PATH.write_text(aes_key.hex())
    DATASET_ENC_PATH.write_text(bytes(ciphertext_block).hex())

if __name__ == "__main__":
    main()