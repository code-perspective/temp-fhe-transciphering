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
    __, params, seed, __, __, __ = parse_submission_arguments('Generate dataset for FHE benchmark.')
    DATASET_PATH = params.datadir() / f"db.txt"
    AES_KEY_PATH = params.datadir() / f"aes_key.hex"
    AES_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    IV_PATH = params.datadir() / f"aes_iv.hex"
    DATASET_ENC_PATH = params.datadir() / f"db.hex"

    print(DATASET_PATH)

    # 1) Generate a 128-bit AES key from an integer seed
    # We convert the int to string/bytes then hash it to get a 16-byte key
    aes_key = hashlib.sha256(str(seed).encode()).digest()[:16]
    
    # 1) Load database 
    db = [int(line) for line in DATASET_PATH.read_text().strip().split('\n')]
    if len(db) % 8:
        raise ValueError("File must contain blocks of size 128 bits, otherwise we need to pad.")

    # 2) Encode into as many plaintext blocks as needed (16 bytes each)
    packer = struct.Struct('>' + 'H' * len(db))
    plaintext_blocks = packer.pack(*db)

    if params.get_size() == 0:
        # 3) Encrypt using AES ECB mode
        aes = pyaes.AES(aes_key)
        ciphertext_blocks = aes.encrypt(plaintext_blocks)
    else:
        # 3) Encrypt using AES CTR mode
        # Generate a random IV
        IV = hashlib.sha256(b"iv"+str(seed).encode()).digest()[:16]
        IV_PATH.write_text(IV.hex())
        aes = pyaes.AESModeOfOperationCTR(aes_key, counter=pyaes.Counter(int.from_bytes(IV, byteorder='big')))
        ciphertext_blocks = aes.encrypt(plaintext_blocks)

    # 4) Store the AES key and the ciphertext
    AES_KEY_PATH.write_text(aes_key.hex())
    DATASET_ENC_PATH.write_text(bytes(ciphertext_blocks).hex())

if __name__ == "__main__":
    main()