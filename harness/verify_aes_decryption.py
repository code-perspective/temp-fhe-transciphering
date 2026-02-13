#!/usr/bin/env python3

# Copyright (c) 2025 HomomorphicEncryption.org
# All rights reserved.
#
# This software is licensed under the terms of the Apache v2 License.
# See the LICENSE.md file for details.

"""
verify_aes_decryption.py - correctness oracle for AES decryptions
"""

import sys
from pathlib import Path

def main():

    """
    Usage:  python3 verify_aes_decryption.py  <expected_file>  <result_file>
    Returns exit-code 0 if equal, 1 otherwise.
    Prints a message so the caller can log it.
    """

    if len(sys.argv) != 3:
        sys.exit("Usage: verify_aes_decryption.py <expected> <result>")

    expected_file = Path(sys.argv[1])
    result_file   = Path(sys.argv[2])

    try:
        exp = list(map(int, expected_file.read_text().split()))
        res = list(map(int, result_file.read_text().split()))
    except Exception as e:
        print(f"[harness] failed to read files: {e}")
        sys.exit(1)

    if exp == res:
        print(f"[harness] PASS AES Decryption  (expected={exp}, got={res})")
        sys.exit(0)
    else:
        print(f"[harness] FAIL AES Decryption  (expected={exp}, got={res})")
        sys.exit(1)

if __name__ == "__main__":
    main()