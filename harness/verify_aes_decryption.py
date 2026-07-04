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

def find_mismatches(list1, list2):
    """
    Compares two lists of integers and returns a list of tuples 
    containing the (index, value_from_list1, value_from_list2) where they differ.
    """
    mismatches = []
    
    # Determine the minimum length to avoid index out of bounds
    min_len = min(len(list1), len(list2))
    
    # Compare elements up to the length of the shorter list
    for i in range(min_len):
        if list1[i] != list2[i]:
            mismatches.append((i, list1[i], list2[i]))
            
    # If list1 is longer, add the remaining elements
    for i in range(min_len, len(list1)):
        mismatches.append((i, list1[i], None))
        
    # If list2 is longer, add the remaining elements
    for i in range(min_len, len(list2)):
        mismatches.append((i, None, list2[i]))
        
    return mismatches

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
        print(f"[harness] PASS AES Decryption")
        sys.exit(0)
    else:
        mismatches = find_mismatches(exp, res)
        print(f"[harness] FAIL AES Decryption  (find_mismatches): {mismatches}")
        sys.exit(1)

if __name__ == "__main__":
    main()