## AES Transciphering

TODO: Add description

## Workload steps

1. harness: generate message to be encrypted
    - Max of 16-bit integers (Toy: 8, Small: 64 , Medium: 512)
    - Inner product of vectors of int16 mod 2^16 (Toy: 4, Small: 32 , Medium: 256)
2. harness: Generate AES Key 
3. harness: Encrypt message with AES key
4. submission-client: Keygen (FHE Key)
5. submission-client: pre-processing (key expansion will be here)
6. submission-client: encode-encrypt  (AES key with FHE Key)
7. Submission-server: encrypted_transciphering for homomorphically evaluating the AES decryption circuit on message in step3 with FHE(AES key) in step 6
8. Submission-server: Encrypted computation to be performed as defined by the harness
    - CGGI - Max function
    - CKKS - Inner product
9. Submission - client: transciphering Decrypt+Decode 
10. Submission - client: transciphering postprocess (to reconstitute message in step 1)
11. Submission: decrypt_decode
12. Submission: post_process (to reconstitute the final expected output)
13. Harness: verify transciphering output (from step 10)
14. Harness: verify final output (step 12)
