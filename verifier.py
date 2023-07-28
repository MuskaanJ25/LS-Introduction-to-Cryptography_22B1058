import hashlib
import os

def sha256_hash(filename):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as file:
        while True:
            data = file.read(65536)  # Read in 64 KB chunks
            if not data:
                break
            sha256.update(data)
    return sha256.digest()

def rsa_verify(sha256_hash, N, e, signature_hex):
    signature = int(signature_hex, 16)
    decrypted_signature = pow(signature, e, N)
    original_hash = int.from_bytes(sha256_hash, byteorder='big')
    return decrypted_signature == original_hash

def main():
    filename = input("Enter the name of the text file: ")
    if not os.path.isfile(filename):
        print("File not found.")
        return

    N = int(input("Enter N (semiprime): "))
    e = int(input("Enter e (public exponent): "))
    signature_hex = input("Enter the signature (hex): ")

    hash_value = sha256_hash(filename)
    is_valid = rsa_verify(hash_value, N, e, signature_hex)

    if is_valid:
        print("accept")
    else:
        print("reject")

if __name__ == "__main__":
    main()

