import os
import hashlib
from sympy.ntheory.factor_ import totient
import math

from Crypto.Util import number

def sha256_hash(filename):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as file:
        while True:
            data = file.read(65536)  # Read in 64 KB chunks
            if not data:
                break
            sha256.update(data)
    return sha256.digest()

def generate_random_semiprime(bits=1024):
    while True:
        p= number.getPrime(bits)
        q= number.getPrime(bits)
        if p != q:
            return [p,q,p * q]

def mod_inverse(e, phi):
    if math.gcd(e, phi) != 1:
        raise ValueError("The modular inverse does not exist.")
    return pow(e,-1,phi)

def rsa_sign(sha256_hash, p, q, e=65537):
    phi = (p-1)*(q-1)
    d = mod_inverse(e, phi)
    N=p*q
    signature = pow(int.from_bytes(sha256_hash, byteorder='big'), d, N)
    return hex(signature)

def main():
    filename = input("Enter the name of the text file: ")
    if not os.path.isfile(filename):
        print("File not found.")
        return

    N_pq = generate_random_semiprime()
    hash_value = sha256_hash(filename)
    signature_hex = rsa_sign(hash_value, N_pq[0], N_pq[1])

    print("Digital signature of the file:")
    print("N:", N_pq[2])
    print("e:", 65537)
    print("Signature (hex):", signature_hex)

if __name__ == "__main__":
    main()
