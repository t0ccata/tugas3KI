import socket
import random
from base64 import b64encode, b64decode
import os

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    for x in range(1, phi):
        if (e * x) % phi == 1:
            return x
    return None

def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime():
    while True:
        num = random.randint(100, 200)
        if is_prime(num):
            return num

def generate_keys():
    p = generate_prime()
    q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537  
    while gcd(e, phi) != 1:
        e = random.randint(2, phi)

    d = mod_inverse(e, phi)
    return (e, n), (d, n)  

def encrypt(public_key, plaintext):
    e, n = public_key
    plaintext_bytes = plaintext.encode('utf-8')
    plaintext_int = int.from_bytes(plaintext_bytes, 'big')
    ciphertext_int = pow(plaintext_int, e, n)
    return ciphertext_int

def decrypt(private_key, ciphertext):
    d, n = private_key
    plaintext_int = pow(ciphertext, d, n)
    plaintext_bytes = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big')
    return plaintext_bytes.decode('utf-8')

def generate_des_key():
    
    return os.urandom(8)


def des_encrypt(key, plaintext):
    
    return plaintext  

def des_decrypt(key, ciphertext):
    
    return ciphertext  