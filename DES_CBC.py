import numpy as np
import base64


INITIAL_PERMUTATION = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]


FINAL_PERMUTATION = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]


def permute(block, table):
    return [block[x - 1] for x in table]


def string_to_bits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:].rjust(8, '0')
        result.extend([int(b) for b in bits])
    return result


def bits_to_string(b):
    chars = []
    for i in range(0, len(b), 8):
        byte = b[i:i+8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)


def des_encrypt_block(plaintext_block, key):
    
    permuted_block = permute(plaintext_block, INITIAL_PERMUTATION)
    
    final_block = permute(permuted_block, FINAL_PERMUTATION)
    return final_block

def des_decrypt_block(ciphertext_block, key):
    
    
    permuted_block = permute(ciphertext_block, INITIAL_PERMUTATION)
    
    
    
    
    final_block = permute(permuted_block, FINAL_PERMUTATION)
    return final_block


def xor_bits(a, b):
    return [i ^ j for i, j in zip(a, b)]


def pad(text, block_size):
    padding_len = block_size - len(text) % block_size
    return text + chr(padding_len) * padding_len


def unpad(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]


def des_cbc_encrypt(plaintext, key, iv):
    
    plaintext = pad(plaintext, 8)
    
    
    plaintext_bits = string_to_bits(plaintext)
    iv_bits = string_to_bits(iv)
    
    
    blocks = [plaintext_bits[i:i+64] for i in range(0, len(plaintext_bits), 64)]
    
    ciphertext_bits = []
    prev_block = iv_bits
    for block in blocks:
        
        block = xor_bits(block, prev_block)
        
        
        encrypted_block = des_encrypt_block(block, key)
        
        
        ciphertext_bits.extend(encrypted_block)
        
        
        prev_block = encrypted_block
    
    
    ciphertext = bits_to_string(ciphertext_bits)
    return ciphertext


def des_cbc_decrypt(ciphertext, key, iv):
    
    ciphertext_bits = string_to_bits(ciphertext)
    iv_bits = string_to_bits(iv)
    
    
    blocks = [ciphertext_bits[i:i+64] for i in range(0, len(ciphertext_bits), 64)]
    
    plaintext_bits = []
    prev_block = iv_bits
    for block in blocks:
        
        decrypted_block = des_decrypt_block(block, key)
        
        
        plaintext_block = xor_bits(decrypted_block, prev_block)
        
        
        plaintext_bits.extend(plaintext_block)
        
        
        prev_block = block
    
    
    plaintext = bits_to_string(plaintext_bits)
    
    
    return unpad(plaintext)

def bits_to_base64(bits):
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        byte_array.append(int(''.join([str(bit) for bit in byte]), 2))
    return base64.b64encode(byte_array).decode('utf-8')

def base64_to_bits(base64_string):
    byte_array = base64.b64decode(base64_string)
    bits = []
    for byte in byte_array:
        bits.extend([int(bit) for bit in bin(byte)[2:].rjust(8, '0')])
    return bits

def des_cbc_encrypt_base64(plaintext, key, iv):
    
    plaintext = pad(plaintext, 8)
    
    
    plaintext_bits = string_to_bits(plaintext)
    iv_bits = string_to_bits(iv)
    
    
    blocks = [plaintext_bits[i:i+64] for i in range(0, len(plaintext_bits), 64)]
    
    ciphertext_bits = []
    prev_block = iv_bits
    for block in blocks:
        
        block = xor_bits(block, prev_block)
        
        
        encrypted_block = des_encrypt_block(block, key)
        
        
        ciphertext_bits.extend(encrypted_block)
        
        
        prev_block = encrypted_block
    
    
    ciphertext_base64 = bits_to_base64(ciphertext_bits)
    return ciphertext_base64

def des_cbc_decrypt_base64(ciphertext_base64, key, iv):
    
    ciphertext_bits = base64_to_bits(ciphertext_base64)
    iv_bits = string_to_bits(iv)
    
    
    blocks = [ciphertext_bits[i:i+64] for i in range(0, len(ciphertext_bits), 64)]
    
    plaintext_bits = []
    prev_block = iv_bits
    for block in blocks:
        
        decrypted_block = des_decrypt_block(block, key)
        
        
        plaintext_block = xor_bits(decrypted_block, prev_block)
        
        
        plaintext_bits.extend(plaintext_block)
        
        
        prev_block = block
    
    
    plaintext = bits_to_string(plaintext_bits)
    
    
    return unpad(plaintext)

# key = 'mysecret'  
# iv = 'initvect'   
# plaintext = "Muhammad Abdurrahman Faiz"

# print("plaintext: ", plaintext)


# ciphertext = des_cbc_encrypt_base64(plaintext, key, iv)
# print("Ciphertext:", ciphertext)


# decrypted_text = des_cbc_decrypt_base64(ciphertext, key, iv)
# print("Decrypted Text:", decrypted_text)