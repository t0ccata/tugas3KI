import socket
import random
from base64 import b64encode, b64decode
import os
import threading

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
    
    if isinstance(plaintext, bytes):
        
        plaintext_int = int.from_bytes(plaintext, 'big')
    elif isinstance(plaintext, str):
        
        plaintext_bytes = plaintext.encode('utf-8')
        plaintext_int = int.from_bytes(plaintext_bytes, 'big')
    else:
        raise ValueError("Plaintext must be a string or bytes")
    
    ciphertext_int = pow(plaintext_int, e, n)
    return ciphertext_int

def decrypt(private_key, ciphertext):
    d, n = private_key
    if isinstance(ciphertext, int):
        plaintext_int = pow(ciphertext, d, n)
    else:
        raise ValueError("Ciphertext must be an integer")
    plaintext_bytes = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big')
    return plaintext_bytes

def generate_des_key():
    
    return os.urandom(8)


def des_encrypt(key, plaintext):
    
    return plaintext  

def des_decrypt(key, ciphertext):
    
    return ciphertext

# Dictionary to store public keys with client identifiers
public_keys = {}

def store_public_key(client_id, public_key):
    public_keys[client_id] = public_key

def get_public_key(client_id):
    return public_keys.get(client_id)

def handle_client_connection(conn, addr):
    print(f"Connection from: {addr}")
    client_id = conn.recv(1024).decode()
    public_key_data = conn.recv(1024).decode()
    e, n = map(int, public_key_data.split())
    store_public_key(client_id, (e, n))
    print(f"Stored public key for client {client_id}")
    
    # Send acknowledgment to client
    conn.send("Public key stored successfully".encode())

    while True:
        request = conn.recv(1024).decode()
        if request == "GET_PUBLIC_KEY":
            target_client_id = conn.recv(1024).decode()
            target_public_key = get_public_key(target_client_id)
            if target_public_key:
                conn.send(f"{target_public_key[0]} {target_public_key[1]}".encode())
            else:
                conn.send("Public key not found".encode())
        elif request == "EXIT":
            break

    conn.close()

def run_pka_server(host='127.0.0.1', port=6305):  # Change from localhost
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Public Key Authority server running on {host}:{port}")

    while True:
        conn, addr = server_socket.accept()
        client_handler = threading.Thread(target=handle_client_connection, args=(conn, addr))
        client_handler.start()

if __name__ == "__main__":
    run_pka_server()