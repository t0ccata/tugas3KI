import socket
import random
from base64 import b64encode, b64decode
import os
import threading
import time

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

class PKAServer:
    def __init__(self):
        self.public_keys = {}
        self.pka_public_key, self.pka_private_key = generate_keys()
        print("PKA Server keys generated")
        
    def store_public_key(self, client_id, public_key):
        self.public_keys[client_id] = {
            'key': public_key,
            'timestamp': time.time()
        }
        print(f"Stored public key for {client_id}")
        print(f"Current keys stored: {list(self.public_keys.keys())}")
        
    def get_public_key(self, client_id):
        if client_id in self.public_keys:
            key_data = self.public_keys[client_id]
            if time.time() - key_data['timestamp'] <= 7200:  # 2 hour validity
                return key_data['key']
        return None

def handle_client_connection(conn, addr, pka_server):
    print(f"New connection from {addr}")
    try:
        # Receive client ID
        client_id = conn.recv(1024).decode()
        print(f"Client ID received: {client_id}")
        
        # Receive public key
        public_key_data = conn.recv(1024).decode()
        e, n = map(int, public_key_data.split())
        pka_server.store_public_key(client_id, (e, n))
        
        # Send acknowledgment
        conn.send("Public key stored successfully".encode())
        
        # Handle key requests
        while True:
            request = conn.recv(1024).decode()
            if not request:
                break
                
            if request == "GET_PUBLIC_KEY":
                target_id = conn.recv(1024).decode()
                print(f"Request for {target_id}'s public key from {client_id}")
                target_key = pka_server.get_public_key(target_id)
                
                if target_key:
                    response = f"{target_key[0]} {target_key[1]}"
                    conn.send(response.encode())
                    print(f"Sent {target_id}'s public key")
                else:
                    conn.send("Public key not found".encode())
                    print(f"Public key not found for {target_id}")
            
            elif request == "EXIT":
                break
                
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()

def run_pka_server(host='127.0.0.1', port=6305):
    pka_server = PKAServer()
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"PKA Server running on {host}:{port}")

    while True:
        conn, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client_connection, args=(conn, addr, pka_server))
        thread.start()

if __name__ == "__main__":
    run_pka_server()