import socket
from DES_CBC import des_cbc_decrypt_base64, des_cbc_encrypt_base64
import RSA

def server_program():
    host = socket.gethostname()
    port = 6304  

    server_socket = socket.socket()
    server_socket.bind((host, port))  

    server_socket.listen(2)
    conn, address = server_socket.accept()  
    print("Connection from: " + str(address))

    
    server_public_key, server_private_key = RSA.generate_keys()
    
    
    conn.send(f"{server_public_key[0]} {server_public_key[1]}".encode())
    
    
    client_public_key_data = conn.recv(1024).decode()
    client_e, client_n = map(int, client_public_key_data.split())
    
    
    encrypted_des_key = conn.recv(1024).decode()
    if not encrypted_des_key:
        print("No data received.")
        return
    
    encrypted_des_key = int(encrypted_des_key)
    
    
    decrypted_with_private = RSA.decrypt(server_private_key, encrypted_des_key)
    
    
    if isinstance(decrypted_with_private, bytes):
    
        decrypted_with_private_int = int.from_bytes(decrypted_with_private, 'big')
        des_key = RSA.decrypt((client_e, client_n), decrypted_with_private_int)
    else:
        raise ValueError("Decrypted result must be in bytes")
    
    iv = "initvect"   

    while True:
        data = conn.recv(1024).decode()
        if not data:
            break

        print("Received from client (encrypted): " + data)
        
        
        decrypted_message = des_cbc_decrypt_base64(data, des_key, iv)
        print("Decrypted message from client:", decrypted_message)

        response = input("Enter response -> ")
        
        encrypted_response = des_cbc_encrypt_base64(response, des_key, iv)
        conn.send(encrypted_response.encode())  

    conn.close()  

if __name__ == '__main__':
    server_program()