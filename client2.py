import socket
from DES_CBC import des_cbc_encrypt_base64, des_cbc_decrypt_base64  
import RSA

def client_program():
    host = socket.gethostname()  
    port = 6304  

    client_socket = socket.socket()  
    client_socket.connect((host, port))  

    
    client_public_key, client_private_key = RSA.generate_keys()
    
    
    client_socket.send(f"{client_public_key[0]} {client_public_key[1]}".encode())
    
    
    server_public_key_data = client_socket.recv(1024).decode()
    server_e, server_n = map(int, server_public_key_data.split())
    
    
    des_key = RSA.generate_des_key()  
    
    
    encrypted_des_key_with_private = RSA.encrypt(client_private_key, des_key)
    
    encrypted_des_key = RSA.encrypt((server_e, server_n), str(encrypted_des_key_with_private))
    
    
    client_socket.send(str(encrypted_des_key).encode())
    
    iv = "initvect"  
    
    message = input(" -> ")
    
    while message.lower().strip() != 'bye' and message.lower().strip() != 'exit':
        
        encrypted_message = des_cbc_encrypt_base64(message, des_key, iv)
        print("Sending encrypted message:", encrypted_message)
        client_socket.send(encrypted_message.encode())  

        data = client_socket.recv(1024).decode()
        print('Received from server (encrypted): ' + data)  
        
        if not data:
            break
        
        
        decrypted_response = des_cbc_decrypt_base64(data, des_key, iv)
        print("Decrypted message from server:", decrypted_response)  

        message = input(" -> ")  

    client_socket.close()  

if __name__ == '__main__':
    client_program()