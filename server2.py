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

    public_key, private_key = RSA.generate_keys()
    
    conn.send(f"{public_key[0]} {public_key[1]}".encode())
    
    encrpypted_des_key = int(conn.recv(1024).decode())
    des_key = RSA.decrypt(private_key, encrpypted_des_key)
    
    # key = "mysecret"  
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
