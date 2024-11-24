import socket
from DES_CBC import des_cbc_decrypt_base64, des_cbc_encrypt_base64
import RSA

def server_program():
    host = '127.0.0.1'
    port = 6304  

    server_socket = socket.socket()
    server_socket.bind((host, port))  
    print(f"DES Server started on {host}:{port}")

    server_socket.listen(2)
    conn, address = server_socket.accept()  
    print("Connection from: " + str(address))

    try:
        # Exchange public keys
        server_public_key, server_private_key = RSA.generate_keys()
        conn.send(f"{server_public_key[0]} {server_public_key[1]}".encode())
        print("Sent server public key")

        client_public_key_data = conn.recv(1024).decode()
        if not client_public_key_data:
            print("Failed to receive client's public key.")
            return

        print("Received client public key:", client_public_key_data)
        client_e, client_n = map(int, client_public_key_data.split())

        # Receive encrypted DES key
        encrypted_des_key = conn.recv(1024).decode()
        if not encrypted_des_key:
            print("No DES key received.")
            return

        print("Received encrypted DES key:", encrypted_des_key)

        try:
            import base64
            # First decode base64 to bytes
            encrypted_des_key_bytes = base64.b64decode(encrypted_des_key)
            # Convert bytes to integer
            encrypted_des_key_int = int.from_bytes(encrypted_des_key_bytes, 'big')
            # Decrypt the DES key
            des_key = RSA.decrypt(server_private_key, encrypted_des_key_int)

            print("DES key successfully decrypted")
            
            # Communication loop
            iv = "initvect"   
            print("\nWaiting for messages...")
            
            while True:
                try:
                    encrypted_message = conn.recv(1024).decode()
                    if not encrypted_message:
                        print("Connection closed by client")
                        break

                    print(f"\nReceived encrypted message: {encrypted_message}")
                    decrypted_message = des_cbc_decrypt_base64(encrypted_message, des_key, iv)
                    print(f"Decrypted message: {decrypted_message}")

                    response = input("Enter response -> ")
                    if response.lower().strip() in ['exit', 'quit', 'bye']:
                        break
                        
                    encrypted_response = des_cbc_encrypt_base64(response, des_key, iv)
                    conn.send(encrypted_response.encode())
                    print("Response sent")

                except Exception as e:
                    print(f"Error in message exchange: {str(e)}")
                    break

        except Exception as e:
            print(f"Error processing DES key: {str(e)}")
            return

    except Exception as e:
        print(f"Server error: {str(e)}")
    finally:
        conn.close()
        print("\nConnection closed")

if __name__ == '__main__':
    server_program()