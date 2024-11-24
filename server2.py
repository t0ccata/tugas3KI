import socket
from DES_CBC import des_cbc_decrypt_base64, des_cbc_encrypt_base64
import RSA

def server_program():
    host = '127.0.0.1'
    port = 6304  

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")
    while True:
        conn, address = server_socket.accept()  
        print("Connection from: " + str(address))

        try:
            # Get PKA's public key first
            pka_socket = socket.socket()
            pka_socket.connect((host, 6305))
            
            # Register server's keys with PKA
            server_id = "server1"
            server_public_key, server_private_key = RSA.generate_keys()
            
            pka_socket.send(server_id.encode())
            pka_socket.send(f"{server_public_key[0]} {server_public_key[1]}".encode())
            
            ack = pka_socket.recv(1024).decode()
            if ack != "Public key stored successfully":
                print("Failed to register with PKA")
                return

            # Receive handshake request from client
            handshake_request = conn.recv(1024).decode()
            
            # Get client's public key from PKA
            pka_socket.send("GET_PUBLIC_KEY".encode())
            pka_socket.send("client1".encode())
            client_public_key_data = pka_socket.recv(1024).decode()
            
            if client_public_key_data == "Public key not found":
                print("Client public key not found in PKA")
                return
                
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
                        # Clear receive buffer
                        conn.settimeout(1)  # Add timeout for receiving messages
                        encrypted_message = conn.recv(1024).decode().strip()
                        
                        if encrypted_message:
                            print(f"\nReceived encrypted message: {encrypted_message}")
                            try:
                                decrypted_message = des_cbc_decrypt_base64(encrypted_message, des_key, iv)
                                print(f"Decrypted message: {decrypted_message}")

                                response = input("Enter response -> ")
                                if response.lower().strip() in ['exit', 'quit', 'bye']:
                                    break
                                    
                                encrypted_response = des_cbc_encrypt_base64(response, des_key, iv)
                                conn.send(encrypted_response.encode())
                                print("Response sent")
                            except Exception as e:
                                print(f"Error processing message: {str(e)}")
                                continue
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        print(f"Connection error: {str(e)}")
                        break

            except Exception as e:
                print(f"Error processing DES key: {str(e)}")
                return

        except Exception as e:
            print(f"Server error: {str(e)}")
        finally:
            conn.close()
            pka_socket.close()
            print("\nConnection closed")

if __name__ == '_main_':
    server_program()