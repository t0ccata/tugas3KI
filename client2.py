import socket
import time
from DES_CBC import des_cbc_encrypt_base64, des_cbc_decrypt_base64  
import RSA

def client_program():
    pka_host = '127.0.0.1'
    pka_port = 6305
    des_host = '127.0.0.1'
    des_port = 6304

    try:
        # First connect to PKA with timeout
        print("Connecting to PKA server...")
        pka_socket = socket.socket()
        pka_socket.settimeout(5)  # Add 5 second timeout
        try:
            pka_socket.connect((pka_host, pka_port))
        except socket.error as e:
            print(f"Failed to connect to PKA server: {e}")
            print("Make sure PKA server (RSA.py) is running first")
            return
        
        # Reset timeout after connection
        pka_socket.settimeout(None)
        
        # Continue with existing code...
        client_id = "client1"
        client_public_key, client_private_key = RSA.generate_keys()
        
        print("Sending registration to PKA...")
        pka_socket.send(client_id.encode())
        pka_socket.send(f"{client_public_key[0]} {client_public_key[1]}".encode())
        
        # Add timeout for receiving acknowledgment
        pka_socket.settimeout(5)
        try:
            ack = pka_socket.recv(1024).decode()
        except socket.timeout:
            print("Timeout waiting for PKA server response")
            return
            
        if ack != "Public key stored successfully":
            print("Failed to register with PKA")
            return
            
        # Connect to DES server
        print("\nConnecting to DES server...")
        client_socket = socket.socket()
        client_socket.connect((des_host, des_port))
        
        # Send handshake request
        handshake = "HANDSHAKE_REQUEST"
        client_socket.send(handshake.encode())
        
        # Get server's public key from PKA
        pka_socket.send("GET_PUBLIC_KEY".encode())
        pka_socket.send("server1".encode())
        server_public_key_data = pka_socket.recv(1024).decode()
        
        if server_public_key_data == "Public key not found":
            print("Server public key not found in PKA")
            return
            
        server_e, server_n = map(int, server_public_key_data.split())
        
        # Generate and encrypt DES key
        des_key = RSA.generate_des_key()
        encrypted_des_key = RSA.encrypt((server_e, server_n), des_key)
        
        # Send encrypted DES key to server
        client_socket.send(str(encrypted_des_key).encode())
        
        session_start = time.time()
        iv = "initvect"
        
        print("Handshake completed, starting secure communication...")
        
        while True:
            # Check session timeout (2 hours = 7200 seconds)
            if time.time() - session_start > 7200:
                print("Session expired. Need to perform handshake again.")
                break
                
            message = input(" -> ")
            if message.lower().strip() == 'bye':
                break
                
            try:
                encrypted_message = des_cbc_encrypt_base64(message, des_key, iv)
                print("Sending encrypted message:", encrypted_message)
                client_socket.send(encrypted_message.encode())
                
                # Wait for server response with timeout
                client_socket.settimeout(20)
                try:
                    encrypted_response = client_socket.recv(1024).decode()
                    if encrypted_response:
                        decrypted_response = des_cbc_decrypt_base64(encrypted_response, des_key, iv)
                        print("Server response:", decrypted_response)
                except socket.timeout:
                    print("No response from server")
                    
            except Exception as e:
                print(f"Error sending message: {str(e)}")
                break

    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        try:
            pka_socket.close()
            client_socket.close()
        except:
            pass

if __name__ == '_main_':
    client_program()