import socket
import time
from DES_CBC import des_cbc_encrypt_base64, des_cbc_decrypt_base64  
import RSA

def client_program():
    # PKA Server connection settings
    pka_host = '127.0.0.1'  # Change from localhost to explicit IP
    pka_port = 6305

    # DES Server connection settings 
    des_host = '127.0.0.1'  # Change from localhost to explicit IP
    des_port = 6304

    try:
        print("Connecting to PKA server...")
        pka_socket = socket.socket()
        pka_socket.connect((pka_host, pka_port))
        
        client_id = "client1"
        client_public_key, client_private_key = RSA.generate_keys()
        
        print("Sending client ID and public key to PKA...")
        pka_socket.send(client_id.encode())
        time.sleep(1)  # Small delay between sends
        pka_socket.send(f"{client_public_key[0]} {client_public_key[1]}".encode())
        
        ack = pka_socket.recv(1024).decode()
        print(f"Received PKA response: {ack}")
        
        if (ack != "Public key stored successfully"):
            print("Failed to store public key on PKA server.")
            return
            
        pka_socket.close()
        time.sleep(2)  # Wait before connecting to DES server
        
        print("\nConnecting to DES server...")
        client_socket = socket.socket()
        client_socket.connect((des_host, des_port))
        
        # Send public key to DES server
        client_socket.send(f"{client_public_key[0]} {client_public_key[1]}".encode())
        
        # Get server's public key
        server_public_key_data = client_socket.recv(1024).decode()
        server_e, server_n = map(int, server_public_key_data.split())
        
        # Generate and encrypt DES key
        des_key = RSA.generate_des_key()
        encrypted_des_key_with_private = RSA.encrypt(client_private_key, des_key)
        encrypted_des_key = RSA.encrypt((server_e, server_n), str(encrypted_des_key_with_private))
        client_socket.send(str(encrypted_des_key).encode())  # Kirim sebagai string
        
        # Continue with existing code...
        
        iv = "initvect"  
    
        message = input(" -> ")
    
        while message.lower().strip() != 'bye':
        
            encrypted_message = des_cbc_encrypt_base64(message, des_key, iv)
            print("Sending encrypted message:", encrypted_message)
            client_socket.send(encrypted_message.encode())  

            encrypted_response = client_socket.recv(1024).decode()
            if not encrypted_response:
                break
        
            decrypted_response = des_cbc_decrypt_base64(encrypted_response, des_key, iv)
            print("Received decrypted response:", decrypted_response)

            message = input(" -> ")  

        client_socket.close()  

    except ConnectionRefusedError:
        print(f"Connection refused. Please ensure both servers are running:")
        print("1. PKA Server (python RSA.py) on port 6305")
        print("2. DES Server (python server2.py) on port 6304")
    except Exception as e:
        print(f"Error occurred: {str(e)}")
    finally:
        try:
            pka_socket.close()
        except:
            pass
        try:
            client_socket.close()
        except:
            pass

if __name__ == '__main__':
    client_program()