import socket
from DES import des_encrypt as des_enc, des_decrypt as des_dec, key as des_key
from RSA import rsa_encrypt as rsa_enc, rsa_decrypt as rsa_dec
from PKA import (
    create_random_num as gen_rand_num, 
    get_server_pub_key as req_srv_pub_key, 
    pka_pub_key as pka_pub_key, 
    validate_signature as verify_sig, 
    sign_data as sign_k
)

# Kunci untuk Klien
client_pub_key = (2537, 13)  # (n, e)
client_priv_key = (2537, 937)  # (n, d)

def run_client():
    host_name = socket.gethostname()  
    srv_port = 5050  

    client_sock = socket.socket()  
    client_sock.connect((host_name, srv_port))

    serialized_srv_key, srv_signature = req_srv_pub_key()
    print("Dapatkan kunci publik server (dari PKA): ", serialized_srv_key)
    print("Dapatkan tanda tangan (dari PKA): ", srv_signature)

    if verify_sig(serialized_srv_key, srv_signature, pka_pub_key):
        print("Kunci publik server berhasil diverifikasi.")
        print("Kunci publik server yang diterima: ", serialized_srv_key)

        srv_key_parts = serialized_srv_key.split(":")
        srv_pub_key = (int(srv_key_parts[0]), int(srv_key_parts[1]))
        print("Kunci Publik Server yang Diverifikasi:", srv_pub_key)
        
    else:
        print("Verifikasi gagal. Tutup koneksi.")
        client_sock.close()
        return

    encrypted_nonce1 = list(map(int, client_sock.recv(1024).decode().split(',')))
    print("Terima encrypted N1 (Dari server): ", encrypted_nonce1)

    decrypted_nonce1 = rsa_dec(encrypted_nonce1, client_priv_key)
    print("Dekripsi N1:", decrypted_nonce1)

    nonce2 = gen_rand_num()
    print("Nomor acak N2: ", nonce2)

    enc_nonce1_back = rsa_enc(decrypted_nonce1, srv_pub_key)
    print("Encrypt ulang N1: ", enc_nonce1_back)
    enc_nonce1_back_str = ','.join(map(str, enc_nonce1_back))

    enc_nonce2 = rsa_enc(str(nonce2), srv_pub_key)
    print("Encrypt N2: ", enc_nonce2)
    enc_nonce2_str = ','.join(map(str, enc_nonce2))

    client_sock.send(enc_nonce1_back_str.encode())
    client_sock.send(enc_nonce2_str.encode())
    print("Status: N1 dan N2 terkirim ke server")

    srv_response = list(map(int, client_sock.recv(1024).decode().split(',')))
    print("Terima encrypted N2 dari server: ", srv_response)
    decrypted_nonce2 = rsa_dec(srv_response, client_priv_key)
    print("Dekripsi N2 dari server: ", decrypted_nonce2)

    if decrypted_nonce2 == str(nonce2):
        print("Handshaking berhasil!")
    else:
        print("Handshaking gagal!")
        client_sock.close()
        return

    print("Des Key diperoleh: ", des_key)
    signed_des_key, des_sig = sign_k(des_key, client_priv_key)
    des_key_str = str(signed_des_key)
    des_sig_str = ','.join(map(str, des_sig))
        
    client_sock.send(des_key_str.encode())
    client_sock.send(des_sig_str.encode())

    enc_des_key = rsa_enc(des_key, srv_pub_key)
    print("Encrypted Des Key: ", enc_des_key)
    enc_des_key_str = ','.join(map(str, enc_des_key))
    client_sock.send(enc_des_key_str.encode())

    while True:
        msg = input("Masukkan pesan: ")
        if msg.lower().strip() == 'stop':
            break
        enc_msg_sent = des_enc(msg, des_key)
        client_sock.send(enc_msg_sent.encode())
        data = client_sock.recv(1024).decode()
        decrypted_data = des_dec(data, des_key)
        enc_bin_msg = ''.join(format(ord(c), '08b') for c in data)
        print("Pesan terenkripsi dari server (biner):", enc_bin_msg)
        print("Pesan dari server (setelah dekripsi): " + decrypted_data)

    client_sock.close()


if __name__ == '__main__':
    run_client()
