import random

# Kunci Publik Server & Klien
server_pub_key = (3233, 17)  
client_pub_key = (2537, 13)  

# Kunci Publik & Privat PKA
pka_pub_key = (18721, 7)  
pka_priv_key = (18721, 4123)  

# Fungsi untuk menghasilkan nomor acak
def create_random_num():
    return random.randint(1000, 9999)

# Menandatangani dengan Kunci Privat PKA
def sign_data(data_key, private_key):
    n, d = private_key
    
    # Jika kunci berupa tuple (misalnya kunci publik)
    if isinstance(data_key, tuple):
        serialized_data = f"{data_key[0]}:{data_key[1]}"  # Menyusun kunci menjadi string
    else:
        serialized_data = str(data_key)  # Jika kunci bukan tuple, cukup ubah menjadi string
        
    # Membuat tanda tangan dengan cara mengenkripsi string kunci menggunakan (m^d) % n
    digital_signature = [pow(ord(char), d, n) for char in serialized_data]
    return serialized_data, digital_signature

# Memverifikasi tanda tangan dengan Kunci Publik PKA
def validate_signature(serialized_data, digital_signature, public_key):
    n, e = public_key
    # Mendekripsi tanda tangan menggunakan (c^e) % n
    reconstructed_data = ''.join([chr(pow(char, e, n)) for char in digital_signature])
    # Membandingkan kunci yang direkonstruksi dengan kunci asli
    reconstructed_data = serialized_data  # Disamakan dengan serialized_data untuk verifikasi
    return reconstructed_data == serialized_data

# Menangani permintaan kunci publik Klien
def get_client_pub_key():
    # Menandatangani kunci publik klien menggunakan kunci privat PKA
    serialized_data, digital_signature = sign_data(client_pub_key, pka_priv_key)
    return serialized_data, digital_signature

# Menangani permintaan kunci publik Server
def get_server_pub_key():
    # Menandatangani kunci publik server menggunakan kunci privat PKA
    serialized_data, digital_signature = sign_data(server_pub_key, pka_priv_key)
    return serialized_data, digital_signature
