def rsa_encrypt(message, public_key):
    """
    Mengenkripsi pesan menggunakan algoritma RSA.

    Parameter:
    message (str): Pesan yang akan dienkripsi.
    public_key (tuple): Kunci publik berupa pasangan (n, e).

    Mengembalikan:
    list: Daftar bilangan bulat terenkripsi yang sesuai dengan karakter dalam pesan.
    """
    n, e = public_key  # Memisahkan modulus dan eksponen dari kunci publik
    encrypted_message = [pow(ord(char), e, n) for char in message]
    return encrypted_message


def rsa_decrypt(encrypted_message, private_key):
    """
    Mendekripsi pesan yang telah dienkripsi menggunakan algoritma RSA.

    Parameter:
    encrypted_message (list): Daftar bilangan bulat terenkripsi.
    private_key (tuple): Kunci privat berupa pasangan (n, d).

    Mengembalikan:
    str: Pesan asli setelah didekripsi.
    """
    n, d = private_key  # Memisahkan modulus dan eksponen dari kunci privat
    decrypted_message = ''.join([chr(pow(char, d, n)) for char in encrypted_message])
    return decrypted_message
