# README Tugas 3 KI

## Deskripsi
Pengembangan program Percakapan antara dua perangkat dari Tugas 2:
1. Implementasi Pengiriman key DES pada percakapan menggunakan algoritma RSA
2. Public key dari RSA harus diperoleh melalui Public Key Authority
3. Pengiriman Key DES harus menggunakan Public-Key Cryptosystems
4. disarankan berkelompok maksimal 2 orang dan yang sudah berkelompok pada tugas kemarin, silahkan melanjutkan
5. Commit github menjadi pertimbangan nilai per individu
6. Mencantumkan deskripsi pembagian kerja pada README
7. Dilarang plagiasi 

Untuk penjelasan lebih detail : https://youtube.com/live/VKuzjIfBF-M.
Silahkan mengisi sheet q&a berikut ada yang ditanyakan: https://docs.google.com/spreadsheets/d/1kq_aOs15XZPgHbz0qq0IMjE2Gqt9IvEA7nM2RCnysQA/edit?usp=sharing

Form pengumpulan: https://its.id/m/PengumpulanTugas3KI
Deadline: Kamis, 21 Nov 2024, 23:59 WIB
Demo: Jumat, 22 Nov - Minggu, 24 Nov 2024

## Fitur
- **Enkripsi RSA**: Menggunakan algoritma RSA untuk mengenkripsi kunci DES.
- **Enkripsi DES**: Menggunakan algoritma DES dalam mode CBC untuk mengenkripsi pesan.
- **Komunikasi Klien-Server**: Klien dapat mengirim pesan terenkripsi ke server, dan server dapat mendekripsi pesan tersebut.

## Struktur
# Implementasi algoritma RSA.
RSA.py 
# Implementasi algoritma DES dalam mode CBC.
DES_CBC.py
# Kode untuk klien yang mengirim pesan.
client2.py
# Kode untuk server yang menerima dan mendekripsi pesan.
server2.py


## Prerequisites
Pastikan Anda memiliki Python 3.x terinstal di sistem Anda. Anda juga perlu menginstal pustaka yang diperlukan, jika ada.

## Cara Menjalankan
1. **Jalankan Server**:
   - Buka terminal dan navigasikan ke direktori proyek.
   - Jalankan perintah berikut untuk memulai server:
     ```bash
     python server2.py
     ```

2. **Jalankan Klien**:
   - Buka terminal baru dan navigasikan ke direktori proyek.
   - Jalankan perintah berikut untuk memulai klien:
     ```bash
     python client2.py
     ```

3. **Interaksi**:
   - Klien akan meminta input pesan untuk dikirim ke server.
   - Server akan menerima pesan dan mendekripsinya, kemudian menampilkan pesan asli.

## Catatan
- Pastikan untuk memeriksa dan mengonfigurasi alamat IP dan port yang digunakan dalam kode klien dan server agar sesuai dengan pengaturan jaringan Anda.
- Jika ada kesalahan atau masalah, periksa kembali kode dan pastikan semua dependensi telah terinstal dengan benar.

## Lisensi
Proyek ini dilisensikan di bawah [Lisensi MIT](LICENSE).