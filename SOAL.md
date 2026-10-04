# Filtered Login
**Category:** Web Exploitation
**Difficulty:** Low
**Points:** 100

## Deskripsi

Setelah insiden sebelumnya, tim developer bilang mereka sudah "memperbaiki" bug SQL Injection dengan memblokir kata `OR`. Mereka sangat percaya diri sekarang sistemnya aman.

Buktikan filter mereka tidak cukup.

**Target:** `http://localhost:5000/`

## Objektif

Login sebagai `admin` tanpa tahu passwordnya, meski ada filter keamanan yang memblokir kata `OR`, lalu ambil flag-nya.

## Format Flag

```
CTF{...}
```

## Hint

- 1 (-10 pts): Ini masih SQL Injection yang sama seperti biasa. Masalahnya cuma ada filter yang mendeteksi string `" or "` (dengan spasi) di input kamu.
- 2 (-15 pts): Filter itu mendeteksi berdasarkan string literal. Apakah ada cara menulis ulang query SQL yang secara fungsional sama tapi tidak mengandung kata `OR` dengan spasi di sekitarnya?
- 3 (-25 pts): SQL punya sintaks komentar inline `/**/` yang bisa dipakai sebagai pengganti spasi tanpa mengubah arti query. Coba ganti semua spasi di payload-mu dengan `/**/`.
- 4 (-10 pts): Sama seperti challenge sebelumnya — setelah berhasil login sebagai admin, cek halaman pengaturan dan `robots.txt`. Flag kali ini di-encode **hex**, bukan base64.
