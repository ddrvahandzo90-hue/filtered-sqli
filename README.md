# Filtered Login - CTF Web Exploitation (Low)

Challenge ini adalah "lanjutan" dari **Baby Login**: SQLi yang sama, tapi kali ini
dilindungi filter blacklist naif yang memblokir kata `OR`. Peserta harus
menemukan cara bypass filter (pakai komentar SQL `/**/` sebagai pengganti spasi).

## Menjalankan challenge

### Opsi 1: Langsung (Python)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLAG="CTF{ganti_flag_ini_sebelum_event}"
python app.py
```
Buka `http://localhost:5000`

### Opsi 2: Docker
```bash
docker build -t filtered-login .
docker run -p 5000:5000 -e FLAG="CTF{ganti_flag_ini_sebelum_event}" filtered-login
```

## Struktur file
```
app.py              # source aplikasi (vulnerable) - jangan dibagikan ke peserta
templates/
  login.html
  success.html
  admin_settings.html
requirements.txt
Dockerfile
SOAL.md             # deskripsi soal untuk peserta
WRITEUP.md          # solusi untuk panitia
```

## Alur solve (ringkas)
1. Coba payload SQLi klasik `admin' OR '1'='1` → **diblokir** oleh filter.
2. Ganti spasi di sekitar `OR` dengan `/**/` → `admin'/**/OR/**/'1'='1` → **berhasil** bypass filter & login sebagai admin.
3. Cek `robots.txt` → ada hint path `/admin-settings`.
4. Buka `/admin-settings` (session admin tersimpan) → flag muncul dalam bentuk **hex**.
5. Decode hex → flag asli.

## Catatan sebelum deploy ke event
1. **Ganti FLAG** di environment variable, jangan pakai default.
2. Jangan expose `app.py` / source code ke peserta.
3. `debug=False` sudah default, jangan diubah.
4. Disarankan deploy per-tim terisolasi (Docker per instance) agar database SQLite tidak saling bertabrakan.
