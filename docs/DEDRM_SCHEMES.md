# DeDRM_tools — DRM Schemes & Algorithms Reference

> Implementation reference distilled from the DeDRM_tools plugin suite
> (`external/DeDRM_tools`), intended as the specification for a standalone
> Rust CLI reimplementation. Every scheme below is documented at the level of
> byte offsets, constants, and key-derivation steps.

## 0. Scope & Architecture

DeDRM_tools is not a single algorithm but a **federation of decryptors**, one
per ebook ecosystem, sharing a small set of crypto primitives. The schemes:

| Scheme | Vendor | Container | Content cipher | Key source |
|---|---|---|---|---|
| Mobipocket | Amazon Kindle | PalmDB (`.mobi/.azw/.prc`) | PC1 stream | PID (device/serial derived) |
| Topaz | Amazon Kindle | TPZ0 container (`.tpz/.azw1`) | Topaz stream + zlib | PID |
| KFX/KDF | Amazon Kindle | KFX-ZIP / KDF SQLite (`.kfx-zip`) | AES-128-CBC via ION voucher | PID / voucher secrets |
| ADEPT EPUB | Adobe | EPUB (OCF ZIP) | AES-128-CBC + zlib | RSA user key |
| ADEPT PDF | Adobe | PDF | AES/RC4 | RSA user key |
| ignoble EPUB | Barnes & Noble | EPUB | AES + zlib | key from name+CC |
| ignoble PDF | Barnes & Noble | PDF | AES/RC4 | key from name+CC |
| eReader | Palm/Peanut Press | PalmDB (`.pdb`) | PC1 / DES + PalmDoc | key from name+CC |
| Kobo | Kobo | KEPUB (ZIP) | AES-128-CBC | device serial / user id |

### Dispatch layer (`DeDRM_plugin/__init__.py`, `run()`)

Format detection is **purely by file extension**; each handler then
brute-forces every stored key and, on total failure, tries live key-extraction
from the locally installed DRM app and retries.

| Extension | Handler | Schemes attempted (in order) |
|---|---|---|
| `prc, mobi, pobi, azw, azw1, azw3, azw4, tpz, kfx-zip` | `KindleMobiDecrypt` → `k4mobidedrm.GetDecryptedBook` | Mobipocket / Topaz / KFX (auto-detected internally) |
| `pdb` | `eReaderDecrypt` → `erdr2pml` | eReader |
| `pdf` | `PDFDecrypt` | B&N PDF, then Adobe ADEPT PDF |
| `epub` | `ePubDecrypt` | B&N ignoble **first**, then Adobe ADEPT |

Stored key buckets in prefs: `bandnkeys`, `adeptkeys`, `kindlekeys`,
`serials`, `pids`, `ereaderkeys`, `androidkeys`. The design cleanly separates
**key acquisition** (per-vendor, often platform-specific) from **content
decryption** (container parse + cipher) — mirror that split in Rust.

---

## 1. Shared Crypto Primitives

Source: `DeDRM_plugin/{aescbc,alfcrypto,python_des,openssl_des,pycrypto_des}.py`

> **Hazard:** the Python code intermixes `str`/`bytes` and uses
> `ord()`/`chr()` freely. The intended semantics are **byte-oriented**
> throughout — treat every "string" as `&[u8]`/`Vec<u8>` in Rust.

### 1.1 AES-CBC (`aescbc.py` = pure-Python Rijndael fallback; native = OpenSSL)

- **Cipher:** AES (Rijndael pinned to 16-byte blocks). Key 16/24/32 bytes →
  AES-128/192/256; rounds 10/12/14. Standard FIPS-197 (standard S-box, Rcon,
  MixColumns `2 3 1 1`, InvMixColumns `0E 0B 0D 09`, log/antilog GF(2^8) with
  generator 3).
- **Mode:** CBC. **No padding** in the DeDRM path (`noPadding()`), so data must
  be block-aligned.
- **IV quirk:** the pure-Python `AES_CBC.decrypt` prepends the IV as a fake
  first ciphertext block (`decrypt(iv + data)` with internal `iv=None`), which
  the CBC layer consumes as the IV and emits no output for. Net effect =
  **standard AES-128-CBC decryption of `data` with initialization vector
  `iv`**. In Rust: `aes` + `cbc` with `NoPadding` and explicit IV.

### 1.2 PC1 / Pukall Cipher (`alfcrypto.py`) — CUSTOM, port byte-for-byte

Self-synchronizing 16-bit-word stream cipher. Used by Mobipocket and (a
variant) by eReader.

- **Key:** exactly **16 bytes**, loaded as 8 **big-endian** 16-bit words:
  `wkey[i] = (key[2i] << 8) | key[2i+1]`. `wkey` is **mutated as state**.
- **Persistent state across all bytes:** `sum1=0`, `sum2=0`, `keyXorVal=0`.
- **Per input byte:**
  1. `temp1 = 0; byteXorVal = 0`
  2. for `j` in 0..7:
     - `temp1 ^= wkey[j]`
     - `sum2 = ((sum2 + j) * 20021 + sum1)`  *(compute wide)*
     - `sum1 = (temp1 * 346) & 0xFFFF`
     - `sum2 = (sum2 + sum1) & 0xFFFF`
     - `temp1 = (temp1 * 20021 + 1) & 0xFFFF`
     - `byteXorVal ^= temp1 ^ sum2`
  3. `cur = src[i]`
  4. **encrypt only:** `keyXorVal = cur * 257` *(before transform)*
  5. `cur = ((cur ^ (byteXorVal >> 8)) ^ byteXorVal) & 0xFF`
  6. **decrypt only:** `keyXorVal = cur * 257` *(after transform)*
  7. for `j` in 0..7: `wkey[j] ^= keyXorVal`
  8. output `cur`
- **Constants:** `20021, 346, 257 (0x101)`, masks `0xFFFF/0xFF`, 8 words, 16-byte
  key. No S-box. The encrypt/decrypt asymmetry (step 4 vs 6) ensures both feed
  the *plaintext* byte into the key mixing, making them inverse.

### 1.3 Topaz Cipher (`alfcrypto.py`) — CUSTOM, port byte-for-byte

32-bit stream cipher used by the Topaz format.

- **State:** two 32-bit words `(ctx1, ctx2)`; **seed `ctx1 = 0xCAFFE19E`**;
  **magic multiplier `0x0F902007`**; all arithmetic 32-bit wrapping.
- **Key init:** for each key byte `k`: `ctx2 = ctx1`;
  `ctx1 = ((ctx1>>2)*(ctx1>>7) & 0xFFFFFFFF) ^ ((k*k*0x0F902007) & 0xFFFFFFFF)`.
- **Decrypt:** for each cipher byte `d`:
  `m = d ^ ((ctx1>>3)&0xFF) ^ ((ctx2<<3)&0xFF)`; output `m`; then
  `ctx2 = ctx1`; `ctx1 = ((ctx1>>2)*(ctx1>>7) & 0xFFFFFFFF) ^ ((m*m*0x0F902007) & 0xFFFFFFFF)`.
- No IV/blocks/padding — pure byte stream, state feeds back recovered plaintext.

### 1.4 DES (`python_des.py` / `openssl_des.py` / `pycrypto_des.py`)

All three expose the same effective contract used by DeDRM: **DES-ECB decrypt,
8-byte key, 8-byte blocks, no padding** (iterate input 8 bytes at a time).
`python_des.py` is a full standard-table DES (also supports CBC/encrypt/pad-char
stripping, unused here). In Rust one `des` crate call in ECB/NoPadding covers
all three. Used by eReader and by Kindle key databases.

### 1.5 PBKDF2 (`alfcrypto.KeyIVGen`)

Standard **PBKDF2-HMAC-SHA1** (RFC 2898), 1-based big-endian block counter,
output truncated to requested length.

---
## 2. Amazon Kindle — Mobipocket (MOBI / AZW / PRC)

Source: `mobidedrm.py`, `kgenpids.py`, `kindlepid.py`, `k4mobidedrm.py`.

### 2.1 Container: PalmDB

Whole file read into memory. First 78 bytes = PalmDB header.

| Offset | Size | Field |
|---|---|---|
| 0x00 | 32 | DB name (NUL-terminated; fallback title) |
| 0x3C | 8 | type+creator "magic" — must be `BOOKMOBI` or `TEXtREAd` |
| 0x4C | 2 | num_sections (BE u16) |

Then record-info array at offset 78, one 8-byte entry per section:
`struct '>LBBBB'` → `offset` (BE u32, absolute), `flags` (u8), 3-byte unique id.
Section *n* spans `[sections[n].offset, sections[n+1].offset)`; last runs to EOF.
**All integers big-endian.**

### 2.2 Record 0 — PalmDoc + MOBI headers (offsets within section 0)

| Offset | Field | Notes |
|---|---|---|
| 0x00 | compression (u16) | 1=none, 2=PalmDoc, **17480 (0x4448)=HUFF/CDIC** |
| 0x08 | text record count → `records` | |
| 0x0C | encryption type (u16) | 0=none, 1=old Mobi, 2=Mobi PID |
| 0x10 | `MOBI` magic (implicit, unchecked) | |
| 0x14 | mobi_length (u32) | |
| 0x68 | mobi_version (u32) | |
| 0x80 | EXTH flags (u32) | bit 0x40 = EXTH present |
| 0xA8 | DRM block: drm_ptr, drm_count, drm_size, drm_flags (4×u32) | |
| 0xF2 | extra_data_flags (u16) | only if mobi_length≥0xE4 and mobi_version≥5 |

**extra_data_flags:** if compression != 17480, clear low bit (`&= 0xFFFE`) — the
multibyte trailing entry is then part of the encrypted region.

**EXTH** (at `16 + mobi_length` when flag 0x40 set): `"EXTH"` magic, header len
(u32), nitems (u32), then records of `type` (u32), `size` (u32, includes 8-byte
header), `size-8` content bytes → `meta_array[type]`. Notable types: **209**
(PID metadata blob), **503** (title), **406** (rental expiry — nonzero aborts),
401/404 (patched in place for clipping/TTS).

### 2.3 DRM scheme (encryption type 2)

Master constant: `keyvec1 = 72 38 33 B0 B4 F2 E3 CA DF 09 01 D6 E2 E0 3F 96` (16 B).

Per candidate PID (8 chars):
1. `bigpid = pid.ljust(16, b'\0')`
2. `temp_key = PC1(keyvec1, bigpid, decryption=False)` *(PC1 in **encrypt** mode)*
3. `temp_key_sum = sum(temp_key) & 0xFF`

DRM voucher array = `sect[drm_ptr : drm_ptr+drm_size]`, `drm_count` entries of
**48 bytes** each, `struct '>LLLBxxx32s'`:
`verification` (u32), `size` (u32), `type` (u32), `cksum` (u8), 3 pad,
`cookie` (32 B).

For each voucher where `cksum == temp_key_sum`:
- `cookie = PC1(temp_key, cookie)` *(decrypt)*
- unpack `'>LL16sLL'` → `ver`, `flags`, **`finalkey` (16 B)**, expiry, expiry2
- accept if `verification == ver` **and** `(flags & 0x1F) == 1` → `found_key = finalkey`

**Fallback (no PID):** retry with `temp_key = keyvec1`, `pid='00000000'`, and
only require `verification == ver` (drop the flags check).

**Type 1 (old Mobipocket):** fixed key `t1_keyvec = b'QDCVEPMU675RUBSZ'`;
`found_key = PC1(t1_keyvec, bookkey_data)` where bookkey_data is at section-0
offset 0x0E (`TEXtREAd`), 0x90 (version<0), or `mobi_length+16` (normal).

### 2.4 Record decryption

For text records `1..=records`: strip `extra_size` trailing bytes (see below),
`PC1(found_key, data[:len-extra_size])`, re-append trailing bytes verbatim.
Section 0 and sections beyond `records+1` pass through unchanged. Record 1
starting `%MOP` ⇒ Print Replica (`.azw4`).

**Trailing-data size** (`getSizeOfTrailingDataEntries(ptr,size,flags)`): for each
set bit of `flags>>1`, read a backward base-128 varint from the tail (7 bits/byte,
MSB terminates or bitpos≥28); if `flags & 1`, add `(ptr[size-num-1] & 3) + 1`
(multibyte entry).

### 2.5 PID generation

Alphabets:
- `charMap1 = n5Pr6St7Uv8Wx9YzAb0Cd1Ef2Gh3Jk4M` (32) — hash encoding
- `charMap3 = A-Za-z0-9+/` (64) — encodePID 6-bit alphabet
- `charMap4 = ABCDEFGHIJKLMNPQRSTUVWXYZ123456789` (33, no O/0) — PID + checksum chars

**rec209/token** (`getPIDMetaInfo`): rec209 = `meta_array[209]`; walk it in 5-byte
groups (1 tag byte + BE u32 key), look up each key in `meta_array`, concatenate →
`token`. `(md1=rec209, md2=token)` feed all generators.

**From a Kindle serial** (`getKindlePids`): two PIDs —
(a) `encodePID(SHA1(serial + rec209 + token))` then `checksumPid`;
(b) `pidFromSerial(serial, 7) + "*"` then `checksumPid` (legacy pre-2.5 firmware).

**From a K4PC/Mac key DB** (`getK4Pids`): derive DSN (either stored or
`encode(SHA1(MazamaRandomNumber + encode(MD5(IDString)) + encode(MD5(UserName))), charMap1)`),
then book PIDs from `SHA1(DSN + kindleAccountToken + rec209 + token)` and
variants (dropping DSN or token). Plus a `generateDevicePID(table, DSN, 4)`.

Helper encodings:
- `encodePID(hash)`: 8 output chars; each = 6 bits read MSB-first (2 bits at a
  time) from the hash, indexed into `charMap3`.
- `checksumPid(s)`: `crc = (~crc32(s,-1)) & 0xFFFFFFFF; crc ^= crc>>16`; for i in
  {0,1}: `b = crc & 0xFF; pos = (b//33) ^ (b%33); append charMap4[pos%33]; crc >>= 8`.
- `pidFromSerial(s, l)`: fold serial bytes into `arr[l]` by XOR (`arr[i%l] ^= s[i]`),
  XOR in the 4 CRC bytes cyclically, then map each byte
  `charMap4[(b>>7) + ((b>>5 & 3) ^ (b & 0x1F))]`.
- `encode(data,map)`: each byte → two chars `map[(b^0x80)//len]`, `map[b%len]`.
- device-PID CRC table: standard reflected CRC-32, poly `0xEDB88320`.

**PID normalization before matching:** 10-char PIDs are checksum-validated then
truncated to 8 chars; 8-char PIDs used as-is. Matcher always uses 8-char PIDs.

### 2.6 Orchestration (`k4mobidedrm.GetDecryptedBook`)

Magic dispatch on first 8 bytes:
`\xeaDRMION\xee` → reject (bare DRMION); `PK\x03\x04` → `KFXZipBook`;
`TPZ` → `TopazBook`; else → `MobiBook`. PIDs merged from `-p` explicit, `-s`
serials, `-a` android backups (→serials), `-k` key DBs, deduped, passed to
`processBook`. Output ext: `.mobi`, `.azw3` (KF8, mobi_version≥8), `.azw4`
(Print Replica); Topaz also emits `_SVG.zip`.

---
## 3. Amazon Kindle — KFX / KDF (via Amazon ION)

Source: `kfxdedrm.py`, `ion.py`. Scope of these two files: **ZIP in → find
DRMION + voucher by magic → ION parse + AES decrypt → ZIP out.** The KDF SQLite
("CONT") → KFX-ZIP unpacking is *not* in these files (it lives in the external
KFX Input plugin / `kfxlib`); a Rust tool ingesting raw KDF must source that
separately.

### 3.1 Container (KFX-ZIP)

`.kfx-zip` is a standard ZIP. Members identified by **leading magic**, not name:

| Member | Magic | Purpose |
|---|---|---|
| DRMION content | `\xeaDRMION\xee` (`EA 44 52 4D 49 4F 4E EE`, 8 B) | encrypted book pages |
| DRM voucher | `\xe0\x01\x00\xea` (ION BVM) + contains ASCII `ProtectedData` | wrapped content key |

DRMION payload is the ION stream with **8 bytes stripped from front AND 8 from
end** (`data[8:-8]`). Output = rebuilt ZIP with decrypted members replacing
originals, others copied verbatim.

### 3.2 Amazon ION binary format (as implemented in `ion.py`)

Pull-parser. **BVM** = `E0 01 00 EA` (Ion 1.0). Each value = 1 descriptor byte:
**high nibble = type id, low nibble = length**.

Type ids: `0=null 1=bool 2=posint 3=negint 4=float 5=decimal 6=timestamp
7=symbol 8=string 9=clob A=blob B=list C=sexp D=struct E=typedecl/annotation F=unused`.

Length-nibble specials: `0xE` = length is a following VarUInt; `0xF` = null of
that type. Bool encodes value in the length nibble (`L==1`→true). Struct `L==1`
= ordered-struct, real length is a VarUInt.

- **VarUInt**: big-endian base-128; continue while high bit **clear**, terminator
  has high bit **set**.
- **VarInt**: same, but first byte's `0x40` = sign, `0x3F` = top magnitude bits.
- **Ints/symbols**: big-endian unsigned magnitude ≤4 bytes; negint negates.
- **Strings**: UTF-8, `valuelen` bytes. **LOB (clob/blob)**: raw bytes — used for
  cipher_text, cipher_iv, encoded keys.
- **Annotations (typedecl 0xE, L≠0)**: VarUInt length, then a list of annotation
  SIDs; first SID = "type name" (e.g. `com.amazon.drm.Voucher@1.0`). L==0 → BVM.
- **Symbol table**: 10 system symbols (SID 1–9), then imports appended from SID
  11. The shared table **`ProtectedData` v1** (`SYM_NAMES`, fixed ordered list —
  see `ion.py`) must be pre-seeded in the catalog on every parser; SID order is
  positional and load-bearing. `SYM_NAMES` ends with programmatically appended
  `com.amazon.drm.VoucherEnvelope@{2..28}.0` then `@{9708,1031,2069,9041,3646,6052,9479,9888,4648,5683}.0`.

### 3.3 Voucher → content key derivation (THE key chain)

PID is split into `(dsn, secret)` by trying length splits
`[(0,0),(16,0),(16,40),(32,40),(40,0),(40,40)]` (valid PID lengths 0/16/32/40/56/72/80);
empty PID `''` tried first. `dsn = pid[:dsn_len]` (CLIENT_ID),
`secret = pid[dsn_len:]` (ACCOUNT_SECRET).

Voucher envelope = ION struct annotated `com.amazon.drm.VoucherEnvelope@<ver>`
containing: `voucher` (BLOB, nested ION), and `strategy` annotated
`com.amazon.drm.PIDv3@1.0` with `encryption_algorithm`, `encryption_transformation`,
`hashing_algorithm`, `lock_parameters` (list). Inner `voucher` BLOB = struct
`com.amazon.drm.Voucher@1.0` with `cipher_iv` (BLOB), `cipher_text` (BLOB),
`license` (with `license_type`, must be `"Purchase"`).

```
shared = "PIDv3" + encAlg + encTransform + hashAlg
for param in sorted(lock_parameters):
    if param == "ACCOUNT_SECRET": shared += b"ACCOUNT_SECRET" + secret
    if param == "CLIENT_ID":      shared += b"CLIENT_ID" + dsn
sharedsecret = obfuscate(shared, voucherVersion)
kek = HMAC_SHA256(key=sharedsecret, msg=b"PIDv3")            # 32-byte KEK
voucher_plain = PKCS7unpad(AES_256_CBC_decrypt(cipher_text, kek, cipher_iv[:16]))
```

`voucher_plain` is ION: a LIST `com.amazon.drm.KeySet@1.0`; find struct
`com.amazon.drm.SecretKey@1.0` with `algorithm=="AES"`, `format=="RAW"`, and
**`encoded` (BLOB) = the 16-byte content key**.

**`obfuscate(secret, version)`**: version 1 = identity. Otherwise look up
`(magic, word)` in `OBFUSCATION_TABLE["V<n>"]`; zero-pad `secret` to a multiple
of `magic`; with `rows = len/magic`, permute source byte `i` to
`index = (i//rows) + magic*(i%rows)` and XOR with `SHA256(word)[index % 16]`.
Port `OBFUSCATION_TABLE` byte-for-byte (words contain non-ASCII bytes).

No RFC 3394 key-wrap, no PBKDF2 — just HMAC-SHA256 (label `"PIDv3"`) + AES-CBC + PKCS#7.

### 3.4 Content decryption (`DrmIon`)

Inner DRMION stream (after 8+8 strip) = ION doc: `doctype` symbol, then a LIST
`com.amazon.drm.Envelope@1.0/@2.0`. Members:
- `EnvelopeMetadata@1.0/@2.0` → `encryption_voucher` names the voucher; content
  key = `voucher.secretkey`.
- `EncryptedPage@1.0/@2.0` → `cipher_text` + `cipher_iv`; optional nested
  `Compressed@1.0` marker.
- `PlainText@1.0/@2.0` → `data`, not decrypted.

Per page (`processpage`): **AES-128-CBC** decrypt with `key[:16]` (content key)
and per-page IV `cipher_iv[:16]`, then **PKCS#7 unpad**. If compressed: first
byte must be `0x00` (UseFilter), remaining bytes are **LZMA "alone"/legacy
`.lzma`** (not `.xz`). PKCS#7 failure = wrong PID (try next). All pages
concatenated become the replacement DRMION member.

**Two AES contexts:** voucher unwrap = AES-**256**-CBC (HMAC-derived 32-B key);
page content = AES-**128**-CBC (16-B `encoded` key). Both PKCS#7, IV = `iv[:16]`.

---

## 4. Barnes & Noble (Nook / "ignoble")

Source: `ignoblekeygen.py`, `ignoblekey.py`, `ignoblekeyfetch.py`,
`ignobleepub.py`, `ignoblepdf.py`.

### 4.1 The user key (three sources, one artifact)

A single **user key** = 28 base64 chars (= 20-byte SHA-1). Obtainable by:
generating from name+CC (§4.2), fetching from B&N servers (§4.3), or scraping
`BNClientLog.txt` (regex `ccHash: "(.{28})"`). Decryptors use only its **first
16 bytes** after base64-decode.

### 4.2 Key generation (`generate_key(name, ccn)`) — THE CRUX

1. Normalize each: `lowercase`, then remove ASCII spaces only. UTF-8 encode.
2. Append one `0x00` to each: `name‖0x00`, `ccn‖0x00`.
3. `name_sha = SHA1(name‖0x00)[:16]` → **AES IV**.
   `ccn_sha = SHA1(ccn‖0x00)[:16]` → **AES-128 key**.
   `both_sha = SHA1(name‖0x00 ‖ ccn‖0x00)` → 20 bytes.
4. `crypt = AES_128_CBC_encrypt(key=ccn_sha, iv=name_sha, both_sha ‖ (0x0c × 12))`
   — plaintext is exactly 32 bytes (20 + 12 hardcoded PKCS#7 pad); use
   **no-padding** encryptor.
5. `userkey = SHA1(crypt)` (20 B) → **standard base64** → 28 chars, written raw
   (no newline).

> Note: keygen IV = `name_sha` (real IV); both *decryptor* unwraps below use an
> **all-zero IV**. Don't conflate them. Book keys are always the **last 16 bytes**
> after PKCS#7 strip (`[-16:]`), never the first 16.

### 4.3 Key fetch (`fetch_key(email, password)`)

HTTP GET to `https://cart4.barnesandnoble.com/services/service.aspx` with query:
`Version=2, acctPassword=<pw>, devID=PC_BN_2.5.6.9575_<30hex>, emailAddress=<em>,
outFormat=5, schema=1, service=1, stage=deviceHashB`. Parse response with regex
`ccHash>(.+?)</ccHash`; require len 28. Fallback retries with
`devID=hobbes_9.3.50818_<30hex>` (same random reused). Password passed in URL.

### 4.4 EPUB (`ignobleepub.py`)

ZIP with `META-INF/rights.xml` + `META-INF/encryption.xml`. ADEPT ns
`http://ns.adobe.com/adept`, enc ns `http://www.w3.org/2001/04/xmlenc#`.

- **Wrapped key**: `rights.xml` `.//{adept}encryptedKey` text, must be **64 base64
  chars** (48 bytes).
- **Unwrap**: `user_key = base64(keyfile)[:16]`; AES-128-CBC decrypt the 48 bytes
  with **IV = 16 zero bytes**; strip PKCS#7 (`[:-last_byte]`); **book key =
  result[-16:]**.
- **Per-file** (files listed in `encryption.xml` `CipherReference@URI`):
  AES-128-CBC decrypt (book key, zero IV) → **drop first 16 bytes** (prepended IV
  block) → strip PKCS#7 → **raw inflate (windowBits −15)**. Unlisted files copied.
- Repackage: `mimetype` first + STORED; others DEFLATED; drop rights.xml &
  encryption.xml; no Zip64. Return 0 success / 1 not-secure / 2 error.

### 4.5 PDF (`ignoblepdf.py`, fork of `ineptpdf.py`, `EBX_HANDLER` filter)

- User key = `base64(keyfile)[:16]`. Wrapped key is in the `/Encrypt` dict's
  **`ADEPT_LICENSE`** entry: base64 → **raw inflate (−15)** → XML →
  `.//{adept}encryptedKey`.
- Unwrap: AES-128-CBC decrypt (user key, **zero IV**), strip PKCS#7, `[-16:]` →
  book key.
- **Per-object cipher = RC4** (not AES) with per-object key:
  - `genkey_v2`: `MD5(book_key ‖ objid_LE[:3] ‖ genno_LE[:2])[:min(len+5,16)]`.
  - `genkey_v3`: `objid ^= 0x3569ac`, `genno ^= 0xca96`, interleave bytes, append
    literal `'sAlT'`, MD5, same truncation.
- The file is a partially-broken Py3 port (v0.2) — use as **algorithm reference**,
  not a working oracle. The generic PDF tokenizer (xref tables + xref streams +
  ObjStm, filters Flate/LZW/ASCII85) is shared with `ineptpdf.py` (see §7,
  Adobe ADEPT PDF).

---
## 5. Amazon Kindle — Topaz (TPZ)

Source: `topazextract.py`, `convert2xml.py`, `genbook.py`, `flatxml2*.py`,
`stylexml2css.py`, `alfcrypto_src.zip` (`topaz.c`). Topaz = Amazon's OCR/scanned
book format (glyph outlines + OCR text + reflow metadata).

### 5.1 Primitive encodings

- **Encoded number** (variable-length, big-endian base-128): read 1 byte; if
  `0xFF`, it's a negative-sign marker, read next byte. If `< 0x80`, single-byte
  value. Else accumulate `acc = b & 0x7F`; while current byte has bit 7 set,
  `acc = (acc << 7) + (next & 0x7F)`. Apply sign at end.
- **Length-prefixed string**: encoded-number length + that many raw bytes.

### 5.2 Container (`TPZ0`)

```
"TPZ0" (4 bytes) | HEADER | 0x64 marker | PAYLOAD (bookPayloadOffset here)
```

Header: `nbRecords` (encoded-number), then per record: `0x63` ('c') marker,
name (lp-string), then record-data = `nbValues` (encoded-number) followed by
`nbValues` triples `[offset, decompressedLength, compressedLength]` (each an
encoded-number). `compressedLength == 0` → stored uncompressed. Header ends with
`0x64` ('d'); current file position = `bookPayloadOffset`. Record offsets are
relative to `bookPayloadOffset`.

**Payload record** (seek to `bookPayloadOffset + offset`): tag (lp-string, must
match name), `recordIndex` (encoded-number — **if negative, the record is
encrypted**, real index = `-recordIndex - 1`), then `compressedLength` bytes (if
compressed) else `decompressedLength` bytes. Pipeline: **decrypt (if flagged) →
zlib inflate (if compressed)**. Compression is standard **zlib** (2-byte header),
not raw DEFLATE.

Record names → output files: `img`→`img/imgNNNN.jpg`, `color`→`color_img/…`,
`page`→`page/pageNNNN.dat`, `glyphs`→`glyphs/…`, `dkey` (skipped — key store),
others→`nameNNNN.dat` (e.g. `dict0000.dat`, `other0000.dat`, `metadata0000.dat`).

**Metadata record** (inline, unencrypted): tag `"metadata"`, 1-byte flags,
1-byte `nbRecords`, then `nbRecords` × `[keyval (lp-string), content (lp-string)]`
→ `bookMetadata`. PID metadata: `md1 = metadata["keys"]` (comma-separated key
names); `md2 =` concatenation of the values those names reference.

### 5.3 Topaz cipher (from `topaz.c`) — CUSTOM

Two u32 words, **wrapping arithmetic**. Init: `v0 = 0xCAFFE19E`; for each key
byte `k`: `v1 = v0; v0 = (v0>>2).wrapping_mul(v0>>7) ^ (k as u32).wrapping_mul(k).wrapping_mul(0x0F902007)`.
Decrypt per byte: `m = in ^ ((v0>>3) as u8) ^ ((v1<<3) as u8)`; then
`v1 = v0; v0 = (v0>>2).wrapping_mul(v0>>7) ^ (m as u32).wrapping_mul(m).wrapping_mul(0x0F902007)`.
No IV; **fresh state per record** (re-run key schedule each record). Same as the
`alfcrypto` Topaz cipher in §1.3.

### 5.4 DRM: dkey → book key

Read `dkey[0]` payload (unencrypted, zlib if compressed). Blob layout:
`nbKeyRecords` (1 byte), then `nbKeyRecords × [len (1 byte), subRecord (len bytes)]`.

For each candidate **PID (8 bytes**, truncated `pid[0:8]`): `topazCryptoInit(pid)`
decrypt each 24-byte sub-record → `struct '3sB8sB8s3s'`:

| Off | Size | Field | Expected |
|---|---|---|---|
| 0 | 3 | magic | `"PID"` |
| 3 | 1 | len1 | 8 |
| 4 | 8 | pid | == the PID key (self-check) |
| 12 | 1 | len2 | 8 |
| 13 | 8 | **bookKey** | 8-byte per-book key |
| 21 | 3 | magic2 | `"pid"` |

First structurally-valid sub-record yields the 8-byte book key, which then
decrypts all payload records flagged encrypted. Wrong PID → garbage failing the
magic checks (that *is* the validation). No dkey ⇒ book is unencrypted.

PID generation is identical to Mobipocket (§2.5): `md1=keys`, `md2=token`.

### 5.5 Flat-XML token format (`convert2xml.py`) — brief

`dict0000.dat` = string table: `count` (encoded-number) + `count` lp-strings;
holds **both** tag names and all textual content. Page/glyph `.dat` streams are
sequences of encoded-numbers that are either control bytes (`0x72` snippet-loop,
`0x76` vector/delta-loop, `0x74` subtag-count escape, `0x5f` block separator) or
dictionary indices resolving to tag names. A static `token_tags` grammar maps
each dotted tag name (e.g. `info.word.ocrText`, `glyph.x`) to
`(num_args, argtype, subtags, splcase)`. `0x76` vectors are delta/prefix-sum
encoded (used for glyph coordinate arrays). Output = flattened
`name=val1|val2`-per-line text consumed by the renderers.

### 5.6 Rendering (`genbook.py` etc.) — summary

`stylexml2css.py` → CSS from `other0000.dat`; `flatxml2html.py` → OCR-text reflow
to HTML (region classification, dehyphenation, links); `flatxml2svg.py` →
faithful-layout SVG placing glyph `<use>` refs (glyph outlines from
`glyphsNNNN.dat` vectors → SVG Bézier paths at 1440 DPI). Not needed for DRM
removal proper, only for reconstructing readable output.

---

## 6. Kindle Key Extraction (device/account keys → PIDs)

Source: `kindlekey.py` (Kindle for PC/Mac), `androidkindlekey.py`,
`kindlepid.py`. These produce the `kindlekeys` (`.k4i` JSON), `serials`, and
`pids` consumed by §2/§3/§5.

### 6.1 Shared obfuscation primitives

- `encode(data, map)` (64-byte map): each input byte → 2 output bytes,
  `Q = (b ^ 0x80)//64`, `R = b % 64`, output `map[Q], map[R]`. `decode` inverts.
- `encodeHash(data, map) = encode(MD5(data), map)` → 32 bytes (key-name hashes).
- `primes(n)`: used only as `primes(len//3)[-1]` = largest prime ≤ ⌊len/3⌋.
- PBKDF2-HMAC-SHA1 throughout.
- **Char maps differ between PC and Mac branches** (byte-exact tables in
  `kindlekey.py` — `charMap1/2/5`, `testMap1/8`); port them exactly per platform.

### 6.2 `.kinf` container (PC & Mac)

File = records joined by `/` (strip trailing `/`). First record = header blob;
rest grouped into key records. Header: `decode(headerblob, testMap1/charMap1)` →
`UnprotectHeaderData` = PBKDF2-HMAC-SHA1(`b'header_key_data'`, `b'HEADER.2011'`,
iter `0x80`, len `0x100`) → AES-256-CBC (key `[0:32]`, iv `[32:48]`). Cleartext
parsed by regex `[Version:N][Build:N][Cksum:...][Guid:...]`.

Per key record: `keyhash = item[0:32]`, `rcnt = int(decode(item[34:], charMap5))`,
join `rcnt` following records = `encdata`. **Rotation de-obfuscation**:
`noffset = len(encdata) - primes(len//3)[-1]`; move first `noffset` bytes to end.
Key names recovered via `namehashmap = { encodeHash(name, testMap8): name }`.

### 6.3 Value decryption by version

- **v5 `.kinf2011` (Windows):** `decode(encdata, testMap8)` → Windows **DPAPI**
  `CryptUnprotectData` with entropy `SHA1(keyhash) + build + guid`. Requires the
  user's Windows profile — **not reproducible offline**.
- **v5 `.kinf2011` (Mac):** emulated DPAPI —
  PBKDF2(`encode(SHA256(USER + b'+@#$%+' + IDString), charMap2)`,
  salt `str(0x2df*build)+guid`, iter `0x800`, len `0x400`) → AES-256-CBC →
  `decode(charMap2)`. (Note: keyhash **not** mixed into entropy on Mac.)
- **v6 `.kinf2018` (PC & Mac):** key = PBKDF2(`encode(SHA256(USER + b'+@#$%+' +
  IDString), charMap5)`, salt `str(0x6d8*build)+guid`, iter `10000`, len `0x400`)[:32];
  value = AES-256 **GCM-implemented-as-CTR** (12-byte nonce = `iv[:12]`, counter
  suffix `\x00\x00\x00\x02` starting at 2, **auth tag ignored**) → `decode(charMap5)`.

Device values: **Windows** IDString = decimal string of C: volume serial
(`GetVolumeInformationW`); UserName via `GetUserNameW` (non-ASCII→U+FFFD, UTF-8).
**Mac** `GetIDStrings()` enumerates many candidates (munged MACs XOR `0xa5` with a
3↔4 byte swap, disk serials via `ioreg`, mount partitions, UUIDs) and tries each
until `len(DB) > 6`; UserName = `$USER`. Output `.k4i` = JSON of hex-encoded values.

File locations: Windows under `%LOCALAPPDATA%\Amazon\Kindle\storage\`
(`.kinf2018`, `.kinf2011`, `rainier.2.1.1.kinf`, legacy GUID folder
`{AMAwzsaPaaZAzmZzZQzgZCAkZ3AjA_AY}`); Mac under
`~/Library/…/Kindle/storage/` (`.kinf2018`, `.kinf2011`, etc.).

### 6.4 Kindle for Android (`androidkindlekey.py`)

Produces candidate **serials** (not a single key). Inputs: `backup.ab`
(header `ANDROID BACKUP` + zlib → tar), `AmazonSecureStorage.xml`,
`map_data_storage.db`.

- XML obfuscation **V1** = AES-128-**ECB**, key
  `0176e04c9408b1702d90be333fd53523`, hex-wrapped, PKCS pad; both keys and values
  obfuscated. **V2** (if 16-hex `AmazonSaltKey` present) = DES-CBC with
  key/iv from `md5^503(b'Thomsun was here!' + salt)` → `[:8]`/`[8:16]`.
- XML path: `dsnid = get_value('DsnId')`,
  `tokens = get_value('kindle.account.tokens').split(',')`; serials =
  `[dsnid]` + for each token `[dsnid+token, token]`.
- DB path (values in clear): `SELECT device_data_value … LIKE '%serial.number%'`
  and `… LIKE '%/%kindle.account.tokens%'`; serials = each dsn + tokens + dsn+token.

### 6.5 eInk serial → PID (`kindlepid.py`)

`letters = 'ABCDEFGHIJKLMNPQRSTUVWXYZ123456789'` (33, no O/0).
`crc32(s) = (~binascii.crc32(s,-1)) & 0xFFFFFFFF`.
`pidFromSerial(s, l)`: fold `arr[i%l] ^= s[i]`, XOR the 4 CRC bytes cyclically,
then each byte → `letters[(b>>7) + ((b>>5 & 3) ^ (b & 0x1f))]`.
16-char serial (starts `B`/`9`) → `checksumPid(pidFromSerial(serial, 7) + "*")`
(10-char PID). 40-char UDID → `checksumPid(pidFromSerial(serial, 8))`.
`checksumPid` appends 2 chars from `crc ^= crc>>16`, `pos = (b//33)^(b%33)`.

---

## 7. Adobe ADEPT (Adobe Digital Editions) — EPUB + PDF

Source: `adobekey.py`, `ineptepub.py`, `ineptpdf.py`. ADEPT (a.k.a. "INEPT").

### 7.1 Key hierarchy

```
Windows DPAPI entropy  /  Mac activation.dat
   → keykey (16-B AES, Windows only, via CryptUnprotectData)
   → userkey = RSA private key (PKCS#1 RSAPrivateKey DER)   ← "adobekey.der"
   → bookkey = 16-B AES content key (RSA PKCS#1 v1.5 unwrap)
   → EPUB: AES-128-CBC per file + raw inflate  /  PDF: RC4 or AES per object
```

The portable artifact both decryptors consume is the **RSA private key DER**.

### 7.2 Key extraction (`adobekey.py`)

**Windows:**
1. Build 32-byte DPAPI entropy: `struct.pack('>I12s3s13s', volumeSerial, cpuid0_vendor,
   cpuid1_signature, username)` — volume serial of C: (u32 BE), CPUID leaf-0 vendor
   (`EBX‖EDX‖ECX`, 12 B), CPUID leaf-1 EAX low 3 bytes, username (`GetUserNameW` →
   every even byte of UTF-16-LE, 13-byte field).
2. `keykey = CryptUnprotectData(HKCU\…\Adept\Device["key"], entropy)` (16 B AES).
3. Enumerate `HKCU\Software\Adobe\Adept\Activation`; find `credentials` group →
   `privateLicenseKey` value (base64). Decode → AES-128-**CBC** decrypt with
   `keykey` (**zero IV**) → strip **26-byte header** + PKCS#7 pad → DER RSA key.

**Mac:** parse `~/Library/Application Support/Adobe/Digital Editions/**/activation.dat`;
XPath `//adept:credentials/adept:privateLicenseKey` → base64 decode → strip **26
bytes only** (no AES, not encrypted) → DER RSA key.

**RSA note:** userkey is PKCS#1 `RSAPrivateKey` DER (parse `n,e,d` = children
1,2,3). Decrypt is PKCS#1 v1.5; downstream uses the rule "**byte at index −17 ==
0x00 → book key = last 16 bytes**" rather than a strict unpadder.

### 7.3 EPUB (`ineptepub.py`)

ZIP with `META-INF/rights.xml` + `META-INF/encryption.xml`. Detection: rights.xml
`.//{adept}encryptedKey` text is **172 chars** (base64 of 128-byte block → 1024-bit
RSA). `encryption.xml` `CipherReference@URI` lists encrypted files.

- **Book key:** RSA-decrypt base64(encryptedKey) → last 16 bytes (validated by
  `[-17]==0x00`).
- **Per file:** AES-128-CBC decrypt (book key). Implementation decrypts whole blob
  with zero IV then drops first 16 bytes — **equivalent to IV = ciphertext[0:16],
  decrypt ciphertext[16:]**. Strip PKCS#7, then **raw inflate (windowBits −15)**;
  on inflate failure pass through (stored members). `mimetype` + META-INF not
  decrypted. Repackage: `mimetype` first + STORED.

### 7.4 PDF (`ineptpdf.py`)

Generic pdfminer-derived tokenizer: classic `xref` tables + PDF-1.5 xref streams +
object streams (`ObjStm`); filters `FlateDecode`/`LZWDecode`/`ASCII85Decode`,
Predictor 12 (PNG-up). `PDFSerializer` re-emits a decrypted PDF. Encryption
dispatch by `/Encrypt`/`Filter`: `Standard` (classic RC4/AES password),
`Adobe.APS` (German library principal-key), **`EBX_HANDLER` (retail ADEPT)**.

**EBX_HANDLER (`initialize_ebx`):** wrapped key in `/Encrypt` dict's
**`ADEPT_LICENSE`** (base64 → **raw inflate −15** → adept XML → `encryptedKey`).
RSA-decrypt → strip PKCS#7 → last 16 bytes = book key. Version `V` (2 or 3) chosen
by length; content cipher = **RC4** with per-object key:
- `genkey_v2`: `MD5(book_key ‖ objid_LE[:3] ‖ genno_LE[:2])[:min(len+5,16)]`.
- `genkey_v3`: `objid ^= 0x3569ac`, `genno ^= 0xca96`, interleave
  `objid[0],genno[0],objid[1],genno[1],objid[2]`, append `b'sAlT'`, MD5, truncate.

**AES branch** (`decrypt_aes`, used by Adobe.APS / Standard V4): IV = first 16
bytes of object data, AES-128-CBC, strip PKCS#7; `genkey_v4` appends `b'sAlT'`.

**Adobe.APS** uses a hardcoded principal key (e.g. `bibliothek-digital.de` →
base64 `rRwGv2tbpKov1krvv7PO0ws9S436/lArPlfipz5Pqhw=`, 32-B AES-256) — only needed
for German Onleihe library loans.

---

## 8. eReader / Palm (`.pdb`)

Source: `erdr2pml.py`. Converts DRM'd eReader `.pdb` → PML. Cipher = **DES-ECB**
(single-block), keyed by name+credit-card. (No PC1 here — that's Mobipocket.)

### 8.1 Container (Palm PDB)

Header ident at offset `0x3C` (8 B) = `PNRdPPrs` (book) or `PDctPPrs` (dict);
`num_sections` at `0x4C` (u16 BE); record-info list at offset 78, 8 bytes each
(`>LBBBB` → offset (u32 BE), flags, 3-byte id). All big-endian.

### 8.2 User key derivation (name + credit card)

```
newname = lowercase(name), keep only [a-z0-9]
cc = cc.replace(" ", "")
user_key = pack('>LL', crc32(newname), crc32(cc[-8:]))   # 8 bytes, two independent CRC-32s
```

`fixKey(key)` forces **bit 7 (MSB)** of each byte to a parity-derived value (port
literally — it operates on the MSB, not the standard DES LSB parity).

### 8.3 DRM flow

Record 0: version (u16 BE at 0) must be 259/260/272. Record 1 (DRM cookie):
first 8 bytes = DES key (after `fixKey`); decrypt last 8 bytes → `cookie_shuf`
(3..0x14), `cookie_size` (0xF0..0x200); decrypt last `cookie_size` bytes →
`input`; `unshuff(input[:-8], cookie_shuf)` (scatter permutation, `j += shuf mod
len`) → header `r`. Required flags mask `0x680` (bits 7,9,10).

Content key: `content_key = DES_decrypt(fixKey(user_key), encrypted_key)` (8 B);
`encrypted_key` and its SHA-1 check digest live at version-dependent offsets in
`r` (259: key@`r[64:72]`, sha@`r[44:64]`; 260 sub-13: key@`r[44:52]`,
sha@`r[52:72]`; 260 sub-11: key@`r[64:72]`, sha@`r[44:64]`; 272: key@`r[172:180]`,
sha@`r[56:76]`). Validate `SHA1(content_key) == encrypted_key_sha` — mismatch =
wrong name/CC.

**Text pages** = records `1..num_text_pages` (record 1 doubles as first text
page): `zlib.decompress(DES_decrypt(fixKey(content_key), record))` — compression
is **zlib inflate**, not PalmDoc LZ77. Images (records from `first_image_page`)
are unencrypted: 32-byte name at offset 4, data at offset 62. PML uses cp1252;
high bytes escaped to `\a###`.

---

## 9. Kobo (`obok.py`)

Source: `Obok_plugin/obok/obok.py` (v4.0.0, canonical) and `Other_Tools/Kobo/obok.py`
(v3.2.4, Py2 — identical crypto, differs only in host integration). Cipher =
**AES-128-ECB**, applied in two layers.

### 9.1 Storage & inputs

Device: `.kobo/KoboReader.sqlite`; Desktop app: `Kobo.sqlite` (Win
`%LOCALAPPDATA%\Kobo\Kobo Desktop Edition`, Mac
`~/Library/Application Support/Kobo/Kobo Desktop Edition`). Books in `kepub/`
(ZIP/EPUB archives). Device serial from `.adobe-digital-editions/device.xml`
(tag containing `deviceSerial`). SQLite may be WAL — patch header bytes 18–19 to
`01 01` on a temp copy to force rollback journal.

### 9.2 User-key derivation

```
KOBO_HASH_KEYS = ['88b3a2e13', 'XzUhGYdFp', 'NoCanLook', 'QJhwzAtXL']
macaddrs = all NIC MACs (upper, colon-sep) + device serials
userids  = SELECT UserID FROM user
for hash in KOBO_HASH_KEYS, macaddr in macaddrs, userid in userids:
    deviceid = SHA256_hex(hash + macaddr)
    userkey  = unhex( SHA256_hex(deviceid + userid)[32:] )   # SECOND half → 16-byte AES key
```

Keys are **derived, not stored** (no "userkey table"). The correct one is found by
trial decryption over this cartesian product.

### 9.3 Content decryption

Per-file encrypted page keys from DB:
`SELECT elementid, elementkey FROM content_keys, content WHERE volumeid = ? AND
volumeid = contentid` — `elementid` = path inside the kepub ZIP, `elementkey` =
base64 AES-encrypted 16-byte page key. Book list:
`SELECT DISTINCT volumeid, Title, Attribution, Series FROM content_keys, content
WHERE contentid = volumeid`.

```
page_key = AES128_ECB_decrypt(userkey, base64decode(elementkey))   # layer 1
plaintext = AES128_ECB_decrypt(page_key, file_contents)            # layer 2
strip CMS/PKCS#7 padding (last byte = pad length)
```

Validity check per file (`check`): xhtml → first 5 chars printable ASCII (after
BOM); jpeg → starts `FF D8 FF`. Wrong key raises → try next candidate. Output
re-zipped as `<title>.epub` (DEFLATED); DRM-free books copied. OPF/container.xml
must be unencrypted (used for MIME types).

---

## 10. Rust Port — Consolidated Guidance

**Custom ciphers to port byte-for-byte:** PC1/Pukall (§1.2, Mobipocket + not
eReader), Topaz stream cipher (§1.3/§5.3). Everything else is standard: AES-CBC/
ECB/CTR, DES-ECB, RC4, MD5/SHA1/SHA256, HMAC-SHA256, PBKDF2-HMAC-SHA1, CRC-32
(poly `0xEDB88320`), RSA PKCS#1 v1.5, zlib/raw DEFLATE, LZMA-alone.

**Recommended crate mapping:** `aes` + `cbc`/`ctr` + `ecb` (NoPadding, explicit
IV), `des`, `rc4`, `rsa`, `md-5`/`sha1`/`sha2`, `hmac`, `pbkdf2`, `crc32fast`
(note the `!` re-inversion in `checksumPid`), `flate2` (raw inflate windowBits
−15 = `DeflateDecoder`; zlib = `ZlibDecoder`), `lzma-rs`/`xz2` (alone format,
strip 1-byte `0x00` prefix), `zip`, `quick-xml`/`roxmltree`, `rusqlite`.

**Architecture:** mirror the Python split — (1) a `keys` layer per vendor
(platform-specific extraction: DPAPI, plists, SQLite, registry; plus offline
generators for B&N/eReader from name+CC) producing candidate keys/PIDs, and (2) a
`decrypt` layer per format (container parse + cipher) that brute-forces candidate
keys and detects success via a scheme-specific oracle (PKCS#7/padding failure,
magic bytes, PID self-check, or content sniffing).

**Platform caveats not reproducible offline:** Windows Kindle `.kinf2011` (v5)
and Adobe `privateLicenseKey` both require Windows **DPAPI** with the user's
profile; the Mac equivalents and all v6/Android/eInk paths are pure crypto.

**Cross-cutting gotchas:** treat all "strings" as bytes; all MOBI/PalmDB/ION/PDB
integers are big-endian; book keys are frequently the **last** 16 bytes after
padding strip (ADEPT/B&N), not the first; the EPUB per-file "drop first 16 bytes"
is the prepended-IV convention; Topaz's encrypted flag is the *sign* of the record
index; wrapping u32 arithmetic is mandatory in PC1 and Topaz.
