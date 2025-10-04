from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

# ================== ZIGZAG ==================
def zigzag_encrypt(text, key):
    rail = [['\n' for i in range(len(text))] for j in range(key)]
    dir_down = False
    row, col = 0, 0
    process = []

    for i in range(len(text)):
        if row == 0 or row == key - 1:
            dir_down = not dir_down
        rail[row][col] = text[i]
        process.append(f"Masukkan '{text[i]}' ke rail {row+1}, kolom {col+1}")
        col += 1
        row += 1 if dir_down else -1

    result = []
    for r in rail:
        for c in r:
            if c != '\n':
                result.append(c)
    return "".join(result), process


def zigzag_decrypt(cipher, key):
    rail = [['\n' for i in range(len(cipher))] for j in range(key)]
    dir_down = None
    row, col = 0, 0

    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        rail[row][col] = '*'
        col += 1
        row += 1 if dir_down else -1

    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if (rail[i][j] == '*') and (index < len(cipher)):
                rail[i][j] = cipher[index]
                index += 1

    result, process = [], []
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key-1:
            dir_down = False
        if (rail[row][col] != '*'):
            result.append(rail[row][col])
            process.append(f"Ambil '{rail[row][col]}' dari rail {row+1}, kolom {col+1}")
            col += 1
        row += 1 if dir_down else -1

    return "".join(result), process


# ================== VIGENERE ==================
# VIGENERE CIPHER DENGAN RUMUS MOD 26
def char_to_num(ch):
    return ord(ch.upper()) - 65

def num_to_char(n):
    return chr((n % 26) + 65)

def vigenere_encrypt(text, key):
    result = ""
    process = []
    key = key.upper()
    key_nums = [char_to_num(k) for k in key]
    i = 0
    for char in text:
        if char.isalpha():
            p = char_to_num(char)
            k = key_nums[i % len(key)]
            c = (p + k) % 26
            result += num_to_char(c)
            process.append(f"({char}->{p} + {key[i % len(key)]}->{k}) mod 26 = {c} -> {num_to_char(c)}")
            i += 1
        else:
            result += char
            process.append(f"Karakter '{char}' tidak diubah")
    return result, process


def vigenere_decrypt(cipher, key):
    result = ""
    process = []
    key = key.upper()
    key_nums = [char_to_num(k) for k in key]
    i = 0
    for char in cipher:
        if char.isalpha():
            c = char_to_num(char)
            k = key_nums[i % len(key)]
            p = (c - k) % 26
            result += num_to_char(p)
            process.append(f"({char}->{c} - {key[i % len(key)]}->{k}) mod 26 = {p} -> {num_to_char(p)}")
            i += 1
        else:
            result += char
            process.append(f"Karakter '{char}' tidak diubah")
    return result, process

# ================== STREAM (LFSR) ==================
# === Helper: ubah teks jadi biner ===
def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

# === Fungsi LFSR ===
def lfsr_keystream(seed, taps, length):
    sr = [int(b) for b in seed]
    out = []
    for _ in range(length):
        out.append(sr[-1])
        fb = 0
        for t in taps:
            fb ^= sr[t]
        sr = [fb] + sr[:-1]
    return out

# === Stream Encrypt ===
# === Helper: ubah teks jadi biner ===
def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def bits_to_text(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

# === Fungsi LFSR ===
def lfsr_keystream(seed, taps, length):
    sr = [int(b) for b in seed]
    out = []
    for _ in range(length):
        out.append(sr[-1])
        fb = 0
        for t in taps:
            fb ^= sr[t]
        sr = [fb] + sr[:-1]
    return out

# === Stream Encrypt / Decrypt ===
def stream_cipher_lfsr(text, seed, taps, mode="encrypt"):
    if not all(ch in '01' for ch in seed):
        seed = text_to_bits(seed)

    if mode == "encrypt":
        # plaintext ke biner
        pt_bits = text_to_bits(text)

        # generate keystream
        ks = lfsr_keystream(seed, taps, len(pt_bits))

        # XOR plaintext dengan keystream
        ct_bits = ''.join(str(int(b) ^ int(k)) for b, k in zip(pt_bits, ks))

        # proses: tampilkan PT -> KS -> CT
        proses = [{"pt": b, "ks": str(k), "ct": r} for b, k, r in zip(pt_bits, ks, ct_bits)]

        return ct_bits, proses

    else:  # decrypt
        ct_bits = text

        # generate keystream
        ks = lfsr_keystream(seed, taps, len(ct_bits))

        # XOR cipher dengan keystream
        pt_bits = ''.join(str(int(b) ^ int(k)) for b, k in zip(ct_bits, ks))

        # ubah biner ke teks
        plaintext = bits_to_text(pt_bits)

        # proses: tampilkan CT -> KS -> PT
        proses = [{"ct": b, "ks": str(k), "pt": r} for b, k, r in zip(ct_bits, ks, pt_bits)]

        return plaintext, proses

# ================== ROUTES ==================

@app.route("/")
def index():
    return render_template("index.html")


def zigzag_visualize(text, key):
    rail = [['' for _ in range(len(text))] for _ in range(key)]
    dir_down = False
    row, col = 0, 0

    for char in text:
        if row == 0 or row == key-1:
            dir_down = not dir_down
        rail[row][col] = char
        col += 1
        row += 1 if dir_down else -1

    return rail


@app.route("/zigzag", methods=["GET", "POST"])
def zigzag_page():
    result = None
    process = []
    grid = []
    if request.method == "POST":
        text = request.form.get("text", "")
        key = int(request.form.get("key", "2"))
        mode = request.form.get("mode")

        if mode == "encrypt":
            result, process = zigzag_encrypt(text, key)
            grid = zigzag_visualize(text, key)
        else:
            result, process = zigzag_decrypt(text, key)
            grid = zigzag_visualize(result, key)

    return render_template("zigzag.html", result=result, process=process, grid=grid)

@app.route('/vigenere', methods=["GET", "POST"])
def vigenere_page():
    result = ""
    process = []
    if request.method == "POST":
        text = request.form.get('text', '')
        key = request.form.get('key', '')
        mode = request.form.get('mode', '')

        if text and key and mode:
            if mode == "encrypt":
                result, process = vigenere_encrypt(text, key)
            elif mode == "decrypt":
                result, process = vigenere_decrypt(text, key)

    return render_template("vigenere.html", result=result, process=process)

@app.route("/stream", methods=["GET", "POST"])
def stream_page():
    result = None
    proses = None
    text = ""
    key = ""
    mode = "encrypt"

    if request.method == "POST":
        text = request.form["text"]
        key = request.form["key"]
        mode = request.form["mode"]

        if mode == "encrypt":
            result, proses = stream_cipher_lfsr(text, seed=key, taps=[0, 2], mode="encrypt")
        else:
            result, proses = stream_cipher_lfsr(text, seed=key, taps=[0, 2], mode="decrypt")

    return render_template("stream.html", result=result, proses=proses, text=text, key=key, mode=mode)

if __name__ == "__main__":
    app.run(debug=True)
