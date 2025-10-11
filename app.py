from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)
# ================== ZIGZAG ==================

def key_to_number(key):
    """Konversi key (angka atau teks) ke jumlah rail (minimal 2)."""
    if key.isdigit():
        return max(2, int(key))
    else:
        # Ubah teks menjadi nilai numerik berdasarkan jumlah karakter unik
        total = sum(ord(c) for c in key)
        num = (total % 7) + 2  # hasil 2–8 biar tidak terlalu ekstrem
        return num

def zigzag_encrypt(text, key):
    # Jangan hapus spasi — langsung pakai teks apa adanya
    rail = [['\n' for _ in range(len(text))] for _ in range(key)]
    dir_down = False
    row, col = 0, 0
    process = []

    for i, ch in enumerate(text):
        if row == 0 or row == key - 1:
            dir_down = not dir_down
        rail[row][col] = ch  # spasi tetap masuk ke rail
        process.append(f"Masukkan '{ch}' ke rail {row+1}, kolom {col+1}")
        col += 1
        row += 1 if dir_down else -1

    result = []
    for r in rail:
        for c in r:
            if c != '\n':
                result.append(c)
    return "".join(result), process


def zigzag_decrypt(cipher, key):
    rail = [['\n' for _ in range(len(cipher))] for _ in range(key)]
    
    dir_down = None
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        elif row == key - 1:
            dir_down = False
        rail[row][col] = '*'
        col += 1
        row += 1 if dir_down else -1

    # Isi rail sesuai urutan cipher (termasuk spasi)
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if rail[i][j] == '*' and index < len(cipher):
                rail[i][j] = cipher[index]
                index += 1

    result = []
    row, col = 0, 0
    dir_down = None
    process = []

    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        elif row == key - 1:
            dir_down = False
        if rail[row][col] != '\n':
            result.append(rail[row][col])
            process.append(f"Ambil '{rail[row][col]}' dari rail {row+1}, kolom {col+1}")
        col += 1
        row += 1 if dir_down else -1

    return "".join(result), process

# ================== VIGENERE ==================
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
            p_num = char_to_num(char)
            k_num = key_nums[i % len(key)]
            c_num = (p_num + k_num) % 26
            c_char = num_to_char(c_num)
            result += c_char
            process.append({
                "P": f"{char.upper()}->{p_num}",
                "K": f"{key[i % len(key)]}->{k_num}",
                "hasil": c_num,
                "char": c_char
            })
            i += 1
        else:
            result += char
            process.append({
                "P": f"'{char}' (tidak dienkripsi)",
                "K": "-",
                "hasil": "-",
                "char": char
            })
    return result, process


def vigenere_decrypt(cipher, key):
    result = ""
    process = []
    key = key.upper()
    key_nums = [char_to_num(k) for k in key]
    i = 0
    for char in cipher:
        if char.isalpha():
            c_num = char_to_num(char)
            k_num = key_nums[i % len(key)]
            p_num = (c_num - k_num) % 26
            p_char = num_to_char(p_num)
            result += p_char
            process.append({
                "P": f"{char.upper()}->{c_num}",
                "K": f"{key[i % len(key)]}->{k_num}",
                "hasil": p_num,
                "char": p_char
            })
            i += 1
        else:
            result += char
            process.append({
                "P": f"'{char}' (tidak diubah)",
                "K": "-",
                "hasil": "-",
                "char": char
            })
    return result, process

# ================== STREAM (LFSR) ==================
def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def bits_to_text(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

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

def stream_cipher_lfsr(text, seed, taps, mode="encrypt"):
    if not all(ch in '01' for ch in seed):
        seed = text_to_bits(seed)

    if mode == "encrypt":
        pt_bits = text_to_bits(text)
        ks = lfsr_keystream(seed, taps, len(pt_bits))
        ct_bits = ''.join(str(int(b) ^ int(k)) for b, k in zip(pt_bits, ks))
        proses = [{"pt": b, "ks": str(k), "ct": r} for b, k, r in zip(pt_bits, ks, ct_bits)]
        return ct_bits, proses
    else:
        ct_bits = text
        ks = lfsr_keystream(seed, taps, len(ct_bits))
        pt_bits = ''.join(str(int(b) ^ int(k)) for b, k in zip(ct_bits, ks))
        plaintext = bits_to_text(pt_bits)
        proses = [{"ct": b, "ks": str(k), "pt": r} for b, k, r in zip(ct_bits, ks, pt_bits)]
        return plaintext, proses

# ================== AES ==================

def normalize_aes_key(key: str) -> bytes:
    """Menyesuaikan panjang key AES agar valid (16, 24, atau 32 byte)"""
    key_bytes = key.encode('utf-8')
    while len(key_bytes) not in [16, 24, 32]:
        if len(key_bytes) > 32:
            key_bytes = key_bytes[:32]
        elif len(key_bytes) < 16:
            key_bytes = (key_bytes * 2)[:16]
        elif 16 < len(key_bytes) < 24:
            key_bytes = (key_bytes * 2)[:24]
        elif 24 < len(key_bytes) < 32:
            key_bytes = (key_bytes * 2)[:32]
    return key_bytes

def aes_encrypt(plaintext, key):
    process = []
    key_bytes = normalize_aes_key(key)
    if len(key_bytes) not in [16, 24, 32]:
        raise ValueError("Key harus 16, 24, atau 32 byte!")
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    padded_text = pad(plaintext.encode('utf-8'), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_text)
    base64_cipher = base64.b64encode(encrypted_bytes).decode('utf-8')
    return base64_cipher, process

def aes_decrypt(ciphertext, key):
    process = []
    key_bytes = normalize_aes_key(key)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decoded_data = base64.b64decode(ciphertext)
    decrypted_bytes = cipher.decrypt(decoded_data)
    unpadded_text = unpad(decrypted_bytes, AES.block_size).decode('utf-8')
    process.append(f"Ciphertext didekode base64: {decoded_data}")
    process.append(f"Hasil decrypt (unpadded): {unpadded_text}")
    return unpadded_text, process

# ================== ROUTES ==================

@app.route("/")
def index():
    return render_template("index.html")

@app.route('/metode')
def metode():
    return render_template('metode.html')

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
    key_input = ""   # <- inisialisasi lebih awal
    key_used = 2     # <- default nilai key (rail minimal 2)

    if request.method == "POST":
        text = request.form.get("text", "")
        key_input = request.form.get("key", "2")
        key_used = key_to_number(key_input)
        mode = request.form.get("mode")

        if mode == "encrypt":
            result, process = zigzag_encrypt(text, key_used)
            grid = zigzag_visualize(text, key_used)
        else:
            result, process = zigzag_decrypt(text, key_used)
            grid = zigzag_visualize(result, key_used)

    # render_template tetap bisa akses semua variabel di atas
    return render_template(
        "zigzag.html",
        result=result,
        process=process,
        grid=grid,
        key_input=key_input,
        key_used=key_used
    )
@app.route('/vigenere', methods=['GET', 'POST'])
def vigenere_page():
    result = None
    process = []
    if request.method == 'POST':
        text = request.form['text']
        key = request.form['key']
        mode = request.form['mode']

        if mode == 'encrypt':
            result, process = vigenere_encrypt(text, key)
        else:
            result, process = vigenere_decrypt(text, key)

    return render_template('vigenere.html', result=result, process=process)


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

@app.route("/aes", methods=["GET", "POST"])
def aes_page():
    result = None
    process = []
    if request.method == "POST":
        text = request.form.get("text", "")
        key = request.form.get("key", "")
        mode = request.form.get("mode", "")

        try:
            if mode == "encrypt":
                result, process = aes_encrypt(text, key)
            elif mode == "decrypt":
                result, process = aes_decrypt(text, key)
        except Exception as e:
            process.append(f"Error: {str(e)}")

    return render_template("aes.html", result=result, process=process)

@app.route("/combine", methods=["GET", "POST"])
def combine_page():
    result = ""
    process = []
    steps = {}  # buat simpan hasil tiap layer biar bisa ditampilkan nanti

    if request.method == "POST":
        text = request.form.get("text", "")
        key = request.form.get("key", "")
        mode = request.form.get("mode", "")

        try:
            if mode == "encrypt":
                # ==================== ENKRIPSI 4 LAYER ====================
                key_rails = key_to_number(key)

                # 1️⃣ Zigzag
                zigzag_res, proc_zigzag = zigzag_encrypt(text, key_rails)
                steps["Zigzag"] = zigzag_res
                process.append("=== ZIGZAG ENCRYPT ===")
                process.extend(proc_zigzag)

                # 2️⃣ Vigenere
                vigenere_res, proc_vigenere = vigenere_encrypt(zigzag_res, key)
                steps["Vigenere"] = vigenere_res
                process.append("\n=== VIGENERE ENCRYPT ===")
                process.extend(proc_vigenere)

                # 3️⃣ Stream (LFSR)
                stream_res, proc_stream = stream_cipher_lfsr(vigenere_res, seed=key, taps=[0, 2], mode="encrypt")
                steps["Stream"] = stream_res
                process.append("\n=== STREAM ENCRYPT ===")
                process.extend([str(p) for p in proc_stream])

                # 4️⃣ AES
                aes_res, proc_aes = aes_encrypt(stream_res, key)
                steps["AES"] = aes_res
                process.append("\n=== AES ENCRYPT ===")
                process.extend(proc_aes)

                result = aes_res

            elif mode == "decrypt":
                # ==================== DEKRIPSI 4 LAYER ====================
                key_rails = key_to_number(key)

                # 1️⃣ AES
                aes_res, proc_aes = aes_decrypt(text, key)
                steps["AES"] = aes_res
                process.append("=== AES DECRYPT ===")
                process.extend(proc_aes)

                # 2️⃣ Stream
                stream_res, proc_stream = stream_cipher_lfsr(aes_res, seed=key, taps=[0, 2], mode="decrypt")
                steps["Stream"] = stream_res
                process.append("\n=== STREAM DECRYPT ===")
                process.extend([str(p) for p in proc_stream])

                # 3️⃣ Vigenere
                vigenere_res, proc_vigenere = vigenere_decrypt(stream_res, key)
                steps["Vigenere"] = vigenere_res
                process.append("\n=== VIGENERE DECRYPT ===")
                process.extend(proc_vigenere)

                # 4️⃣ Zigzag
                zigzag_res, proc_zigzag = zigzag_decrypt(vigenere_res, key_rails)
                steps["Zigzag"] = zigzag_res
                process.append("\n=== ZIGZAG DECRYPT ===")
                process.extend(proc_zigzag)

                result = zigzag_res

        except Exception as e:
            process.append(f"❌ Error: {str(e)}")

    return render_template("combine.html", result=result, process=process, steps=steps)


if __name__ == "__main__":
    app.run(debug=True)
