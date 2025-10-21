from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)
# ================== RAIL FENCE  ==================

def key_to_number(key):
    if key.isdigit(): #mengecek aapakah key berupa angka
        return max(2, int(key)) 
    else:
        key = key.upper()  
        total = sum(ord(c) for c in key) #Menghitung jumlah nilai ASCII dari setiap karakter dalam key.
        num = (total % 7) + 2
        return num

def railfence_encrypt(text, key):

    rail = [['\n' for _ in range(len(text))] for _ in range(key)] # Buat matriks 2D berisi karakter '\n'
    
#Inisialisasi Arah dan Posisi Awal
    dir_down = False   
    row, col = 0, 0    
    process = []      

# Algoritma RAIL FENCE  
    for i, ch in enumerate(text):    
        #  ubah arah (naik/turun)       
        if row == 0 or row == key - 1:      
            dir_down = not dir_down          
        
        #menempatkan karakter pada posisi rail yang sesuai
        rail[row][col] = ch                  
        process.append(f"Masukkan '{ch}' ke rail {row+1}, kolom {col+1}")  
        col += 1    #pindah ke kolom berikutnya dan naik/turun sesuai arah                         
        row += 1 if dir_down else -1        

    result = []                            
    for r in rail:                        
        for c in r:
            if c != '\n':                  
                result.append(c)
    return "".join(result), process      #menggabungkan karakter menjadi string hasil 

def railfence_decrypt(cipher, key):
   
    rail = [['\n' for _ in range(len(cipher))] for _ in range(key)] # Buat matriks 2D berisi karakter '\n'
    
    dir_down = None     
    row, col = 0, 0    

# Inisialisasi Arah dan mengatur posisi 
    for i in range(len(cipher)):         
        if row == 0:                     
            dir_down = True 
        elif row == key - 1:              
            dir_down = False
        rail[row][col] = '*'              
        col += 1                          
        row += 1 if dir_down else -1      # naik/turun sesuai arah

    index = 0
    for i in range(key):          
        #mengisi huruf cipher ke posisi yang sudah ditandai '*'          
        for j in range(len(cipher)):        
            if rail[i][j] == '*' and index < len(cipher):
                rail[i][j] = cipher[index]  
                index += 1

    result = [] 
    #menentukan posisi awal dan menentukan arah                            
    row, col = 0, 0
    dir_down = None 
    process = []          

    for i in range(len(cipher)):
        # Tentukan arah
        if row == 0:
            dir_down = True
        elif row == key - 1:
            dir_down = False

        #mengecek dan mengambil huruf dari rail
        if rail[row][col] != '\n':          
            result.append(rail[row][col])  
            process.append(f"Ambil '{rail[row][col]}' dari rail {row+1}, kolom {col+1}")

        #pindah ke kolom berikutnya dan naik/turun sesuai arah
        col += 1
        row += 1 if dir_down else -1
    return "".join(result), process

# ================== VIGENERE ==================
def char_to_num(ch):
    """Konversi karakter ke angka 0-35 (A-Z=0-25, 0-9=26-35)"""
    if ch.isupper():
        return ord(ch) - 65  # A–Z → 0–25
    elif ch.islower():
        return ord(ch) - 97  # a–z → 0–25
    elif ch.isdigit():
        return 26 + int(ch)  # 0–9 → 26–35
    else:
        return None  # karakter lain tidak diproses


def num_to_char(n, is_upper=True):
    """Konversi angka 0–35 kembali ke huruf/angka"""
    n = n % 36
    if n < 26:
        return chr(n + (65 if is_upper else 97))
    else:
        return str(n - 26)


def vigenere_encrypt(text, key):
    result = ""
    process = []
    key = key.upper()
    key_nums = [char_to_num(k) % 26 for k in key if k.isalpha()]  # kunci tetap huruf
    i = 0

    for char in text:
        p_num = char_to_num(char)
        if p_num is not None:
            k_num = key_nums[i % len(key_nums)]
            c_num = (p_num + k_num) % 36  # ubah jadi mod 36
            is_upper = char.isupper()
            c_char = num_to_char(c_num, is_upper)
            result += c_char

            process.append({
                "P": f"{char}->{p_num}",
                "K": f"{key[i % len(key_nums)]}->{k_num}",
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
    key_nums = [char_to_num(k) % 26 for k in key if k.isalpha()]
    i = 0

    for char in cipher:
        c_num = char_to_num(char)
        if c_num is not None:
            k_num = key_nums[i % len(key_nums)]
            p_num = (c_num - k_num) % 36  # mod 36
            is_upper = char.isupper()
            p_char = num_to_char(p_num, is_upper)
            result += p_char

            process.append({
                "P": f"{char}->{c_num}",
                "K": f"{key[i % len(key_nums)]}->{k_num}",
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

def railfence_visualize(text, key):
    rail = [['' for _ in range(len(text))] for _ in range(key)]
    dir_down = False
    row, col = 0, 0

    for char in text:
        rail[row][col] = char
        col += 1

        if row == 0 or row == key - 1:  # ubah arah jika di atas atau bawah
            dir_down = not dir_down

        row += 1 if dir_down else -1

    return rail


@app.route("/railfence", methods=["GET", "POST"])
def railfence_page():
    # Inisialisasi variabel
    result = None
    process = []
    grid = []
    key_input = ""
    key_used = 2

    # Proses form ketika metode POST
    if request.method == "POST":
        text = request.form.get("text", "")
        key_input = request.form.get("key", "2")
        key_used = key_to_number(key_input)
        mode = request.form.get("mode")

        if mode == "encrypt":
            result, process = railfence_encrypt(text, key_used)
            grid = railfence_visualize(text, key_used)
        else:
            result, process = railfence_decrypt(text, key_used)
            grid = railfence_visualize(result, key_used)

    return render_template(
        "railfence.html",
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
    steps = {}
    if request.method == "POST":
        text = request.form.get("text", "")
        key = request.form.get("key", "")
        mode = request.form.get("mode", "")

        try:
            if mode == "encrypt":
                key_rails = key_to_number(key)
                # 1️⃣ Rail Fence
                rf_res, proc_rf = railfence_encrypt(text, key_rails)
                steps["Railfence"] = rf_res
                process.append("=== Rail Fence ENCRYPT ===")
                process.extend(proc_rf)

                # 2️⃣ Vigenere
                vigenere_res, proc_vigenere = vigenere_encrypt(rf_res, key)
                steps["Vigenere"] = vigenere_res
                process.append("\n=== VIGENERE ENCRYPT ===")
                process.extend(proc_vigenere)

                # 3️⃣ Stream
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

                # 4️⃣ Rail Fence
                rf_res, proc_rf = railfence_decrypt(vigenere_res, key_rails)
                steps["Railfence"] = rf_res
                process.append("\n=== RAILFENCE DECRYPT ===")
                process.extend(proc_rf)

                result = rf_res
        except Exception as e:
            process.append(f"❌ Error: {str(e)}")

    return render_template("combine.html", result=result, process=process, steps=steps)

if __name__ == "__main__":
    app.run(debug=True)