from flask import Flask, render_template, request, session, jsonify  # type: ignore
from openai import OpenAI # type: ignore
from dotenv import load_dotenv # type : ignore
from aes_file import *
from cesar_file import *
from playfair_file import *
from rsa_file import *
from sha_256_file import *
import os
import markdown

app = Flask(__name__)

load_dotenv()
API_KEY = os.getenv("OPENAI_API_KEY")
app.secret_key = os.urandom(24)
client = OpenAI(api_key=API_KEY)

if API_KEY is None:
    raise ValueError("API_KEY is not set in environment variables!")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/books_page', methods=['GET', 'POST'])
def books_page():
    return render_template('books_page.html')


@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get("message", "")
    if not user_message:
        return jsonify({"error": "Empty message"}), 400

    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "You are a helpful assistant in the web-platform for learning and visualization of cryptography. There are cryptography methods like Cesar, Playfair, AES, RSA, SHA-256. This web platform is helpful and effective for students in learning cryptography"},
            {"role": "user", "content": user_message}
        ]
    )
    ai_response = markdown.markdown(completion.choices[0].message.content)
    return jsonify({"response": ai_response})

@app.route('/aes-page', methods=['GET', 'POST'])
def aes():
    if request.method == 'POST':
        plaintext = request.form['plaintext']
        key = request.form['key']

        padded_plaintext = pad_to_block_size(plaintext)
        padded_key = pad_to_block_size(key)
        plaintext_hex = str_to_hex(padded_plaintext)
        key_hex = str_to_hex(padded_key)

        plaintext_bytes = bytearray.fromhex(plaintext_hex)
        key_bytes = bytearray.fromhex(key_hex)

        state = state_from_bytes(plaintext_bytes)
        key_schedule = key_expansion(key_bytes)

        encryption_steps = []
        for round in range(11):
            round_steps = {'round': round}  # Очередь шага
            if round == 0:
                # Изначальный AddRoundKey
                add_round_key(state, key_schedule, round=0)
                round_steps['add_round_key'] = bytes_from_state(state).hex()
            else:
                sub_bytes(state)
                round_steps['sub_bytes'] = bytes_from_state(state).hex()

                shift_rows(state)
                round_steps['shift_rows'] = bytes_from_state(state).hex()

                if round < 10:
                    mix_columns(state)
                    round_steps['mix_columns'] = bytes_from_state(state).hex()

                add_round_key(state, key_schedule, round=round)
                round_steps['add_round_key'] = bytes_from_state(state).hex()

            encryption_steps.append(round_steps)

        ciphertext_bytes = bytes_from_state(state)
        ciphertext_hex = ciphertext_bytes.hex()

        # Дешифрование
        state = state_from_bytes(ciphertext_bytes)
        decryption_steps = []
        for round in range(10, -1, -1):
            round_steps = {'round': 10 - round}
            add_round_key(state, key_schedule, round=round)
            round_steps['add_round_key'] = bytes_from_state(state).hex()

            if round < 10:
                if round > 0:
                    inv_mix_columns(state)
                    round_steps['inv_mix_columns'] = bytes_from_state(state).hex()

                inv_shift_rows(state)
                round_steps['inv_shift_rows'] = bytes_from_state(state).hex()

                inv_sub_bytes(state)
                round_steps['inv_sub_bytes'] = bytes_from_state(state).hex()

            decryption_steps.append(round_steps)

        decrypted_bytes = aes_decryption(ciphertext_bytes, key_bytes)

        try:
            decrypted_text = unpad(decrypted_bytes.decode('utf-8'))
        except UnicodeDecodeError:
            decrypted_text = "Ошибка: расшифрованные данные не могут быть декодированы в UTF-8."

        return render_template('aes-page.html',
                               ciphertext=ciphertext_hex,
                               decrypted_text=decrypted_text,
                               plaintext_hex=plaintext_hex,
                               key_hex=key_hex,
                               encryption_steps=encryption_steps,
                               decryption_steps=decryption_steps)
    return render_template('aes-page.html')


@app.route('/cesar', methods=['GET', 'POST'])
def cesar():
    if request.method == 'POST':
        plaintext = request.form['plaintext']
        shift = int(request.form['shift'])
        encrypted_text, steps = encrypt_text(plaintext, shift)
        return render_template('cesar.html', plaintext=plaintext, shift=shift, encrypted_text=encrypted_text, steps=steps)

    return render_template('cesar.html')

@app.route('/playfair', methods=['GET', 'POST'])
def playfair():
    if request.method == 'POST':
        message = request.form['message']
        key = request.form['key']
        action = request.form['action']

        if action == 'encrypt':
            result, steps, playfair_square = playfair_encrypt(message, key)
        elif action == 'decrypt':
            result, steps, playfair_square = playfair_decrypt(message, key)

        return render_template('playfair.html', message=message, key=key, action=action, result=result, steps=steps, playfair_square=playfair_square)

    return render_template('playfair.html')


@app.route('/rsa', methods=['GET', 'POST'])
def rsa_encrypt_page():
    if request.method == 'POST':
        plaintext = request.form['plaintext']
        rsa_key_size = 2048
        prime_number_bit_length = rsa_key_size // 2

        # Генерация ключей
        p = generate_prime_number(prime_number_bit_length)
        q = generate_prime_number(prime_number_bit_length)
        n = p * q
        e = 65537
        d = calculate_private_key(e, p, q)

        # Шифрование текста
        plaintext_bytes = plaintext.encode()
        p_int = int.from_bytes(plaintext_bytes, "big")
        ciphertext = pow(p_int, e, n)
        ciphertext_hex = hex(ciphertext)

        # Сохранение ключей и промежуточных данных для визуализации
        session['n'] = n
        session['d'] = d
        session['p_int'] = p_int
        session['ciphertext'] = ciphertext

        return render_template('rsa.html',
                               plaintext_hex=str(hex(p_int))[2:],
                               ciphertext=ciphertext_hex,
                               public_key=f"n={n}, e={e}",
                               private_key=f"n={n}, d={d}")

    return render_template('rsa.html')

@app.route('/rsa_decrypt', methods=['POST'])
def rsa_decrypt_page():
    if request.method == 'POST':
        ciphertext_hex = request.form['ciphertext']

        # Восстановление ключей
        n = session.get('n')
        d = session.get('d')

        # Дешифрование текста
        ciphertext = int(ciphertext_hex, 16)
        p_int = pow(ciphertext, d, n)
        decrypted_text = p_int.to_bytes((p_int.bit_length() + 7) // 8, 'big').decode()

        return render_template('rsa.html',
                               ciphertext=ciphertext_hex,
                               decrypted_text=decrypted_text,
                               private_key=f"n={n}, d={d}")

@app.route('/sha256', methods=['GET', 'POST'])
def sha256_page():
    if request.method == 'POST':
        message = request.form['message'].encode()
        sha256_hash = sha_256(message).hex()
        return render_template('sha256.html', sha256_hash=sha256_hash)

    return render_template('sha256.html')


if __name__ == '__main__':
    app.run(debug=True)