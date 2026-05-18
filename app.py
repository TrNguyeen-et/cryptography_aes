"""
app.py - Flask backend cho ung dung minh hoa AES
Khoi dong: python app.py
Truy cap : http://127.0.0.1:5000
"""

import base64
import binascii
from flask import Flask, render_template, request, jsonify
from aes_matma import (
    key_expansion,
    pkcs7_pad, pkcs7_unpad,
    sub_bytes, inv_sub_bytes,
    shift_rows, inv_shift_rows,
    mix_columns, inv_mix_columns,
    add_round_key,
    aes_encrypt_block, aes_decrypt_block,
    ecb_encrypt, ecb_decrypt,
    cbc_encrypt, cbc_decrypt,
    generate_random_key, generate_random_iv,
)

app = Flask(__name__)

# ─────────────────────────────────────────────
#  TIEN ICH: PADDING ASCII CHO KEY VA IV
# ─────────────────────────────────────────────

def _pad_ascii_to_length(text: str, length: int) -> bytes:
    """Chuyển chuỗi ASCII thành bytes và padding bằng null byte (\x00) nếu chưa đủ độ dài."""
    b = text.encode('utf-8')
    if len(b) > length:
        raise ValueError(f"Chuỗi quá dài, tối đa {length} byte (hiện có {len(b)} byte).")
    return b.ljust(length, b'\x00') # Thêm \x00 vào cuối cho đủ độ dài


# ─────────────────────────────────────────────
#  TRANG CHINH
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


# ─────────────────────────────────────────────
#  API: SINH NGAU NHIEN
# ─────────────────────────────────────────────

@app.route('/api/random/key')
def api_random_key():
    bits = int(request.args.get('bits', 128))
    if bits not in (128, 192, 256):
        return jsonify({'error': 'bits phai la 128, 192 hoac 256'}), 400
    key = generate_random_key(bits)
    return jsonify({'hex': key.hex().upper(), 'bytes': list(key)})

@app.route('/api/random/iv')
def api_random_iv():
    iv = generate_random_iv()
    return jsonify({'hex': iv.hex().upper(), 'bytes': list(iv)})


# ─────────────────────────────────────────────
#  API: VERBOSE
# ─────────────────────────────────────────────

def _collect_encrypt_steps(plaintext_block: bytes, key: bytes) -> dict:
    round_keys = key_expansion(key)
    Nr = len(round_keys) - 1
    state = list(plaintext_block)
    rounds = []

    state = add_round_key(state, round_keys[0])
    rounds.append({'round': 0, 'label': 'Initial AddRoundKey', 'steps': [{'name': 'AddRoundKey', 'state': state[:], 'key': round_keys[0][:]}]})

    for r in range(1, Nr):
        steps = []
        state = sub_bytes(state); steps.append({'name': 'SubBytes', 'state': state[:]})
        state = shift_rows(state); steps.append({'name': 'ShiftRows', 'state': state[:]})
        state = mix_columns(state); steps.append({'name': 'MixColumns', 'state': state[:]})
        state = add_round_key(state, round_keys[r]); steps.append({'name': 'AddRoundKey', 'state': state[:], 'key': round_keys[r][:]})
        rounds.append({'round': r, 'label': f'Round {r}', 'steps': steps})

    steps = []
    state = sub_bytes(state); steps.append({'name': 'SubBytes', 'state': state[:]})
    state = shift_rows(state); steps.append({'name': 'ShiftRows', 'state': state[:]})
    state = add_round_key(state, round_keys[Nr]); steps.append({'name': 'AddRoundKey', 'state': state[:], 'key': round_keys[Nr][:]})
    rounds.append({'round': Nr, 'label': f'Final Round {Nr}', 'steps': steps})

    return {'Nr': Nr, 'key_bits': len(key) * 8, 'plaintext': list(plaintext_block), 'ciphertext': state, 'round_keys': [rk[:] for rk in round_keys], 'rounds': rounds}


def _collect_decrypt_steps(ciphertext_block: bytes, key: bytes) -> dict:
    round_keys = key_expansion(key)
    Nr = len(round_keys) - 1
    state = list(ciphertext_block)
    rounds = []

    state = add_round_key(state, round_keys[Nr])
    rounds.append({'round': Nr, 'label': f'Initial AddRoundKey (RK{Nr})', 'steps': [{'name': 'AddRoundKey', 'state': state[:], 'key': round_keys[Nr][:]}]})

    for r in range(Nr - 1, 0, -1):
        steps = []
        state = inv_shift_rows(state); steps.append({'name': 'InvShiftRows', 'state': state[:]})
        state = inv_sub_bytes(state); steps.append({'name': 'InvSubBytes', 'state': state[:]})
        state = add_round_key(state, round_keys[r]); steps.append({'name': 'AddRoundKey', 'state': state[:], 'key': round_keys[r][:]})
        state = inv_mix_columns(state); steps.append({'name': 'InvMixColumns', 'state': state[:]})
        rounds.append({'round': r, 'label': f'Round {r} (inverse)', 'steps': steps})

    steps = []
    state = inv_shift_rows(state); steps.append({'name': 'InvShiftRows', 'state': state[:]})
    state = inv_sub_bytes(state); steps.append({'name': 'InvSubBytes', 'state': state[:]})
    state = add_round_key(state, round_keys[0]); steps.append({'name': 'AddRoundKey', 'state': state[:], 'key': round_keys[0][:]})
    rounds.append({'round': 0, 'label': 'Final Round 0 (inverse)', 'steps': steps})

    return {'Nr': Nr, 'key_bits': len(key) * 8, 'ciphertext': list(ciphertext_block), 'plaintext': state, 'round_keys': [rk[:] for rk in round_keys], 'rounds': rounds}


# ─────────────────────────────────────────────
#  API: MA HOA / GIAI MA
# ─────────────────────────────────────────────

def _parse_hex_field(value: str, name: str, expected_len: int = None) -> bytes:
    try:
        b = bytes.fromhex(value.replace(' ', '').replace(':', ''))
    except ValueError:
        raise ValueError(f"'{name}' khong phai HEX hop le.")
    if expected_len and len(b) != expected_len:
        raise ValueError(f"'{name}' phai {expected_len} byte, dang co {len(b)} byte.")
    return b


@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    data = request.get_json(force=True)
    try:
        pt  = _parse_hex_field(data.get('plaintext_hex', ''), 'plaintext_hex')
        
        # Xử lý Key: Nhận ASCII, pad với null byte nếu ngắn
        key_ascii = data.get('key_ascii', '')
        key_bits = int(data.get('key_bits', 128))
        if key_bits not in (128, 192, 256):
            return jsonify({'error': 'key_bits không hợp lệ'}), 400
        key_len = key_bits // 8
        try:
            key = _pad_ascii_to_length(key_ascii, key_len)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        mode    = data.get('mode', 'ECB').upper()
        verbose = bool(data.get('verbose', False))

        if mode == 'ECB':
            ct = ecb_encrypt(pt, key)
            result = {'ciphertext_hex': ct.hex().upper(), 'ciphertext_b64': base64.b64encode(ct).decode()}
            if verbose and len(pt) <= 16:
                block = pkcs7_pad(pt)[:16]
                result['verbose'] = _collect_encrypt_steps(block, key)

        elif mode == 'CBC':
            # Xử lý IV: Nhận ASCII, pad với null byte. Nếu trống thì sinh ngẫu nhiên
            iv_ascii = data.get('iv_ascii', '').strip()
            generated_iv = False
            if not iv_ascii:
                iv = generate_random_iv()
                generated_iv = True
            else:
                try:
                    iv = _pad_ascii_to_length(iv_ascii, 16)
                except ValueError as e:
                    return jsonify({'error': f"IV lỗi: {str(e)}"}), 400

            ct = cbc_encrypt(pt, key, iv)
            result = {
                'ciphertext_hex': ct.hex().upper(),
                'ciphertext_b64': base64.b64encode(ct).decode(),
                'iv_hex': iv.hex().upper(), # Luôn trả về IV dạng HEX để người dùng copy giải mã
                'iv_generated': generated_iv
            }
            if verbose and len(pt) <= 16:
                block = bytes([p ^ i for p, i in zip(pkcs7_pad(pt)[:16], iv)])
                result['verbose'] = _collect_encrypt_steps(block, key)
        else:
            return jsonify({'error': f"Mode '{mode}' khong hop le. Chon ECB hoac CBC."}), 400

        return jsonify(result)

    except (ValueError, KeyError) as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    data = request.get_json(force=True)
    try:
        ct  = _parse_hex_field(data.get('ciphertext_hex', ''), 'ciphertext_hex')
        
        # Xử lý Key ASCII
        key_ascii = data.get('key_ascii', '')
        key_bits = int(data.get('key_bits', 128))
        if key_bits not in (128, 192, 256):
            return jsonify({'error': 'key_bits không hợp lệ'}), 400
        key_len = key_bits // 8
        try:
            key = _pad_ascii_to_length(key_ascii, key_len)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        mode    = data.get('mode', 'ECB').upper()
        verbose = bool(data.get('verbose', False))

        if mode == 'ECB':
            pt = ecb_decrypt(ct, key)
            result = {'plaintext_hex': pt.hex().upper(), 'plaintext_ascii': pt.decode('utf-8', errors='replace')}
            if verbose and len(ct) == 16:
                result['verbose'] = _collect_decrypt_steps(ct, key)

        elif mode == 'CBC':
            # Giải mã ưu tiên IV_HEX (copy từ kết quả mã hóa), nếu không có thì dùng IV_ASCII
            iv_hex_raw = data.get('iv_hex', '').strip()
            iv_ascii = data.get('iv_ascii', '').strip()
            
            if iv_hex_raw:
                iv = _parse_hex_field(iv_hex_raw, 'iv_hex', 16)
            elif iv_ascii:
                try:
                    iv = _pad_ascii_to_length(iv_ascii, 16)
                except ValueError as e:
                    return jsonify({'error': f"IV lỗi: {str(e)}"}), 400
            else:
                return jsonify({'error': 'CBC cần IV để giải mã. Vui lòng nhập IV (HOẶC dán IV HEX từ lúc mã hóa).'}), 400

            pt = cbc_decrypt(ct, key, iv)
            result = {'plaintext_hex': pt.hex().upper(), 'plaintext_ascii': pt.decode('utf-8', errors='replace')}
            if verbose and len(ct) == 16:
                result['verbose'] = _collect_decrypt_steps(ct, key)
        else:
            return jsonify({'error': f"Mode '{mode}' khong hop le."}), 400

        return jsonify(result)

    except (ValueError, KeyError) as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/key_schedule', methods=['POST'])
def api_key_schedule():
    data = request.get_json(force=True)
    try:
        key_ascii = data.get('key_ascii', '')
        key_bits = int(data.get('key_bits', 128))
        key_len = key_bits // 8
        key = _pad_ascii_to_length(key_ascii, key_len)

        rks = key_expansion(key)
        return jsonify({
            'key_bits': len(key) * 8,
            'Nr': len(rks) - 1,
            'round_keys': [
                {'round': i, 'hex': bytes(rk).hex().upper(), 'bytes': rk}
                for i, rk in enumerate(rks)
            ]
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)