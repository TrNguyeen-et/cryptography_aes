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
    ctr_encrypt, ctr_decrypt,
    generate_random_key, generate_random_iv, generate_random_nonce,
)

app = Flask(__name__)


# ─────────────────────────────────────────────
#  TRANG CHINH
# ─────────────────────────────────────────────

@app.route('/')
def index():
    """Tra ve trang chinh cua ung dung."""
    return render_template('index.html')


# ─────────────────────────────────────────────
#  API: SINH NGAU NHIEN
# ─────────────────────────────────────────────

@app.route('/api/random/key')
def api_random_key():
    """Sinh khoa ngau nhien theo do dai yeu cau (128/192/256 bit)."""
    bits = int(request.args.get('bits', 128))
    if bits not in (128, 192, 256):
        return jsonify({'error': 'bits phai la 128, 192 hoac 256'}), 400
    key = generate_random_key(bits)
    return jsonify({'hex': key.hex().upper(), 'bytes': list(key)})


@app.route('/api/random/iv')
def api_random_iv():
    """Sinh IV ngau nhien 16 byte (dung cho CBC)."""
    iv = generate_random_iv()
    return jsonify({'hex': iv.hex().upper(), 'bytes': list(iv)})


@app.route('/api/random/nonce')
def api_random_nonce():
    """Sinh Nonce ngau nhien 8 byte (dung cho CTR)."""
    nonce = generate_random_nonce()
    return jsonify({'hex': nonce.hex().upper(), 'bytes': list(nonce)})


# ─────────────────────────────────────────────
#  API: VERBOSE - HIEN THI TUNG BUOC MA HOA
# ─────────────────────────────────────────────

def _collect_encrypt_steps(plaintext_block: bytes, key: bytes) -> dict:
    """
    Ham noi bo: Thuc hien ma hoa 1 khoi va ghi lai trang thai
    sau moi buoc cua tung vong de tra ve frontend.
    Tra ve: dict chua cac vong va trang thai.
    """
    round_keys = key_expansion(key)
    Nr = len(round_keys) - 1
    state = list(plaintext_block)
    rounds = []

    # Vong 0: chi co AddRoundKey
    state = add_round_key(state, round_keys[0])
    rounds.append({
        'round': 0,
        'label': 'Initial AddRoundKey',
        'steps': [
            {'name': 'AddRoundKey', 'state': state[:], 'key': round_keys[0][:]}
        ]
    })

    # Cac vong chinh 1 -> Nr-1
    for r in range(1, Nr):
        steps = []
        state = sub_bytes(state)
        steps.append({'name': 'SubBytes', 'state': state[:]})
        state = shift_rows(state)
        steps.append({'name': 'ShiftRows', 'state': state[:]})
        state = mix_columns(state)
        steps.append({'name': 'MixColumns', 'state': state[:]})
        state = add_round_key(state, round_keys[r])
        steps.append({'name': 'AddRoundKey', 'state': state[:], 'key': round_keys[r][:]})
        rounds.append({'round': r, 'label': f'Round {r}', 'steps': steps})

    # Vong cuoi Nr: khong co MixColumns
    steps = []
    state = sub_bytes(state)
    steps.append({'name': 'SubBytes', 'state': state[:]})
    state = shift_rows(state)
    steps.append({'name': 'ShiftRows', 'state': state[:]})
    state = add_round_key(state, round_keys[Nr])
    steps.append({'name': 'AddRoundKey', 'state': state[:], 'key': round_keys[Nr][:]})
    rounds.append({'round': Nr, 'label': f'Final Round {Nr}', 'steps': steps})

    return {
        'Nr': Nr,
        'key_bits': len(key) * 8,
        'plaintext': list(plaintext_block),
        'ciphertext': state,
        'round_keys': [rk[:] for rk in round_keys],
        'rounds': rounds,
    }


def _collect_decrypt_steps(ciphertext_block: bytes, key: bytes) -> dict:
    """
    Ham noi bo: Thuc hien giai ma 1 khoi va ghi lai trang thai
    sau moi buoc cua tung vong nguoc.
    """
    round_keys = key_expansion(key)
    Nr = len(round_keys) - 1
    state = list(ciphertext_block)
    rounds = []

    # Buoc dau: AddRoundKey voi khoa vong cuoi
    state = add_round_key(state, round_keys[Nr])
    rounds.append({
        'round': Nr,
        'label': f'Initial AddRoundKey (RK{Nr})',
        'steps': [
            {'name': 'AddRoundKey', 'state': state[:], 'key': round_keys[Nr][:]}
        ]
    })

    # Cac vong nguoc Nr-1 -> 1
    for r in range(Nr - 1, 0, -1):
        steps = []
        state = inv_shift_rows(state)
        steps.append({'name': 'InvShiftRows', 'state': state[:]})
        state = inv_sub_bytes(state)
        steps.append({'name': 'InvSubBytes', 'state': state[:]})
        state = add_round_key(state, round_keys[r])
        steps.append({'name': 'AddRoundKey', 'state': state[:], 'key': round_keys[r][:]})
        state = inv_mix_columns(state)
        steps.append({'name': 'InvMixColumns', 'state': state[:]})
        rounds.append({'round': r, 'label': f'Round {r} (inverse)', 'steps': steps})

    # Vong cuoi nguoc: khong co InvMixColumns
    steps = []
    state = inv_shift_rows(state)
    steps.append({'name': 'InvShiftRows', 'state': state[:]})
    state = inv_sub_bytes(state)
    steps.append({'name': 'InvSubBytes', 'state': state[:]})
    state = add_round_key(state, round_keys[0])
    steps.append({'name': 'AddRoundKey', 'state': state[:], 'key': round_keys[0][:]})
    rounds.append({'round': 0, 'label': 'Final Round 0 (inverse)', 'steps': steps})

    return {
        'Nr': Nr,
        'key_bits': len(key) * 8,
        'ciphertext': list(ciphertext_block),
        'plaintext': state,
        'round_keys': [rk[:] for rk in round_keys],
        'rounds': rounds,
    }


# ─────────────────────────────────────────────
#  API: MA HOA / GIAI MA
# ─────────────────────────────────────────────

def _parse_hex_field(value: str, name: str, expected_len: int = None) -> bytes:
    """Ham noi bo: Chuyen chuoi HEX thanh bytes, kem kiem tra do dai."""
    try:
        b = bytes.fromhex(value.replace(' ', '').replace(':', ''))
    except ValueError:
        raise ValueError(f"'{name}' khong phai HEX hop le.")
    if expected_len and len(b) != expected_len:
        raise ValueError(f"'{name}' phai {expected_len} byte, dang co {len(b)} byte.")
    return b


@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    """
    API ma hoa AES. Nhan JSON:
      {
        "plaintext_hex" : "...",   // plaintext dang HEX
        "key_hex"       : "...",   // khoa 16/24/32 byte dang HEX
        "mode"          : "ECB" | "CBC" | "CTR",
        "iv_hex"        : "...",   // chi can cho CBC (16 byte)
        "nonce_hex"     : "...",   // chi can cho CTR (8 byte)
        "verbose"       : true     // tra ve chi tiet tung vong (chi ECB/CBC 1 khoi)
      }
    Tra ve JSON chua ciphertext va (neu verbose) chi tiet tung vong.
    """
    data = request.get_json(force=True)
    try:
        pt  = _parse_hex_field(data.get('plaintext_hex', ''), 'plaintext_hex')
        key = _parse_hex_field(data.get('key_hex', ''), 'key_hex')
        if len(key) not in (16, 24, 32):
            raise ValueError("key_hex phai 16, 24 hoac 32 byte.")
        mode    = data.get('mode', 'CBC').upper()
        verbose = bool(data.get('verbose', False))

        if mode == 'ECB':
            ct = ecb_encrypt(pt, key)
            result = {'ciphertext_hex': ct.hex().upper(),
                      'ciphertext_b64': base64.b64encode(ct).decode()}
            if verbose and len(pt) <= 16:
                block = pkcs7_pad(pt)[:16]
                result['verbose'] = _collect_encrypt_steps(block, key)

        elif mode == 'CBC':
            iv = _parse_hex_field(data.get('iv_hex', ''), 'iv_hex', 16)
            ct = cbc_encrypt(pt, key, iv)
            result = {'ciphertext_hex': ct.hex().upper(),
                      'ciphertext_b64': base64.b64encode(ct).decode()}
            if verbose and len(pt) <= 16:
                block = bytes([p ^ i for p, i in zip(pkcs7_pad(pt)[:16], iv)])
                result['verbose'] = _collect_encrypt_steps(block, key)

        elif mode == 'CTR':
            nonce = _parse_hex_field(data.get('nonce_hex', ''), 'nonce_hex', 8)
            ct = ctr_encrypt(pt, key, nonce)
            result = {'ciphertext_hex': ct.hex().upper(),
                      'ciphertext_b64': base64.b64encode(ct).decode()}
        else:
            return jsonify({'error': f"Mode '{mode}' khong hop le. Chon ECB, CBC, CTR."}), 400

        return jsonify(result)

    except (ValueError, KeyError) as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    """
    API giai ma AES. Nhan JSON tuong tu /api/encrypt nhung voi ciphertext_hex.
    Tra ve JSON chua plaintext goc.
    """
    data = request.get_json(force=True)
    try:
        ct  = _parse_hex_field(data.get('ciphertext_hex', ''), 'ciphertext_hex')
        key = _parse_hex_field(data.get('key_hex', ''), 'key_hex')
        if len(key) not in (16, 24, 32):
            raise ValueError("key_hex phai 16, 24 hoac 32 byte.")
        mode    = data.get('mode', 'CBC').upper()
        verbose = bool(data.get('verbose', False))

        if mode == 'ECB':
            pt = ecb_decrypt(ct, key)
            result = {'plaintext_hex': pt.hex().upper(),
                      'plaintext_ascii': pt.decode('utf-8', errors='replace')}
            if verbose and len(ct) == 16:
                result['verbose'] = _collect_decrypt_steps(ct, key)

        elif mode == 'CBC':
            iv = _parse_hex_field(data.get('iv_hex', ''), 'iv_hex', 16)
            pt = cbc_decrypt(ct, key, iv)
            result = {'plaintext_hex': pt.hex().upper(),
                      'plaintext_ascii': pt.decode('utf-8', errors='replace')}
            if verbose and len(ct) == 16:
                result['verbose'] = _collect_decrypt_steps(ct, key)

        elif mode == 'CTR':
            nonce = _parse_hex_field(data.get('nonce_hex', ''), 'nonce_hex', 8)
            pt = ctr_decrypt(ct, key, nonce)
            result = {'plaintext_hex': pt.hex().upper(),
                      'plaintext_ascii': pt.decode('utf-8', errors='replace')}
        else:
            return jsonify({'error': f"Mode '{mode}' khong hop le."}), 400

        return jsonify(result)

    except (ValueError, KeyError) as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/key_schedule', methods=['POST'])
def api_key_schedule():
    """
    API hien thi Key Schedule (tat ca cac round key duoc sinh tu khoa goc).
    Nhan JSON: { "key_hex": "..." }
    Tra ve danh sach cac round key dang HEX.
    """
    data = request.get_json(force=True)
    try:
        key = _parse_hex_field(data.get('key_hex', ''), 'key_hex')
        if len(key) not in (16, 24, 32):
            raise ValueError("key_hex phai 16, 24 hoac 32 byte.")
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


# ─────────────────────────────────────────────
#  CHAY UNG DUNG
# ─────────────────────────────────────────────

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)