"""
app.py - Flask backend cho ung dung minh hoa AES
"""

import base64
import binascii
from flask import Flask, render_template, request, jsonify
from aes_matma import (
    key_expansion, pkcs7_pad, pkcs7_unpad,
    sub_bytes, inv_sub_bytes, shift_rows, inv_shift_rows,
    mix_columns, inv_mix_columns, add_round_key,
    ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt,
    generate_random_key, generate_random_iv, SBOX, RCON
)

app = Flask(__name__)

def _pad_ascii_to_length(text: str, length: int) -> bytes:
    b = text.encode('utf-8')
    if len(b) > length: raise ValueError(f"Chuỗi quá dài, tối đa {length} byte.")
    return b.ljust(length, b'\x00')

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/random/key')
def api_random_key():
    bits = int(request.args.get('bits', 128))
    if bits not in (128, 192, 256): return jsonify({'error': 'bits khong hop le'}), 400
    key = generate_random_key(bits)
    return jsonify({'hex': key.hex().upper(), 'bytes': list(key)})

@app.route('/api/random/iv')
def api_random_iv():
    iv = generate_random_iv()
    return jsonify({'hex': iv.hex().upper(), 'bytes': list(iv)})

def _verbose_key_expansion(key: bytes) -> dict:
    Nk = len(key) // 4; Nr = Nk + 6; w = [list(key[i:i+4]) for i in range(0, len(key), 4)]; steps = []
    for i in range(Nk, 4 * (Nr + 1)):
        step_info = {'i': i, 'Nk': Nk}; temp = w[i - 1][:]; step_info['w_im1'] = w[i-1][:]; step_info['w_iNk'] = w[i-Nk][:]
        if i % Nk == 0:
            rotated = temp[1:] + temp[:1]; step_info['rotated'] = rotated[:]; subbed = [SBOX[b] for b in rotated]; step_info['subbed'] = subbed[:]
            rcon_val = [RCON[i // Nk], 0, 0, 0]; step_info['rcon'] = rcon_val; xored_rcon = [s ^ r for s, r in zip(subbed, rcon_val)]; step_info['xored_rcon'] = xored_rcon
            final = [w[i - Nk][j] ^ xored_rcon[j] for j in range(4)]; step_info['type'] = 'rcon'
        elif Nk > 6 and i % Nk == 4:
            subbed = [SBOX[b] for b in temp]; step_info['subbed'] = subbed[:]; final = [w[i - Nk][j] ^ subbed[j] for j in range(4)]; step_info['type'] = 'sub'
        else:
            final = [w[i - Nk][j] ^ temp[j] for j in range(4)]; step_info['type'] = 'simple'
        step_info['result'] = final; w.append(final); steps.append(step_info)
    round_keys = [sum(w[i:i+4], []) for i in range(0, 4 * (Nr + 1), 4)]
    return {'key_bits': len(key) * 8, 'Nr': Nr, 'Nk': Nk, 'steps': steps, 'round_keys': [{'round': i, 'hex': bytes(rk).hex().upper(), 'bytes': rk} for i, rk in enumerate(round_keys)]}

def _collect_encrypt_steps(plaintext_block: bytes, key: bytes) -> dict:
    round_keys = key_expansion(key); Nr = len(round_keys) - 1; state = list(plaintext_block); rounds = []
    old_state = state[:]; state = add_round_key(state, round_keys[0])
    details = [{"pos": i, "state": old_state[i], "key": round_keys[0][i], "result": state[i]} for i in range(16)]
    rounds.append({'round': 0, 'label': 'Initial AddRoundKey (Block 0)', 'steps': [{'name': 'AddRoundKey', 'state': state[:], 'old_state': old_state[:], 'key': round_keys[0][:], 'details': details}]})
    for r in range(1, Nr):
        steps = []
        old_state = state[:]; state = sub_bytes(state); details = [{"pos": i, "in": old_state[i], "out": state[i]} for i in range(16)]
        steps.append({'name': 'SubBytes', 'state': state[:], 'old_state': old_state[:], 'details': details})
        old_state = state[:]; state = shift_rows(state); details = [{"row": 0, "shift": 0, "desc": "Không dịch", "before": [old_state[i] for i in [0,4,8,12]], "after": [state[i] for i in [0,4,8,12]]}, {"row": 1, "shift": 1, "desc": "Dịch trái 1", "before": [old_state[i] for i in [1,5,9,13]], "after": [state[i] for i in [5,9,13,1]]}, {"row": 2, "shift": 2, "desc": "Dịch trái 2", "before": [old_state[i] for i in [2,6,10,14]], "after": [state[i] for i in [10,14,2,6]]}, {"row": 3, "shift": 3, "desc": "Dịch trái 3", "before": [old_state[i] for i in [3,7,11,15]], "after": [state[i] for i in [15,3,7,11]]}]
        steps.append({'name': 'ShiftRows', 'state': state[:], 'old_state': old_state[:], 'details': details})
        old_state = state[:]; state = mix_columns(state); details = [{"col": i, "input": old_state[i*4:(i+1)*4], "output": state[i*4:(i+1)*4]} for i in range(4)]
        steps.append({'name': 'MixColumns', 'state': state[:], 'old_state': old_state[:], 'details': details})
        old_state = state[:]; state = add_round_key(state, round_keys[r]); details = [{"pos": i, "state": old_state[i], "key": round_keys[r][i], "result": state[i]} for i in range(16)]
        steps.append({'name': 'AddRoundKey', 'state': state[:], 'old_state': old_state[:], 'key': round_keys[r][:], 'details': details})
        rounds.append({'round': r, 'label': f'Round {r}', 'steps': steps})
    steps = []
    old_state = state[:]; state = sub_bytes(state); details = [{"pos": i, "in": old_state[i], "out": state[i]} for i in range(16)]
    steps.append({'name': 'SubBytes', 'state': state[:], 'old_state': old_state[:], 'details': details})
    old_state = state[:]; state = shift_rows(state); details = [{"row": 0, "shift": 0, "desc": "Không dịch", "before": [old_state[i] for i in [0,4,8,12]], "after": [state[i] for i in [0,4,8,12]]}, {"row": 1, "shift": 1, "desc": "Dịch trái 1", "before": [old_state[i] for i in [1,5,9,13]], "after": [state[i] for i in [5,9,13,1]]}, {"row": 2, "shift": 2, "desc": "Dịch trái 2", "before": [old_state[i] for i in [2,6,10,14]], "after": [state[i] for i in [10,14,2,6]]}, {"row": 3, "shift": 3, "desc": "Dịch trái 3", "before": [old_state[i] for i in [3,7,11,15]], "after": [state[i] for i in [15,3,7,11]]}]
    steps.append({'name': 'ShiftRows', 'state': state[:], 'old_state': old_state[:], 'details': details})
    old_state = state[:]; state = add_round_key(state, round_keys[Nr]); details = [{"pos": i, "state": old_state[i], "key": round_keys[Nr][i], "result": state[i]} for i in range(16)]
    steps.append({'name': 'AddRoundKey', 'state': state[:], 'old_state': old_state[:], 'key': round_keys[Nr][:], 'details': details})
    rounds.append({'round': Nr, 'label': f'Final Round {Nr}', 'steps': steps})
    return {'Nr': Nr, 'key_bits': len(key) * 8, 'plaintext': list(plaintext_block), 'ciphertext': state, 'round_keys': [rk[:] for rk in round_keys], 'rounds': rounds}

def _collect_decrypt_steps(ciphertext_block: bytes, key: bytes) -> dict:
    round_keys = key_expansion(key); Nr = len(round_keys) - 1; state = list(ciphertext_block); rounds = []
    old_state = state[:]; state = add_round_key(state, round_keys[Nr])
    details = [{"pos": i, "state": old_state[i], "key": round_keys[Nr][i], "result": state[i]} for i in range(16)]
    rounds.append({'round': Nr, 'label': f'Initial AddRoundKey (RK{Nr})', 'steps': [{'name': 'AddRoundKey', 'state': state[:], 'old_state': old_state[:], 'key': round_keys[Nr][:], 'details': details}]})
    for r in range(Nr - 1, 0, -1):
        steps = []
        old_state = state[:]; state = inv_shift_rows(state); details = [{"row": i, "shift": i, "desc": f"Dịch phải {i}", "before": [], "after": []} for i in range(4)]
        steps.append({'name': 'InvShiftRows', 'state': state[:], 'old_state': old_state[:], 'details': details})
        old_state = state[:]; state = inv_sub_bytes(state); details = [{"pos": i, "in": old_state[i], "out": state[i]} for i in range(16)]
        steps.append({'name': 'InvSubBytes', 'state': state[:], 'old_state': old_state[:], 'details': details})
        old_state = state[:]; state = add_round_key(state, round_keys[r]); details = [{"pos": i, "state": old_state[i], "key": round_keys[r][i], "result": state[i]} for i in range(16)]
        steps.append({'name': 'AddRoundKey', 'state': state[:], 'old_state': old_state[:], 'key': round_keys[r][:], 'details': details})
        old_state = state[:]; state = inv_mix_columns(state); details = [{"col": i, "input": old_state[i*4:(i+1)*4], "output": state[i*4:(i+1)*4]} for i in range(4)]
        steps.append({'name': 'InvMixColumns', 'state': state[:], 'old_state': old_state[:], 'details': details})
        rounds.append({'round': r, 'label': f'Round {r} (inverse)', 'steps': steps})
    steps = []
    old_state = state[:]; state = inv_shift_rows(state); details = [{"row": i, "shift": i, "desc": f"Dịch phải {i}", "before": [], "after": []} for i in range(4)]
    steps.append({'name': 'InvShiftRows', 'state': state[:], 'old_state': old_state[:], 'details': details})
    old_state = state[:]; state = inv_sub_bytes(state); details = [{"pos": i, "in": old_state[i], "out": state[i]} for i in range(16)]
    steps.append({'name': 'InvSubBytes', 'state': state[:], 'old_state': old_state[:], 'details': details})
    old_state = state[:]; state = add_round_key(state, round_keys[0]); details = [{"pos": i, "state": old_state[i], "key": round_keys[0][i], "result": state[i]} for i in range(16)]
    steps.append({'name': 'AddRoundKey', 'state': state[:], 'old_state': old_state[:], 'key': round_keys[0][:], 'details': details})
    rounds.append({'round': 0, 'label': 'Final Round 0 (inverse)', 'steps': steps})
    return {'Nr': Nr, 'key_bits': len(key) * 8, 'ciphertext': list(ciphertext_block), 'plaintext': state, 'round_keys': [rk[:] for rk in round_keys], 'rounds': rounds}

def _parse_hex_field(value: str, name: str, expected_len: int = None) -> bytes:
    try: b = bytes.fromhex(value.replace(' ', ''))
    except ValueError: raise ValueError(f"'{name}' khong phai HEX hop le.")
    if expected_len and len(b) != expected_len: raise ValueError(f"'{name}' phai {expected_len} byte.")
    return b

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    data = request.get_json(force=True)
    try:
        pt  = _parse_hex_field(data.get('plaintext_hex', ''), 'plaintext_hex')
        key_ascii = data.get('key_ascii', ''); key_bits = int(data.get('key_bits', 128)); key = _pad_ascii_to_length(key_ascii, key_bits // 8)
        mode = data.get('mode', 'ECB').upper(); verbose = bool(data.get('verbose', False))
        
        # Bắt đầu mã hóa
        if mode == 'ECB':
            ct = ecb_encrypt(pt, key); result = {'ciphertext_hex': ct.hex().upper(), 'ciphertext_b64': base64.b64encode(ct).decode()}
        
            if verbose:
                block = pkcs7_pad(pt)[:16]
                result['verbose'] = _collect_encrypt_steps(block, key)
                
        elif mode == 'CBC':
            iv_ascii = data.get('iv_ascii', '').strip(); iv = generate_random_iv() if not iv_ascii else _pad_ascii_to_length(iv_ascii, 16)
            ct = cbc_encrypt(pt, key, iv); result = {'ciphertext_hex': ct.hex().upper(), 'ciphertext_b64': base64.b64encode(ct).decode(), 'iv_hex': iv.hex().upper(), 'iv_generated': not iv_ascii}
           
            if verbose:
                block = bytes([p ^ i for p, i in zip(pkcs7_pad(pt)[:16], iv)])
                result['verbose'] = _collect_encrypt_steps(block, key)
        else: return jsonify({'error': 'Mode khong hop le'}), 400
        return jsonify(result)
    except Exception as e: return jsonify({'error': str(e)}), 400

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    data = request.get_json(force=True)
    try:
        ct  = _parse_hex_field(data.get('ciphertext_hex', ''), 'ciphertext_hex')
        key_ascii = data.get('key_ascii', ''); key_bits = int(data.get('key_bits', 128)); key = _pad_ascii_to_length(key_ascii, key_bits // 8)
        mode = data.get('mode', 'ECB').upper(); verbose = bool(data.get('verbose', False))
        
        if mode == 'ECB':
            pt = ecb_decrypt(ct, key); result = {'plaintext_hex': pt.hex().upper(), 'plaintext_ascii': pt.decode('utf-8', errors='replace')}
            
            if verbose and len(ct) >= 16:
                result['verbose'] = _collect_decrypt_steps(ct[:16], key)
                
        elif mode == 'CBC':
            iv_hex_raw = data.get('iv_hex', '').strip(); iv_ascii = data.get('iv_ascii', '').strip()
            if iv_hex_raw: iv = _parse_hex_field(iv_hex_raw, 'iv_hex', 16)
            elif iv_ascii: iv = _pad_ascii_to_length(iv_ascii, 16)
            else: return jsonify({'error': 'CBC cần IV'}), 400
            pt = cbc_decrypt(ct, key, iv); result = {'plaintext_hex': pt.hex().upper(), 'plaintext_ascii': pt.decode('utf-8', errors='replace')}
            # ĐÃ SỬA: Lấy block đầu tiên của ciphertext để trực quan hóa giải mã
            if verbose and len(ct) >= 16:
                result['verbose'] = _collect_decrypt_steps(ct[:16], key)
        else: return jsonify({'error': 'Mode khong hop le'}), 400
        return jsonify(result)
    except Exception as e: return jsonify({'error': str(e)}), 400

@app.route('/api/key_schedule', methods=['POST'])
def api_key_schedule():
    data = request.get_json(force=True)
    try:
        key_ascii = data.get('key_ascii', ''); key_bits = int(data.get('key_bits', 128)); key = _pad_ascii_to_length(key_ascii, key_bits // 8)
        return jsonify(_verbose_key_expansion(key))
    except Exception as e: return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)