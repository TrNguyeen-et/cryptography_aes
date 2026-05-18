"""
=============================================================
  FILE: aes_matma.py
  MO TA: Cai dat thuat toan ma hoa AES (Advanced Encryption Standard)
         ho tro 3 do dai khoa: 128-bit, 192-bit, 256-bit
         ho tro 3 che do: ECB, CBC, CTR
  TAC GIA: (Vuong Truong Nguyen)
  NGAY:    2025
=============================================================

HUONG DAN SU DUNG NHANH:
  python aes_matma.py              --> Chay menu tuong tac
  python aes_matma.py --test       --> Chay bo kiem tra tu dong
  python aes_matma.py --help       --> Xem huong dan chi tiet

CAU TRUC FILE:
  [1] Hang so (S-Box, RCON)
  [2] Cac phep bien doi co ban (SubBytes, ShiftRows, MixColumns, AddRoundKey)
  [3] Mo rong khoa (Key Expansion / Key Schedule)
  [4] Ma hoa / Giai ma tung khoi (Block Encrypt / Decrypt)
  [5] Cac che do van hanh (ECB, CBC, CTR)
  [6] Tien ich (Padding, format, hien thi)
  [7] Kiem tra tu dong (so sanh voi PyCryptodome)
  [8] Menu tuong tac cho nguoi dung
  [9] Diem chay chinh
"""

import os
import sys
import base64
import binascii
import random
import struct


# ==============================================================
#  [1] HANG SO CHUAN (LOOKUP TABLES)
# ==============================================================

# S-Box: Bang tra cuu 256 phan tu, dung trong SubBytes va Key Expansion.
# Moi byte dau vao duoc thay the bang byte tuong ung trong bang nay.
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

# Inverse S-Box: Bang tra cuu nguoc cua SBOX, dung trong InvSubBytes khi giai ma.
ISBOX = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
]

# RCON: Round Constant, dung trong qua trinh mo rong khoa (Key Schedule).
# RCON[i] = 2^(i-1) trong truong GF(2^8).
RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


# ==============================================================
#  [2] CAC PHEP BIEN DOI CO BAN (CORE TRANSFORMATIONS)
# ==============================================================

def sub_bytes(state: list) -> list:
    """
    SubBytes: Thay the tung byte trong state bang gia tri tuong ung trong SBOX.
    Tao tinh phi tuyen (non-linearity) cho thuat toan.
    Vi du: byte 0x00 -> 0x63, byte 0xFF -> 0x16
    """
    return [SBOX[b] for b in state]


def inv_sub_bytes(state: list) -> list:
    """
    InvSubBytes: Phep bien doi nguoc cua SubBytes, dung khi giai ma.
    Tra cuu trong bang ISBOX thay vi SBOX.
    """
    return [ISBOX[b] for b in state]


def shift_rows(state: list) -> list:
    """
    ShiftRows: Dich vong trai tung hang trong state theo chieu quy dinh AES.
    State duoc luu theo cot (column-major), nen vi tri thay doi nhu sau:
      - Hang 0: khong dich   (0,4,8,12  -> 0,4,8,12)
      - Hang 1: dich trai 1  (1,5,9,13  -> 5,9,13,1)
      - Hang 2: dich trai 2  (2,6,10,14 -> 10,14,2,6)
      - Hang 3: dich trai 3  (3,7,11,15 -> 15,3,7,11)
    """
    return [
        state[0],  state[5],  state[10], state[15],
        state[4],  state[9],  state[14], state[3],
        state[8],  state[13], state[2],  state[7],
        state[12], state[1],  state[6],  state[11],
    ]


def inv_shift_rows(state: list) -> list:
    """
    InvShiftRows: Phep bien doi nguoc cua ShiftRows (dich phai).
    Dich vong phai de hoan tac tac dong cua ShiftRows.
    """
    return [
        state[0],  state[13], state[10], state[7],
        state[4],  state[1],  state[14], state[11],
        state[8],  state[5],  state[2],  state[15],
        state[12], state[9],  state[6],  state[3],
    ]


def _xtime(a: int) -> int:
    """
    Ham noi bo: Nhan mot byte voi x (= 0x02) trong truong GF(2^8).
    Neu bit cao nhat la 1, XOR voi da thuc khu tuyen 0x1B sau khi dich.
    Day la phep toan co ban de xay dung cac phep nhan GF(2^8) khac.
    """
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


# --- Cac phep nhan GF(2^8) dung cho InvMixColumns ---
def _mul09(a: int) -> int: return _xtime(_xtime(_xtime(a))) ^ a
def _mul0b(a: int) -> int: return _xtime(_xtime(_xtime(a))) ^ _xtime(a) ^ a
def _mul0d(a: int) -> int: return _xtime(_xtime(_xtime(a))) ^ _xtime(_xtime(a)) ^ a
def _mul0e(a: int) -> int: return _xtime(_xtime(_xtime(a))) ^ _xtime(_xtime(a)) ^ _xtime(a)


def _mix_col(col: list) -> list:
    """
    Ham noi bo: Tron mot cot don (4 byte) theo phep nhan ma tran AES.
    Ma tran nhan:
      |2 3 1 1|   |a0|
      |1 2 3 1| x |a1|
      |1 1 2 3|   |a2|
      |3 1 1 2|   |a3|
    """
    a = col
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    return [
        a[0] ^ t ^ _xtime(a[0] ^ a[1]),
        a[1] ^ t ^ _xtime(a[1] ^ a[2]),
        a[2] ^ t ^ _xtime(a[2] ^ a[3]),
        a[3] ^ t ^ _xtime(a[3] ^ u),
    ]


def _inv_mix_col(col: list) -> list:
    """
    Ham noi bo: Giai tron mot cot don theo ma tran nghich cua AES.
    Ma tran nhan:
      |14 11 13  9|   |a0|
      | 9 14 11 13| x |a1|
      |13  9 14 11|   |a2|
      |11 13  9 14|   |a3|
    """
    a = col
    return [
        _mul0e(a[0]) ^ _mul0b(a[1]) ^ _mul0d(a[2]) ^ _mul09(a[3]),
        _mul09(a[0]) ^ _mul0e(a[1]) ^ _mul0b(a[2]) ^ _mul0d(a[3]),
        _mul0d(a[0]) ^ _mul09(a[1]) ^ _mul0e(a[2]) ^ _mul0b(a[3]),
        _mul0b(a[0]) ^ _mul0d(a[1]) ^ _mul09(a[2]) ^ _mul0e(a[3]),
    ]


def mix_columns(state: list) -> list:
    """
    MixColumns: Tron 4 cot cua state de tao tinh khuyech tan (diffusion).
    Moi cot 4 byte duoc xu ly doc lap bang phep nhan ma tran GF(2^8).
    """
    result = []
    for i in range(4):
        result.extend(_mix_col(state[i*4 : i*4+4]))
    return result


def inv_mix_columns(state: list) -> list:
    """
    InvMixColumns: Phep bien doi nguoc cua MixColumns, dung khi giai ma.
    """
    result = []
    for i in range(4):
        result.extend(_inv_mix_col(state[i*4 : i*4+4]))
    return result


def add_round_key(state: list, round_key: list) -> list:
    """
    AddRoundKey: XOR tung byte cua state voi khoa vong tuong ung.
    Day la buoc duy nhat trong AES su dung truc tiep gia tri khoa.
    round_key: danh sach 16 byte (khoa vong cua vong hien tai).
    """
    return [s ^ k for s, k in zip(state, round_key)]


# ==============================================================
#  [3] MO RONG KHOA (KEY EXPANSION / KEY SCHEDULE)
# ==============================================================

def key_expansion(key: bytes) -> list:
    """
    Tao tap hop cac khoa vong (round keys) tu khoa goc.

    AES su dung so vong Nr va so word Nk phu thuoc vao do dai khoa:
      - 128-bit (16 byte): Nk=4, Nr=10 -> 11 khoa vong
      - 192-bit (24 byte): Nk=6, Nr=12 -> 13 khoa vong
      - 256-bit (32 byte): Nk=8, Nr=14 -> 15 khoa vong

    Quy trinh tao moi word w[i]:
      - Neu i chia het cho Nk: RotWord -> SubWord -> XOR RCON
      - Neu Nk=8 va i%Nk==4  : them buoc SubWord (dac biet AES-256)
      - Con lai: w[i] = w[i-1] XOR w[i-Nk]

    Tra ve: danh sach cac khoa vong, moi khoa vong la list 16 byte.
    """
    Nk = len(key) // 4
    Nr = Nk + 6
    # Khoi tao cac word dau tien tu khoa goc
    w = [list(key[i:i+4]) for i in range(0, len(key), 4)]

    for i in range(Nk, 4 * (Nr + 1)):
        temp = w[i - 1][:]
        if i % Nk == 0:
            # RotWord: xoay vong trai 1 byte
            temp = temp[1:] + temp[:1]
            # SubWord: ap dung S-Box cho tung byte
            temp = [SBOX[b] for b in temp]
            # XOR voi hang so vong (Round Constant)
            temp[0] ^= RCON[i // Nk]
        elif Nk > 6 and i % Nk == 4:
            # Buoc SubWord bo sung chi co trong AES-256
            temp = [SBOX[b] for b in temp]
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])

    # Gom cac word thanh tung khoa vong 16 byte
    return [sum(w[i:i+4], []) for i in range(0, 4 * (Nr + 1), 4)]


# ==============================================================
#  [4] MA HOA / GIAI MA TUNG KHOI 16 BYTE (BLOCK CIPHER)
# ==============================================================

def aes_encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """
    Ma hoa mot khoi 16 byte duy nhat voi khoa da cho.

    Dau vao:
      plaintext : bytes, do dai chinh xac 16 byte
      key       : bytes, do dai 16 / 24 / 32 byte (AES-128/192/256)

    Dau ra:
      bytes, 16 byte da ma hoa

    Cac buoc thuc hien:
      1. AddRoundKey voi khoa vong dau (round 0)
      2. Vong 1 den Nr-1: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
      3. Vong cuoi Nr   : SubBytes -> ShiftRows -> AddRoundKey (khong MixColumns)
    """
    if len(plaintext) != 16:
        raise ValueError("Plaintext phai chinh xac 16 byte.")
    if len(key) not in (16, 24, 32):
        raise ValueError("Key phai la 16, 24 hoac 32 byte.")

    state = list(plaintext)
    round_keys = key_expansion(key)
    Nr = len(round_keys) - 1

    state = add_round_key(state, round_keys[0])

    for r in range(1, Nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])

    # Vong cuoi: khong co MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[Nr])

    return bytes(state)


def aes_decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    """
    Giai ma mot khoi 16 byte duy nhat voi khoa da cho.

    Dau vao:
      ciphertext : bytes, do dai chinh xac 16 byte
      key        : bytes, do dai 16 / 24 / 32 byte

    Dau ra:
      bytes, 16 byte ban ro (plaintext)

    Cac buoc thuc hien (nguoc voi ma hoa):
      1. AddRoundKey voi khoa vong cuoi (round Nr)
      2. Vong Nr-1 xuong 1: InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
      3. Vong dau (round 0): InvShiftRows -> InvSubBytes -> AddRoundKey
    """
    if len(ciphertext) != 16:
        raise ValueError("Ciphertext phai chinh xac 16 byte.")
    if len(key) not in (16, 24, 32):
        raise ValueError("Key phai la 16, 24 hoac 32 byte.")

    state = list(ciphertext)
    round_keys = key_expansion(key)
    Nr = len(round_keys) - 1

    state = add_round_key(state, round_keys[Nr])

    for r in range(Nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)

    # Vong dau: khong co InvMixColumns
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return bytes(state)


def aes_encrypt_block_verbose(plaintext: bytes, key: bytes, block_idx: int = 0) -> bytes:
    """
    Ma hoa mot khoi voi che do verbose: hien thi trang thai sau moi buoc cua tung vong.

    Dau vao:
      plaintext : bytes 16 byte can ma hoa
      key       : bytes khoa AES
      block_idx : so thu tu khoi (de hien thi)

    Dau ra:
      bytes, 16 byte da ma hoa (giong aes_encrypt_block)

    Muc dich: dung de hoc, kiem tra, debug thuat toan AES.
    """
    if len(plaintext) != 16 or len(key) not in (16, 24, 32):
        raise ValueError("Plaintext phai 16 byte, Key phai 16/24/32 byte.")

    def fmt(s): return ' '.join(f'{b:02X}' for b in s)

    state = list(plaintext)
    round_keys = key_expansion(key)
    Nr = len(round_keys) - 1

    print(f"\n{'='*60}")
    print(f"  VERBOSE MA HOA - Khoi #{block_idx}")
    print(f"{'='*60}")
    print(f"  Plaintext   : {fmt(state)}")
    print(f"  Key ({len(key)*8}-bit): {fmt(key)}")
    print(f"  So vong Nr  : {Nr}")
    print(f"  Round Key 0 : {fmt(round_keys[0])}")

    state = add_round_key(state, round_keys[0])
    print(f"\n  [Vong 0] AddRoundKey    : {fmt(state)}")

    for r in range(1, Nr):
        print(f"\n  --- Vong {r:2d} ---")
        state = sub_bytes(state)
        print(f"  SubBytes    : {fmt(state)}")
        state = shift_rows(state)
        print(f"  ShiftRows   : {fmt(state)}")
        state = mix_columns(state)
        print(f"  MixColumns  : {fmt(state)}")
        state = add_round_key(state, round_keys[r])
        print(f"  AddRoundKey : {fmt(state)}  (RK{r}: {fmt(round_keys[r])})")

    print(f"\n  --- Vong cuoi {Nr} (khong MixColumns) ---")
    state = sub_bytes(state)
    print(f"  SubBytes    : {fmt(state)}")
    state = shift_rows(state)
    print(f"  ShiftRows   : {fmt(state)}")
    state = add_round_key(state, round_keys[Nr])
    print(f"  AddRoundKey : {fmt(state)}  (RK{Nr}: {fmt(round_keys[Nr])})")

    result = bytes(state)
    print(f"\n  => Ciphertext: {fmt(result)}")
    return result


def aes_decrypt_block_verbose(ciphertext: bytes, key: bytes, block_idx: int = 0) -> bytes:
    """
    Giai ma mot khoi voi che do verbose: hien thi trang thai sau moi buoc.

    Dau vao:
      ciphertext : bytes 16 byte can giai ma
      key        : bytes khoa AES
      block_idx  : so thu tu khoi

    Dau ra:
      bytes, 16 byte plaintext (giong aes_decrypt_block)
    """
    if len(ciphertext) != 16 or len(key) not in (16, 24, 32):
        raise ValueError("Ciphertext phai 16 byte, Key phai 16/24/32 byte.")

    def fmt(s): return ' '.join(f'{b:02X}' for b in s)

    state = list(ciphertext)
    round_keys = key_expansion(key)
    Nr = len(round_keys) - 1

    print(f"\n{'='*60}")
    print(f"  VERBOSE GIAI MA - Khoi #{block_idx}")
    print(f"{'='*60}")
    print(f"  Ciphertext  : {fmt(state)}")
    print(f"  Key ({len(key)*8}-bit): {fmt(key)}")

    state = add_round_key(state, round_keys[Nr])
    print(f"\n  [Vong {Nr}] AddRoundKey (khoa cuoi): {fmt(state)}")

    for r in range(Nr - 1, 0, -1):
        print(f"\n  --- Vong {r:2d} (nguoc) ---")
        state = inv_shift_rows(state)
        print(f"  InvShiftRows   : {fmt(state)}")
        state = inv_sub_bytes(state)
        print(f"  InvSubBytes    : {fmt(state)}")
        state = add_round_key(state, round_keys[r])
        print(f"  AddRoundKey    : {fmt(state)}  (RK{r}: {fmt(round_keys[r])})")
        state = inv_mix_columns(state)
        print(f"  InvMixColumns  : {fmt(state)}")

    print(f"\n  --- Vong 0 (khong InvMixColumns) ---")
    state = inv_shift_rows(state)
    print(f"  InvShiftRows   : {fmt(state)}")
    state = inv_sub_bytes(state)
    print(f"  InvSubBytes    : {fmt(state)}")
    state = add_round_key(state, round_keys[0])
    print(f"  AddRoundKey    : {fmt(state)}  (RK0: {fmt(round_keys[0])})")

    result = bytes(state)
    print(f"\n  => Plaintext: {fmt(result)}")
    return result


# ==============================================================
#  [5] CAC CHE DO VAN HANH (MODES OF OPERATION)
# ==============================================================

# --- [5.1] Padding PKCS#7 ---

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Them padding PKCS#7 vao cuoi du lieu.
    Dam bao do dai du lieu chia het cho block_size (mac dinh 16).
    Gia tri moi byte padding = so byte padding can them.
    Vi du: 'HELLO' (5 byte) -> 'HELLO' + 11 byte gia tri 0x0B
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Loai bo padding PKCS#7 sau khi giai ma.
    Kiem tra tinh hop le cua padding truoc khi xoa.
    Nem loi ValueError neu padding khong hop le.
    """
    if not data:
        raise ValueError("Du lieu trong rong, khong the unpad.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError(f"Padding khong hop le: gia tri {pad_len}.")
    if not all(b == pad_len for b in data[-pad_len:]):
        raise ValueError("Padding PKCS7 bi loi: cac byte padding khong dong nhat.")
    return data[:-pad_len]


# --- [5.2] Che do ECB (Electronic Codebook) ---
# CANH BAO: ECB KHONG AN TOAN cho du lieu thuc te!
# Cung mot khoi plaintext luon cho cung mot khoi ciphertext,
# lo ro cau truc du lieu (vi du: anh bitmap, van ban lap lai).
# Chi su dung ECB de hoc tap hoac kiem tra tung khoi don le.

def ecb_encrypt(plaintext: bytes, key: bytes, verbose: bool = False) -> bytes:
    """
    Ma hoa AES che do ECB (Electronic Codebook).

    Dau vao:
      plaintext : bytes, do dai bat ky
      key       : bytes, 16 / 24 / 32 byte
      verbose   : True de hien thi chi tiet tung khoi

    Dau ra:
      bytes, ciphertext (co padding, chia het cho 16)

    CANH BAO: ECB KHONG AN TOAN cho ung dung thuc te!
    """
    padded = pkcs7_pad(plaintext)
    ciphertext = b''
    fn = aes_encrypt_block_verbose if verbose else aes_encrypt_block
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        ciphertext += fn(block, key) if not verbose else fn(block, key, i // 16)
    return ciphertext


def ecb_decrypt(ciphertext: bytes, key: bytes, verbose: bool = False) -> bytes:
    """
    Giai ma AES che do ECB.

    Dau vao:
      ciphertext : bytes, do dai phai chia het cho 16
      key        : bytes, 16 / 24 / 32 byte
      verbose    : True de hien thi chi tiet tung khoi

    Dau ra:
      bytes, plaintext goc (da bo padding)
    """
    if len(ciphertext) % 16 != 0:
        raise ValueError("Do dai ciphertext phai la boi so cua 16 (ECB mode).")
    raw = b''
    fn = aes_decrypt_block_verbose if verbose else aes_decrypt_block
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        raw += fn(block, key) if not verbose else fn(block, key, i // 16)
    return pkcs7_unpad(raw)


# --- [5.3] Che do CBC (Cipher Block Chaining) ---
# An toan hon ECB: moi khoi plaintext duoc XOR voi khoi ciphertext truoc (hoac IV)
# truoc khi ma hoa. Cac khoi giong nhau cho ciphertext khac nhau.
# Yeu cau: IV ngau nhien, duy nhat cho moi lan ma hoa.

def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes, verbose: bool = False) -> bytes:
    """
    Ma hoa AES che do CBC (Cipher Block Chaining).

    Dau vao:
      plaintext : bytes, do dai bat ky
      key       : bytes, 16 / 24 / 32 byte
      iv        : bytes, chinh xac 16 byte (nen sinh ngau nhien)
      verbose   : True de hien thi chi tiet

    Dau ra:
      bytes, ciphertext (co padding)

    Luong xu ly:
      C[0] = Encrypt(P[0] XOR IV)
      C[i] = Encrypt(P[i] XOR C[i-1])
    """
    if len(iv) != 16:
        raise ValueError("IV phai chinh xac 16 byte (CBC mode).")
    padded = pkcs7_pad(plaintext)
    ciphertext = b''
    prev = list(iv)

    for i in range(0, len(padded), 16):
        block = list(padded[i:i+16])
        # XOR plaintext hien tai voi ciphertext khoi truoc (hoac IV)
        xored = bytes([p ^ c for p, c in zip(block, prev)])
        if verbose:
            enc = aes_encrypt_block_verbose(xored, key, i // 16)
        else:
            enc = aes_encrypt_block(xored, key)
        ciphertext += enc
        prev = list(enc)

    return ciphertext


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes, verbose: bool = False) -> bytes:
    """
    Giai ma AES che do CBC.

    Dau vao:
      ciphertext : bytes, do dai phai chia het cho 16
      key        : bytes, 16 / 24 / 32 byte
      iv         : bytes, chinh xac 16 byte (phai trung voi IV khi ma hoa)
      verbose    : True de hien thi chi tiet

    Dau ra:
      bytes, plaintext goc (da bo padding)

    Luong xu ly:
      P[0] = Decrypt(C[0]) XOR IV
      P[i] = Decrypt(C[i]) XOR C[i-1]
    """
    if len(ciphertext) % 16 != 0:
        raise ValueError("Do dai ciphertext phai la boi so cua 16 (CBC mode).")
    if len(iv) != 16:
        raise ValueError("IV phai chinh xac 16 byte (CBC mode).")
    raw = b''
    prev = list(iv)

    for i in range(0, len(ciphertext), 16):
        curr_block = ciphertext[i:i+16]
        if verbose:
            dec = aes_decrypt_block_verbose(curr_block, key, i // 16)
        else:
            dec = aes_decrypt_block(curr_block, key)
        # XOR ket qua giai ma voi ciphertext cua khoi truoc (hoac IV)
        raw += bytes([d ^ p for d, p in zip(dec, prev)])
        prev = list(curr_block)

    return pkcs7_unpad(raw)


# --- [5.4] Che do CTR (Counter Mode) ---
# CTR bien AES thanh stream cipher: sinh keystream tu (Nonce || Counter),
# sau do XOR voi plaintext. Khong can padding. Ma hoa = Giai ma (doi xung).
# An toan hon CBC neu Nonce/Counter khong bi lap lai.

def _ctr_keystream_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    """
    Ham noi bo: Sinh 16 byte keystream cho mot khoi CTR.
    counter_block = nonce (8 byte) || counter (8 byte, big-endian)
    """
    counter_block = nonce + struct.pack('>Q', counter)  # 8 + 8 = 16 byte
    return aes_encrypt_block(counter_block, key)


def ctr_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Ma hoa AES che do CTR (Counter Mode).

    Dau vao:
      plaintext : bytes, do dai bat ky (KHONG can padding)
      key       : bytes, 16 / 24 / 32 byte
      nonce     : bytes, chinh xac 8 byte (Number used ONCE - phai duy nhat)

    Dau ra:
      bytes, ciphertext cung do dai voi plaintext

    Luu y: Trong CTR, ma hoa va giai ma la cung mot ham (XOR doi xung).
    """
    if len(nonce) != 8:
        raise ValueError("Nonce phai chinh xac 8 byte (CTR mode).")
    ciphertext = b''
    counter = 0
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        keystream = _ctr_keystream_block(key, nonce, counter)
        ciphertext += bytes([p ^ k for p, k in zip(block, keystream)])
        counter += 1
    return ciphertext


def ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Giai ma AES che do CTR.
    Giong het ctr_encrypt vi CTR la doi xung (XOR hai lan = ban dau).

    Dau vao:
      ciphertext : bytes, do dai bat ky
      key        : bytes, 16 / 24 / 32 byte
      nonce      : bytes, chinh xac 8 byte (phai trung voi Nonce khi ma hoa)

    Dau ra:
      bytes, plaintext goc
    """
    return ctr_encrypt(ciphertext, key, nonce)  # CTR ma hoa = giai ma


# ==============================================================
#  [6] TIEN ICH (UTILITIES)
# ==============================================================

def generate_random_key(bits: int = 128) -> bytes:
    """
    Sinh khoa ngau nhien an toan bang os.urandom.
    bits: 128, 192, hoac 256
    Tra ve: bytes khoa ngau nhien
    """
    if bits not in (128, 192, 256):
        raise ValueError("Chi ho tro 128, 192 hoac 256 bit.")
    return os.urandom(bits // 8)


def generate_random_iv() -> bytes:
    """Sinh IV ngau nhien 16 byte an toan (dung cho CBC mode)."""
    return os.urandom(16)


def generate_random_nonce() -> bytes:
    """Sinh Nonce ngau nhien 8 byte an toan (dung cho CTR mode)."""
    return os.urandom(8)


def parse_input_data(raw: str, fmt: str) -> bytes:
    """
    Chuyen chuoi dau vao thanh bytes theo dinh dang chi dinh.
    fmt: 'ascii', 'hex', 'base64'
    Tra ve: bytes, nem loi ValueError neu dinh dang sai.
    """
    fmt = fmt.strip().lower()
    try:
        if fmt == 'ascii':
            return raw.encode('utf-8')
        elif fmt == 'hex':
            return binascii.unhexlify(raw.replace(' ', '').replace(':', ''))
        elif fmt == 'base64':
            return base64.b64decode(raw.strip())
        else:
            raise ValueError(f"Dinh dang khong hop le: {fmt}")
    except Exception as e:
        raise ValueError(f"Loi chuyen doi dinh dang '{fmt}': {e}")


def format_output(data: bytes) -> str:
    """
    Hien thi du lieu dau ra theo ca ba dinh dang de tham khao.
    Tra ve chuoi da dinh dang, bao gom HEX, Base64 va ASCII (neu co the).
    """
    hex_str = data.hex().upper()
    b64_str = base64.b64encode(data).decode()
    try:
        ascii_str = data.decode('utf-8')
    except UnicodeDecodeError:
        ascii_str = "(khong the hien thi duoi dang ASCII)"
    return (
        f"  HEX    : {hex_str}\n"
        f"  Base64 : {b64_str}\n"
        f"  ASCII  : {ascii_str}"
    )


def _separator(char: str = '-', width: int = 60) -> str:
    return char * width


# ==============================================================
#  [7] KIEM TRA TU DONG (AUTOMATED TESTING)
# ==============================================================

def run_tests(num_tests: int = 50) -> None:
    """
    Kiem tra toan bo he thong voi cac test ngau nhien.
    So sanh ket qua voi thu vien PyCryptodome (chuan cong nghiep).
    Kiem tra: ECB encrypt, ECB decrypt, CBC encrypt/decrypt, CTR encrypt/decrypt.

    Yeu cau: pip install pycryptodome
    """
    try:
        from Crypto.Cipher import AES as _AES
        from Crypto.Util.Padding import pad as _pad, unpad as _unpad
    except ImportError:
        print("[LOI] Thieu thu vien PyCryptodome. Cai dat: pip install pycryptodome")
        return

    print(f"\n{'='*60}")
    print(f"  KIEM TRA TU DONG - {num_tests} test moi loai")
    print(f"{'='*60}")

    passed = failed = 0
    key_lens = [16, 24, 32]

    # --- Test 1: ECB ma hoa tung khoi (so sanh voi PyCryptodome ECB) ---
    print(f"\n[1] ECB - Ma hoa tung khoi (AES-128/192/256)")
    for i in range(num_tests):
        klen = random.choice(key_lens)
        key  = os.urandom(klen)
        pt   = os.urandom(16)
        try:
            our_ct  = aes_encrypt_block(pt, key)
            ref_ct  = _AES.new(key, _AES.MODE_ECB).encrypt(pt)
            if our_ct == ref_ct:
                passed += 1
            else:
                print(f"  FAILED test {i+1}: key={key.hex()} pt={pt.hex()}")
                failed += 1
        except Exception as e:
            print(f"  ERROR test {i+1}: {e}")
            failed += 1
    print(f"  Ket qua: {passed} passed / {failed} failed")

    passed = failed = 0

    # --- Test 2: ECB + CBC round-trip (ma hoa roi giai ma phai cho lai plaintext goc) ---
    print(f"\n[2] ECB + CBC - Round-trip (ma hoa -> giai ma)")
    for i in range(num_tests):
        klen = random.choice(key_lens)
        key  = os.urandom(klen)
        pt   = os.urandom(random.randint(1, 100))
        iv   = os.urandom(16)
        try:
            # ECB round-trip
            ecb_ct = ecb_encrypt(pt, key)
            ecb_pt = ecb_decrypt(ecb_ct, key)
            assert ecb_pt == pt, "ECB round-trip that bai"

            # CBC round-trip
            cbc_ct = cbc_encrypt(pt, key, iv)
            cbc_pt = cbc_decrypt(cbc_ct, key, iv)
            assert cbc_pt == pt, "CBC round-trip that bai"

            passed += 1
        except Exception as e:
            print(f"  FAILED test {i+1}: {e}")
            failed += 1
    print(f"  Ket qua: {passed} passed / {failed} failed")

    passed = failed = 0

    # --- Test 3: CBC so sanh voi PyCryptodome ---
    print(f"\n[3] CBC - So sanh voi PyCryptodome")
    for i in range(num_tests):
        klen = random.choice(key_lens)
        key  = os.urandom(klen)
        iv   = os.urandom(16)
        pt   = os.urandom(random.randint(1, 80))
        try:
            our_ct = cbc_encrypt(pt, key, iv)
            ref_ct = _AES.new(key, _AES.MODE_CBC, iv).encrypt(_pad(pt, 16))
            if our_ct == ref_ct:
                passed += 1
            else:
                print(f"  FAILED test {i+1}")
                failed += 1
        except Exception as e:
            print(f"  ERROR test {i+1}: {e}")
            failed += 1
    print(f"  Ket qua: {passed} passed / {failed} failed")

    passed = failed = 0

    # --- Test 4: CTR round-trip (ma hoa -> giai ma phai cho lai plaintext goc) ---
    print(f"\n[4] CTR - Round-trip (ma hoa -> giai ma)")
    for i in range(num_tests):
        klen  = random.choice(key_lens)
        key   = os.urandom(klen)
        nonce = os.urandom(8)
        pt    = os.urandom(random.randint(1, 100))
        try:
            ct = ctr_encrypt(pt, key, nonce)
            assert len(ct) == len(pt), "CTR: do dai output sai"
            rt = ctr_decrypt(ct, key, nonce)
            assert rt == pt, "CTR round-trip that bai"
            passed += 1
        except Exception as e:
            print(f"  FAILED test {i+1}: {e}")
            failed += 1
    print(f"  Ket qua: {passed} passed / {failed} failed")

    print(f"\n{'='*60}")
    print(f"  HOAN TAT KIEM TRA")
    print(f"{'='*60}\n")


# ==============================================================
#  [8] MENU TUONG TAC (INTERACTIVE MENU)
# ==============================================================

def _input_data(label: str) -> bytes:
    """
    Ham noi bo: Hoi nguoi dung nhap du lieu (plaintext hoac ciphertext).
    Ho tro ba dinh dang: ASCII, HEX, Base64.
    Tra ve bytes.
    """
    while True:
        print(f"\n  Dinh dang {label}:")
        print("    1. ASCII  (van ban thuong)")
        print("    2. HEX    (vi du: 48656C6C6F)")
        print("    3. Base64 (vi du: SGVsbG8=)")
        choice = input("  Lua chon (1/2/3): ").strip()
        fmt_map = {'1': 'ascii', '2': 'hex', '3': 'base64'}
        if choice not in fmt_map:
            print("  [LOI] Vui long chon 1, 2 hoac 3.")
            continue
        raw = input(f"  Nhap {label}: ").strip()
        try:
            return parse_input_data(raw, fmt_map[choice])
        except ValueError as e:
            print(f"  [LOI] {e}")


def _input_key() -> bytes:
    """
    Ham noi bo: Hoi nguoi dung nhap hoac sinh ngau nhien khoa AES.
    Ho tro ASCII va HEX, kiem tra do dai 16/24/32 byte.
    Tra ve bytes khoa.
    """
    len_map = {'1': 16, '2': 24, '3': 32}
    while True:
        print("\n  Do dai khoa:")
        print("    1. AES-128 (16 byte)")
        print("    2. AES-192 (24 byte)")
        print("    3. AES-256 (32 byte)")
        klen_choice = input("  Lua chon (1/2/3): ").strip()
        if klen_choice not in len_map:
            print("  [LOI] Vui long chon 1, 2 hoac 3.")
            continue
        klen = len_map[klen_choice]

        print(f"\n  Nhap khoa {klen*8}-bit:")
        print("    1. Nhap ASCII")
        print("    2. Nhap HEX")
        print("    3. Sinh ngau nhien (khuyen nghi)")
        kfmt = input("  Lua chon (1/2/3): ").strip()
        if kfmt == '3':
            key = generate_random_key(klen * 8)
            print(f"  [OK] Khoa ngau nhien : {key.hex().upper()}")
            print(f"       (luu lai de giai ma sau nay!)")
            return key
        try:
            raw = input(f"  Nhap khoa ({klen} ky tu/byte): ").strip()
            key = parse_input_data(raw, 'ascii' if kfmt == '1' else 'hex')
            if len(key) != klen:
                print(f"  [LOI] Key phai du chinh xac {klen} byte (dang co {len(key)} byte).")
                continue
            return key
        except ValueError as e:
            print(f"  [LOI] {e}")


def _input_iv() -> bytes:
    """
    Ham noi bo: Hoi nguoi dung nhap hoac sinh ngau nhien IV (dung cho CBC).
    IV phai chinh xac 16 byte. Khuyen nghi sinh ngau nhien.
    Tra ve bytes IV.
    """
    while True:
        print("\n  IV (Initialization Vector) 16 byte:")
        print("    1. Nhap ASCII (16 ky tu)")
        print("    2. Nhap HEX   (32 ky tu hex)")
        print("    3. Sinh ngau nhien (khuyen nghi)")
        choice = input("  Lua chon (1/2/3): ").strip()
        if choice == '3':
            iv = generate_random_iv()
            print(f"  [OK] IV ngau nhien: {iv.hex().upper()}")
            print(f"       (luu lai de giai ma sau nay!)")
            return iv
        try:
            raw = input("  Nhap IV: ").strip()
            iv = parse_input_data(raw, 'ascii' if choice == '1' else 'hex')
            if len(iv) != 16:
                print(f"  [LOI] IV phai chinh xac 16 byte (dang co {len(iv)} byte).")
                continue
            return iv
        except ValueError as e:
            print(f"  [LOI] {e}")


def _input_nonce() -> bytes:
    """
    Ham noi bo: Hoi nguoi dung nhap hoac sinh ngau nhien Nonce (dung cho CTR).
    Nonce phai chinh xac 8 byte. Phai duy nhat cho moi lan ma hoa.
    Tra ve bytes Nonce.
    """
    while True:
        print("\n  Nonce (Number used ONCE) 8 byte:")
        print("    1. Nhap ASCII (8 ky tu)")
        print("    2. Nhap HEX   (16 ky tu hex)")
        print("    3. Sinh ngau nhien (khuyen nghi)")
        choice = input("  Lua chon (1/2/3): ").strip()
        if choice == '3':
            nonce = generate_random_nonce()
            print(f"  [OK] Nonce ngau nhien: {nonce.hex().upper()}")
            print(f"       (luu lai de giai ma sau nay!)")
            return nonce
        try:
            raw = input("  Nhap Nonce: ").strip()
            nonce = parse_input_data(raw, 'ascii' if choice == '1' else 'hex')
            if len(nonce) != 8:
                print(f"  [LOI] Nonce phai chinh xac 8 byte (dang co {len(nonce)} byte).")
                continue
            return nonce
        except ValueError as e:
            print(f"  [LOI] {e}")


def run_interactive() -> None:
    """
    Menu tuong tac chinh cho nguoi dung.
    Huong dan tung buoc nhap du lieu, chon che do, chon khoa,
    thuc hien ma hoa / giai ma va hien thi ket qua.

    Cac che do ho tro:
      - ECB : don gian, KHONG an toan (chi de hoc)
      - CBC : chuan, an toan (can IV ngau nhien)
      - CTR : stream cipher, an toan (can Nonce duy nhat)

    Che do verbose: hien thi trang thai sau moi buoc cua tung vong AES.
    """
    print("\n" + _separator('='))
    print("  AES ENCRYPTION TOOL - Ho tro ECB / CBC / CTR")
    print("  AES-128 / AES-192 / AES-256")
    print(_separator('='))

    # --- Chon thao tac: ma hoa hay giai ma ---
    while True:
        print("\n  Thao tac:")
        print("    1. Ma hoa (Encrypt)")
        print("    2. Giai ma (Decrypt)")
        op = input("  Lua chon (1/2): ").strip()
        if op in ('1', '2'):
            break
        print("  [LOI] Vui long chon 1 hoac 2.")

    is_encrypt = (op == '1')
    label = "Plaintext" if is_encrypt else "Ciphertext"

    # --- Nhap du lieu ---
    data = _input_data(label)

    # --- Nhap khoa ---
    key = _input_key()

    # --- Chon che do ---
    while True:
        print("\n  Che do van hanh:")
        print("    1. ECB - Electronic Codebook     [CANH BAO: KHONG AN TOAN]")
        print("    2. CBC - Cipher Block Chaining   [Khuyen dung]")
        print("    3. CTR - Counter Mode            [Khuyen dung, khong can padding]")
        mode = input("  Lua chon (1/2/3): ").strip()
        if mode in ('1', '2', '3'):
            break
        print("  [LOI] Vui long chon 1, 2 hoac 3.")

    if mode == '1':
        print("\n  [CANH BAO] ECB khong an toan cho du lieu thuc te!")
        print("             Cac khoi plaintext giong nhau se cho ciphertext giong nhau.")

    # --- Nhap IV hoac Nonce neu can ---
    iv    = _input_iv()    if mode == '2' else None
    nonce = _input_nonce() if mode == '3' else None

    # --- Chon che do verbose ---
    verbose_ans = input("\n  Hien thi chi tiet tung vong AES? (y/n, mac dinh n): ").strip().lower()
    verbose = (verbose_ans == 'y')

    if verbose and len(data) > 32:
        print("  [CANH BAO] Du lieu lon, verbose se rat nhieu output. Tiep tuc? (y/n): ", end='')
        if input().strip().lower() != 'y':
            verbose = False

    # --- Thuc hien ---
    print(f"\n{_separator()}")
    print(f"  Dang {'ma hoa' if is_encrypt else 'giai ma'}...")
    print(_separator())

    try:
        if is_encrypt:
            if mode == '1':
                result = ecb_encrypt(data, key, verbose=verbose)
            elif mode == '2':
                result = cbc_encrypt(data, key, iv, verbose=verbose)
            else:
                result = ctr_encrypt(data, key, nonce)
        else:
            if mode == '1':
                result = ecb_decrypt(data, key, verbose=verbose)
            elif mode == '2':
                result = cbc_decrypt(data, key, iv, verbose=verbose)
            else:
                result = ctr_decrypt(data, key, nonce)
    except Exception as e:
        print(f"\n  [LOI] Qua trinh that bai: {e}")
        return

    # --- Hien thi ket qua ---
    print(f"\n{_separator('=')}")
    print(f"  KET QUA {'MA HOA' if is_encrypt else 'GIAI MA'}")
    print(_separator('='))
    print(format_output(result))
    print(_separator('='))


# ==============================================================
#  [9] DIEM CHAY CHINH (ENTRY POINT)
# ==============================================================

def print_help() -> None:
    """In huong dan su dung khi goi voi co --help."""
    print("""
HUONG DAN SU DUNG: aes_matma.py
================================

Chay menu tuong tac:
  python aes_matma.py

Chay bo kiem tra tu dong (yeu cau PyCryptodome):
  python aes_matma.py --test
  python aes_matma.py --test 100    (100 test moi loai)

Xem huong dan nay:
  python aes_matma.py --help

CAC CHE DO:
  ECB  - Don gian nhung KHONG AN TOAN. Khong dung cho thuc te.
  CBC  - An toan, can IV ngau nhien 16 byte. Pho bien nhat.
  CTR  - An toan, bien AES thanh stream cipher, khong can padding.

CAC DO DAI KHOA:
  AES-128: 16 byte = 128 bit
  AES-192: 24 byte = 192 bit
  AES-256: 32 byte = 256 bit (manh nhat)

CANH BAO BAO MAT:
  - IV (CBC) va Nonce (CTR) PHAI sinh ngau nhien moi lan ma hoa moi.
  - Khong bao gio dung lai IV/Nonce voi cung mot khoa.
  - Giu khoa bi mat; IV/Nonce co the luu cong khai kem ciphertext.
""")


if __name__ == "__main__":
    # --- Xu ly tham so dong lenh ---
    args = sys.argv[1:]

    if '--help' in args or '-h' in args:
        print_help()

    elif '--test' in args:
        # Tim so luong test neu duoc chi dinh (vi du: --test 100)
        idx = args.index('--test')
        n = 50
        if idx + 1 < len(args):
            try:
                n = int(args[idx + 1])
            except ValueError:
                pass
        run_tests(n)

    else:
        # Khong co tham so -> chay menu tuong tac
        try:
            run_interactive()
        except KeyboardInterrupt:
            print("\n\n  [!] Nguoi dung thoat chuong trinh (Ctrl+C).")