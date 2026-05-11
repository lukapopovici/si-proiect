from __future__ import annotations

import hmac
from dataclasses import dataclass
from os import urandom
from typing import Optional

AES_128_KEY_SIZE = 16
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
_SBOX = [
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

_RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]




def _xtime(a: int) -> int:
    """Multiply by 2 in GF(2^8) with reduction polynomial 0x11b."""
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _gf8_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result




def _sub_bytes(state: list[list[int]]) -> list[list[int]]:
    return [[_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state: list[list[int]]) -> list[list[int]]:
    return [
        [state[r][(c + r) % 4] for c in range(4)]
        for r in range(4)
    ]


def _mix_columns(state: list[list[int]]) -> list[list[int]]:
    out = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        out[0][c] = _gf8_mul(0x02, col[0]) ^ _gf8_mul(0x03, col[1]) ^ col[2]          ^ col[3]
        out[1][c] = col[0]          ^ _gf8_mul(0x02, col[1]) ^ _gf8_mul(0x03, col[2]) ^ col[3]
        out[2][c] = col[0]          ^ col[1]          ^ _gf8_mul(0x02, col[2]) ^ _gf8_mul(0x03, col[3])
        out[3][c] = _gf8_mul(0x03, col[0]) ^ col[1]          ^ col[2]          ^ _gf8_mul(0x02, col[3])
    return out


def _add_round_key(state: list[list[int]], rk: list[list[int]]) -> list[list[int]]:
    return [[state[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]




def _key_expansion(key: bytes) -> list[list[list[int]]]:
    """Expand a 16-byte key into 11 round keys, each a 4×4 matrix."""
    words: list[list[int]] = []
    for i in range(4):
        words.append(list(key[4*i : 4*i+4]))

    for i in range(4, 44):
        w = words[i - 1][:]
        if i % 4 == 0:
            w = w[1:] + w[:1]
            w = [_SBOX[b] for b in w]
            w[0] ^= _RCON[i // 4]
        words.append([a ^ b for a, b in zip(words[i - 4], w)])

    round_keys: list[list[list[int]]] = []
    for rk in range(11):
        state = [[0]*4 for _ in range(4)]
        for c in range(4):
            for r in range(4):
                state[r][c] = words[rk*4 + c][r]
        round_keys.append(state)

    return round_keys




def _bytes_to_state(block: bytes) -> list[list[int]]:
    """Convert 16 bytes to a 4×4 column-major state matrix."""
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = block[i]
    return state


def _state_to_bytes(state: list[list[int]]) -> bytes:
    """Reverse of _bytes_to_state."""
    return bytes(state[i % 4][i // 4] for i in range(16))


def _aes_block_encrypt(key: bytes, block: bytes) -> bytes:
    """encrypt a single 16-byte block w/ AES."""
    round_keys = _key_expansion(key)
    state = _bytes_to_state(block)

    state = _add_round_key(state, round_keys[0])

    for rnd in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[rnd])

    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[10])

    return _state_to_bytes(state)




def _gf128_mul(x: int, y: int) -> int:
    R = 0xE1000000000000000000000000000000
    z = 0
    for _ in range(128):
        if y & (1 << 127):
            z ^= x
        y = (y << 1) & ((1 << 128) - 1)
        if x & 1:
            x = (x >> 1) ^ R
        else:
            x >>= 1
    return z


def _ghash(h_int: int, aad: bytes, ciphertext: bytes) -> bytes:
    def _blocks(data: bytes):
        for i in range(0, len(data), 16):
            block = data[i : i + 16].ljust(16, b"\x00")
            yield int.from_bytes(block, "big")

    y = 0
    for b in _blocks(aad):
        y = _gf128_mul(y ^ b, h_int)
    for b in _blocks(ciphertext):
        y = _gf128_mul(y ^ b, h_int)

    len_block = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    y = _gf128_mul(y ^ int.from_bytes(len_block, "big"), h_int)
    return y.to_bytes(16, "big")




def _inc32(block: bytes) -> bytes:
    ctr = int.from_bytes(block[12:16], "big")
    return block[:12] + ((ctr + 1) & 0xFFFFFFFF).to_bytes(4, "big")


def _ctr_encrypt(key: bytes, j0: bytes, data: bytes) -> bytes:
    counter = _inc32(j0)
    output = bytearray()
    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        ks = _aes_block_encrypt(key, counter)[:len(block)]
        counter = _inc32(counter)
        output.extend(a ^ b for a, b in zip(block, ks))
    return bytes(output)


def _build_j0(key: bytes, nonce: bytes) -> tuple[bytes, int]:
    H = _aes_block_encrypt(key, b"\x00" * 16)
    h_int = int.from_bytes(H, "big")
    j0 = (nonce + b"\x00\x00\x00\x01") if len(nonce) == 12 else _ghash(h_int, b"", nonce)
    return j0, h_int


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if len(key) != AES_128_KEY_SIZE:
        raise ValueError("AES-128 key must be exactly 16 bytes.")




@dataclass(frozen=True)
class EncryptedBundle:
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def combined(self) -> bytes:
        """Return nonce || ciphertext || tag for storage/transmission."""
        return self.nonce + self.ciphertext + self.tag

    @staticmethod
    def from_combined(data: bytes) -> "EncryptedBundle":
        if len(data) < GCM_NONCE_SIZE + GCM_TAG_SIZE:
            raise ValueError("Encrypted data is too short.")
        return EncryptedBundle(
            nonce      = data[:GCM_NONCE_SIZE],
            ciphertext = data[GCM_NONCE_SIZE:-GCM_TAG_SIZE],
            tag        = data[-GCM_TAG_SIZE:],
        )


def generate_key() -> bytes:
    return urandom(AES_128_KEY_SIZE)


def encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None,
) -> EncryptedBundle:
    """
    Encrypt *plaintext* with AES-128-GCM.

    *associated_data* is authenticated but not encrypted; supply the same
    value during decryption.

    (ceva ce am vazut ca se pune I am not sure why tho)
    """
    _validate_key(key)
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise TypeError("associated_data must be bytes or None")

    nonce      = urandom(GCM_NONCE_SIZE)
    j0, h_int  = _build_j0(key, nonce)
    aad        = associated_data or b""
    ciphertext = _ctr_encrypt(key, j0, plaintext)

    s   = _ghash(h_int, aad, ciphertext)
    tag = bytes(a ^ b for a, b in zip(_aes_block_encrypt(key, j0), s))

    return EncryptedBundle(nonce=nonce, ciphertext=ciphertext, tag=tag)


def decrypt(
    key: bytes,
    bundle: EncryptedBundle,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Decrypt and authenticate an *EncryptedBundle*.

    Raises ``AuthenticationError`` if the tag does not match.
    """
    _validate_key(key)
    if not isinstance(bundle, EncryptedBundle):
        raise TypeError("bundle must be an EncryptedBundle")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise TypeError("associated_data must be bytes or None")

    j0, h_int = _build_j0(key, bundle.nonce)
    aad       = associated_data or b""

    s            = _ghash(h_int, aad, bundle.ciphertext)
    expected_tag = bytes(a ^ b for a, b in zip(_aes_block_encrypt(key, j0), s))

    if not hmac.compare_digest(expected_tag, bundle.tag):
        raise AuthenticationError("GCM authentication tag mismatch — ciphertext or AAD has been tampered with.")

    return _ctr_encrypt(key, j0, bundle.ciphertext)


class AuthenticationError(Exception):
    """Raised when GCM tag verification fails."""