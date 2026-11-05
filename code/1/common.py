"""공통 통신부: JSON 메시지 송수신 + AES-ECB-256 암복호화 (Base64 포함).

alice.py / bob.py 에서 다음처럼 가져다 쓴다.
    from common import send_msg, recv_msg, aes_encrypt, aes_decrypt, error_msg
"""
import json
import base64
import logging

from Crypto.Cipher import AES   # pip install pycryptodome

BLOCK_SIZE = 16
AES_KEY_SIZE = 32               # AES-256 -> 32 바이트 키

# ---------------------------------------------------------------------------
# opcode / type 상수 (오타 방지용)
# ---------------------------------------------------------------------------
OP_REQUEST = 0      # 요청
OP_KEY = 1          # 키 / 파라미터
OP_ENCRYPTED = 2    # 암호화된 메시지
OP_ERROR = 3        # 오류

TYPE_RSAKEY = "RSAKey"
TYPE_RSA = "RSA"
TYPE_DH = "DH"
TYPE_AES = "AES"

# ---------------------------------------------------------------------------
# JSON 메시지 송수신
# ---------------------------------------------------------------------------
_buffers = {}               # 소켓별 수신 버퍼 (메시지가 붙어오거나 잘려와도 처리)
_decoder = json.JSONDecoder()


def send_msg(sock, msg):
    """dict -> JSON 문자열 -> ASCII 바이트로 보낸다."""
    sjs = json.dumps(msg)
    sock.sendall(sjs.encode("ascii"))
    logging.info("[*] Sent: {}".format(sjs))


def recv_msg(sock):
    """JSON 메시지 하나를 받아 dict 로 돌려준다. 상대가 연결을 끊으면 None."""
    key = id(sock)
    buf = _buffers.get(key, "")
    while True:
        stripped = buf.lstrip()
        if stripped:
            try:
                msg, end = _decoder.raw_decode(stripped)
                _buffers[key] = stripped[end:]
                logging.info("[*] Received: {}".format(stripped[:end]))
                return msg
            except json.JSONDecodeError:
                pass        # 아직 메시지가 다 안 왔음 -> 더 받는다
        data = sock.recv(4096)
        if not data:
            _buffers.pop(key, None)
            return None
        buf = stripped + data.decode("ascii")


def error_msg(text):
    """Protocol IV 오류 메시지: {"opcode": 3, "error": text}"""
    return {"opcode": OP_ERROR, "error": text}

# ---------------------------------------------------------------------------
# AES-ECB 256-bit (+ PKCS#7 패딩, Base64)
# ---------------------------------------------------------------------------
def _pad(data):
    pad = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad]) * pad


def _unpad(data):
    pad = data[-1]
    if pad < 1 or pad > BLOCK_SIZE or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("잘못된 패딩: 키가 틀렸을 가능성이 큼")
    return data[:-pad]


def _check_key(key):
    if not isinstance(key, (bytes, bytearray)) or len(key) != AES_KEY_SIZE:
        raise ValueError("AES 키는 32바이트 bytes 여야 함 (지금: {!r})".format(key))


def aes_encrypt(key, message):
    """문자열 message -> AES 암호화 -> Base64 문자열 (JSON 'encryption' 값)."""
    _check_key(key)
    aes = AES.new(bytes(key), AES.MODE_ECB)
    encrypted = aes.encrypt(_pad(message.encode()))
    return base64.b64encode(encrypted).decode()


def aes_decrypt(key, b64_text):
    """Base64 문자열 -> AES 복호화 -> 원래 문자열."""
    _check_key(key)
    aes = AES.new(bytes(key), AES.MODE_ECB)
    decrypted = aes.decrypt(base64.b64decode(b64_text))
    return _unpad(decrypted).decode()


def aes_msg(key, message):
    """{"opcode": 2, "type": "AES", "encryption": ...} 메시지를 만들어 준다."""
    return {"opcode": OP_ENCRYPTED, "type": TYPE_AES,
            "encryption": aes_encrypt(key, message)}
