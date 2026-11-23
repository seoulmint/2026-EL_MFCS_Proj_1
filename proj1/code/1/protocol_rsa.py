"""Protocol I (RSA 키쌍 생성 + 검증) / Protocol II (RSA 로 대칭키 전달 + AES 메시지 교환).

alice.py / bob.py 에서 다음처럼 호출한다.
    from protocol_rsa import alice_rsakey, bob_rsakey, alice_rsa, bob_rsa

    # Alice (클라이언트): 연결한 소켓 (+ Bob 에게 보낼 메시지)
    alice_rsakey(conn)              # Protocol I
    alice_rsa(conn, "world")        # Protocol II

    # Bob (서버): handler 에서 받은 첫 메시지의 type 으로 고른다
    bob_rsakey(sock, first_msg)            # type == "RSAKey"
    bob_rsa(sock, first_msg, "hello")      # type == "RSA"

alice_rsakey 는 받은 키쌍이 올바르면 True, 틀렸거나 통신 오류면 False 를 돌려준다.
bob_rsakey 는 보낸 키쌍 (p, q, e, d) 를 돌려주고, 오류가 나면 None 을 돌려준다.
alice_rsa / bob_rsa 는 상대에게서 받아 복호화한 문자열을 돌려주고, 오류가 나면 None 을 돌려준다.
"""
import logging
import secrets
import sys

from common import (send_msg, recv_msg, aes_msg, aes_decrypt,
                    OP_REQUEST, OP_KEY, OP_ENCRYPTED, OP_ERROR,
                    TYPE_RSAKEY, TYPE_RSA, TYPE_AES, AES_KEY_SIZE)
from math_utils import (is_prime, generate_rsa_keypair, rsa_encrypt_bytes, rsa_decrypt_bytes,
                        PRIME_MIN, PRIME_MAX)

# Protocol I 응답(Bob -> Alice)의 opcode.
# 슬라이드 3 예시는 0 이지만, 메시지 표에는 "키를 담은 메시지 = 1" 로 되어 있다 (조교 확인 전).
# 보낼 때는 슬라이드 예시(0)를 따르고, 받을 때는 0 과 1 을 모두 허용한다.
RSAKEY_REPLY_OPCODE = OP_REQUEST
RSAKEY_REPLY_ACCEPTED = (OP_REQUEST, OP_KEY)


# ---------------------------------------------------------------------------
# 내부 도우미
# ---------------------------------------------------------------------------
def _expect(msg, opcodes, msg_type=None):
    """받은 메시지가 기대한 opcode/type 인지 확인. 오류 메시지면 출력하고 False.

    protocol_dh._expect 와 같은 역할이고, 허용 opcode 를 여러 개(튜플) 받을 수 있게 한 버전.
    """
    if msg is None:
        print("[!] 상대가 연결을 끊었습니다.")
        return False
    if msg.get("opcode") == OP_ERROR:
        print("[!] Received error: {}".format(msg.get("error")))
        return False
    if msg.get("opcode") not in opcodes or (msg_type is not None and msg.get("type") != msg_type):
        print("[!] 예상하지 못한 메시지: {}".format(msg))
        return False
    return True


def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def _receive_aes(sock, key):
    """AES 메시지 하나를 받아 복호화해 출력하고 돌려준다. 실패하면 None."""
    msg = recv_msg(sock)
    if not _expect(msg, (OP_ENCRYPTED,), TYPE_AES):
        return None
    try:
        plaintext = aes_decrypt(key, msg["encryption"])
    except (KeyError, TypeError, ValueError) as err:   # 필드 없음 / Base64·패딩 오류 (키 불일치)
        print("[!] AES 메시지를 복호화하지 못했습니다: {}".format(err))
        return None
    print("[*] Decrypted: {}".format(plaintext))
    return plaintext


# ---------------------------------------------------------------------------
# Protocol I: RSA 키쌍 생성 + 검증
# ---------------------------------------------------------------------------
def check_rsa_keypair(p, q, e, d):
    """받은 RSA 키쌍을 항목별로 검사해 [(설명, 통과 여부), ...] 를 돌려준다.

    math_utils.verify_rsa_keypair 와 같은 조건(p, q 소수 / p != q / e*d ≡ 1 mod φ(n))을
    검사하되, 항목마다 결과를 출력할 수 있게 나눈 버전이다.
    """
    for name, value in (("p", p), ("q", q), ("e", e), ("d", d)):
        if not _is_int(value):
            return [("{} = {!r} is an integer".format(name, value), False)]

    checks = [
        ("primality test: p = {} is prime".format(p), is_prime(p)),
        ("primality test: q = {} is prime".format(q), is_prime(q)),
        ("p != q", p != q),
    ]
    if p > 1 and q > 1:
        phi = (p - 1) * (q - 1)
        checks.append(("e * d mod phi(n) = {} (phi(n) = {}, must be 1)".format((e * d) % phi, phi),
                       (e * d) % phi == 1))
    else:
        checks.append(("phi(n) = (p-1)(q-1) is defined", False))
    return checks


def alice_rsakey(sock):
    """Alice 쪽 Protocol I.

    1) RSAKey 요청 전송
    2) Bob 의 p, q, 공개키 e, 개인키 d 수신
    3) p, q 각각 소수 판정 + 키쌍 검증 (e*d ≡ 1 mod φ(n))
    4) 키쌍과 검증 결과 출력
    """
    send_msg(sock, {"opcode": OP_REQUEST, "type": TYPE_RSAKEY})

    msg = recv_msg(sock)
    if not _expect(msg, RSAKEY_REPLY_ACCEPTED, TYPE_RSAKEY):
        return False
    try:
        d = msg["private"]
        e = msg["public"]
        p = msg["parameter"]["p"]
        q = msg["parameter"]["q"]
    except (KeyError, TypeError):
        print("[!] 필요한 값(private/public/parameter.p/parameter.q)이 없습니다: {}".format(msg))
        return False

    print("[*] Received RSA keypair")
    print("    p = {}, q = {}".format(p, q))
    if _is_int(p) and _is_int(q):
        print("    n = p * q = {}".format(p * q))
    print("    public key  (e) = {}".format(e))
    print("    private key (d) = {}".format(d))

    checks = check_rsa_keypair(p, q, e, d)
    print("[*] Verification")
    for desc, ok in checks:
        print("    [{}] {}".format("OK" if ok else "FAIL", desc))

    # 범위는 Bob 이 지켜야 할 조건이라 키쌍의 정답 여부와는 따로 경고만 한다.
    for name, value in (("p", p), ("q", q)):
        if _is_int(value) and not (PRIME_MIN <= value <= PRIME_MAX):
            print("    [WARN] {} = {} is outside [{}, {}]".format(name, value, PRIME_MIN, PRIME_MAX))

    correct = all(ok for _, ok in checks)
    print("[*] RSA keypair is {}".format("CORRECT" if correct else "INCORRECT"))
    return correct


def bob_rsakey(sock, first_msg):
    """Bob 쪽 Protocol I.

    first_msg : handler 에서 이미 받은 {"opcode": 0, "type": "RSAKey"}
    1) RSA 키쌍 생성 (p, q 는 400~500 사이 소수)
    2) p, q, 공개키 e, 개인키 d 를 담아 응답
    """
    if not _expect(first_msg, (OP_REQUEST,), TYPE_RSAKEY):
        return None

    p, q, e, d = generate_rsa_keypair()
    logging.info("[*] Generated RSA keypair")
    logging.info("    p = {}, q = {}, n = {}, phi(n) = {}".format(p, q, p * q, (p - 1) * (q - 1)))
    logging.info("    public key  (e) = {}".format(e))
    logging.info("    private key (d) = {}".format(d))

    send_msg(sock, {"opcode": RSAKEY_REPLY_OPCODE, "type": TYPE_RSAKEY,
                    "private": d, "public": e, "parameter": {"p": p, "q": q}})
    return p, q, e, d


# ---------------------------------------------------------------------------
# Protocol II: RSA 로 대칭키(AES-256 키) 전달 + AES 메시지 교환
# ---------------------------------------------------------------------------
def alice_rsa(sock, message):
    """Alice 쪽 Protocol II.

    1) RSA 요청 전송
    2) Bob 의 공개키 e, n 수신
    3) 32바이트 대칭키 생성 -> 한 바이트씩 RSA 암호화 -> encrypted_key (정수 32개) 전송
    4) Bob 의 AES 메시지 복호화 출력, 내 메시지(message)를 AES 로 전송
    """
    send_msg(sock, {"opcode": OP_REQUEST, "type": TYPE_RSA})

    msg = recv_msg(sock)
    if not _expect(msg, (OP_KEY,), TYPE_RSA):
        return None
    try:
        e = msg["public"]
        n = msg["parameter"]["n"]
    except (KeyError, TypeError):
        print("[!] 필요한 값(public/parameter.n)이 없습니다: {}".format(msg))
        return None
    # 한 바이트(0~255)씩 암호화하므로 n 이 255 보다 커야 복호화 결과가 원래 바이트로 돌아온다.
    if not (_is_int(e) and _is_int(n) and e > 0 and n > 255):
        print("[!] 잘못된 RSA 공개키입니다: e = {!r}, n = {!r}".format(e, n))
        return None
    logging.info("[*] Received RSA public key: e = {}, n = {}".format(e, n))

    key = secrets.token_bytes(AES_KEY_SIZE)            # 32바이트 대칭키 (AES-256)
    logging.info("[*] Generated symmetric key: {}".format(key.hex()))
    encrypted_key = rsa_encrypt_bytes(key, e, n)        # 바이트마다 b^e mod n -> 정수 32개
    send_msg(sock, {"opcode": OP_ENCRYPTED, "type": TYPE_RSA, "encrypted_key": encrypted_key})

    received = _receive_aes(sock, key)
    if received is None:
        return None
    send_msg(sock, aes_msg(key, message))
    return received


def bob_rsa(sock, first_msg, message):
    """Bob 쪽 Protocol II.

    first_msg : handler 에서 이미 받은 {"opcode": 0, "type": "RSA"}
    1) RSA 키쌍 생성 -> 공개키 e 와 n 전송 (개인키 d 는 보내지 않는다)
    2) Alice 의 encrypted_key 수신 -> 한 원소씩 RSA 복호화 -> 32바이트 대칭키
    3) 내 메시지(message)를 AES 로 전송, Alice 의 답장 복호화 출력
    """
    if not _expect(first_msg, (OP_REQUEST,), TYPE_RSA):
        return None

    p, q, e, d = generate_rsa_keypair()
    n = p * q
    logging.info("[*] Generated RSA keypair: p = {}, q = {}, n = {}, e = {}, d = {}".format(p, q, n, e, d))
    send_msg(sock, {"opcode": OP_KEY, "type": TYPE_RSA, "public": e, "parameter": {"n": n}})

    msg = recv_msg(sock)
    if not _expect(msg, (OP_ENCRYPTED,), TYPE_RSA):
        return None
    encrypted_key = msg.get("encrypted_key")
    if (not isinstance(encrypted_key, list) or len(encrypted_key) != AES_KEY_SIZE
            or not all(_is_int(c) and 0 <= c < n for c in encrypted_key)):
        print("[!] encrypted_key 는 0 이상 n 미만 정수 {}개의 리스트여야 합니다: {}".format(
            AES_KEY_SIZE, encrypted_key))
        return None
    try:
        key = rsa_decrypt_bytes(encrypted_key, d, n)
    except ValueError:      # 복호화 값이 0~255 를 벗어남 = 다른 공개키로 암호화된 것
        print("[!] 대칭키를 복호화하지 못했습니다 (다른 공개키로 암호화된 것 같습니다)")
        return None
    logging.info("[*] Decrypted symmetric key: {}".format(key.hex()))

    send_msg(sock, aes_msg(key, message))
    return _receive_aes(sock, key)


# ---------------------------------------------------------------------------
# 단독 실행 (alice.py / bob.py 연결 전 테스트용)
#   python protocol_rsa.py bob   --port 5555 [-m "hello"]
#   python protocol_rsa.py alice --port 5555 [--protocol 1|2] [-m "world"]
# Bob 은 받은 첫 메시지의 type (RSAKey / RSA) 을 보고 Protocol I / II 를 고른다.
# ---------------------------------------------------------------------------
def _run_bob(addr, port, message):
    import socket
    import threading

    def handler(sock):
        try:
            first = recv_msg(sock)
            if first is not None and first.get("type") == TYPE_RSA:
                bob_rsa(sock, first, message)
            else:
                bob_rsakey(sock, first)
        finally:
            sock.close()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((addr, port))
    server.listen(10)
    print("[*] RSA Bob (Protocol I/II) is listening on {}:{}  (Ctrl+C 로 종료)".format(addr, port))
    while True:
        conn, info = server.accept()
        logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def _run_alice(addr, port, protocol, message):
    import socket
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))
    try:
        if protocol == 1:
            alice_rsakey(conn)
        else:
            alice_rsa(conn, message)
    finally:
        conn.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Protocol I/II (RSA) 단독 테스트")
    parser.add_argument("role", choices=["alice", "bob"], help="실행할 쪽")
    parser.add_argument("-a", "--addr", type=str, default=None,
                        help="alice: Bob 주소 (기본 127.0.0.1) / bob: 바인드 주소 (기본 0.0.0.0)")
    parser.add_argument("-p", "--port", type=int, required=True)
    parser.add_argument("--protocol", type=int, choices=[1, 2], default=1,
                        help="alice 전용: 1 = RSAKey (Protocol I), 2 = RSA (Protocol II). 기본 1")
    parser.add_argument("-m", "--message", type=str, default=None,
                        help="Protocol II 에서 상대에게 보낼 메시지 (기본 alice=world, bob=hello)")
    parser.add_argument("-l", "--log", type=str, default="INFO",
                        help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)")
    args = parser.parse_args()
    logging.basicConfig(level=args.log)
    sys.stdout.reconfigure(line_buffering=True)   # 출력이 바로바로 보이도록

    if args.role == "bob":
        _run_bob(args.addr or "0.0.0.0", args.port, args.message or "hello")
    else:
        _run_alice(args.addr or "127.0.0.1", args.port, args.protocol, args.message or "world")


if __name__ == "__main__":
    main()
