"""Protocol III (DH 키 교환 + AES 메시지 교환) / Protocol IV (DH 오류 처리).

alice.py / bob.py 에서 다음처럼 호출한다.
    from protocol_dh import alice_dh, bob_dh

    # Alice (클라이언트): 연결한 소켓과 Bob 에게 보낼 메시지
    alice_dh(conn, "world")

    # Bob (서버): handler 에서 받은 첫 메시지의 type 이 "DH" 이면
    bob_dh(sock, first_msg, "hello")
    bob_dh(sock, first_msg, "hello", bad_prime=True)      # Protocol IV-I 테스트
    bob_dh(sock, first_msg, "hello", bad_generator=True)  # Protocol IV-II 테스트

두 함수 모두 상대에게서 받아 복호화한 문자열을 돌려주고, 오류가 나면 None 을 돌려준다.
"""
import logging
import random
import sys

from common import (send_msg, recv_msg, aes_msg, aes_decrypt, error_msg,
                    OP_REQUEST, OP_KEY, OP_ENCRYPTED, OP_ERROR, TYPE_DH, TYPE_AES)
from math_utils import (is_prime, is_generator, generate_dh_params, generate_dh_keypair,
                        dh_shared_secret, dh_to_aes_key, random_prime, random_non_prime,
                        find_non_generator)

ERR_PRIME = "incorrect prime number"
ERR_GENERATOR = "incorrect generator"


# ---------------------------------------------------------------------------
# 내부 도우미
# ---------------------------------------------------------------------------
def _expect(msg, opcode, msg_type=None):
    """받은 메시지가 기대한 opcode/type 인지 확인. 오류 메시지면 출력하고 False."""
    if msg is None:
        print("[!] 상대가 연결을 끊었습니다.")
        return False
    if msg.get("opcode") == OP_ERROR:
        print("[!] Received error: {}".format(msg.get("error")))
        return False
    if msg.get("opcode") != opcode or (msg_type is not None and msg.get("type") != msg_type):
        print("[!] 예상하지 못한 메시지: {}".format(msg))
        return False
    return True


def _receive_aes(sock, key):
    """AES 메시지 하나를 받아 복호화해 출력하고 돌려준다."""
    msg = recv_msg(sock)
    if not _expect(msg, OP_ENCRYPTED, TYPE_AES):
        return None
    plaintext = aes_decrypt(key, msg["encryption"])
    print("[*] Decrypted: {}".format(plaintext))
    return plaintext


# ---------------------------------------------------------------------------
# Alice (클라이언트)
# ---------------------------------------------------------------------------
def alice_dh(sock, message):
    """Alice 쪽 Protocol III/IV.

    1) DH 요청 전송
    2) Bob 의 p, g, 공개키 수신 -> p 소수 판정, g 생성원 판정 (실패 시 opcode 3 전송 후 종료)
    3) 내 공개키 전송, 공유 비밀 -> AES 키
    4) Bob 의 AES 메시지 복호화 출력, 내 메시지(message)를 AES 로 전송
    """
    send_msg(sock, {"opcode": OP_REQUEST, "type": TYPE_DH})

    msg = recv_msg(sock)
    if not _expect(msg, OP_KEY, TYPE_DH):
        return None
    p = msg["parameter"]["p"]
    g = msg["parameter"]["g"]
    bob_public = msg["public"]

    # Protocol IV: 소수 판정 -> 생성원 판정 순서
    if not is_prime(p):
        send_msg(sock, error_msg(ERR_PRIME))
        print("[!] Error: {} (p = {})".format(ERR_PRIME, p))
        return None
    logging.info("[*] p = {} is prime".format(p))

    if not is_generator(g, p):
        send_msg(sock, error_msg(ERR_GENERATOR))
        print("[!] Error: {} (g = {}, p = {})".format(ERR_GENERATOR, g, p))
        return None
    logging.info("[*] g = {} is a generator of p = {}".format(g, p))

    private, public = generate_dh_keypair(p, g)
    send_msg(sock, {"opcode": OP_KEY, "type": TYPE_DH, "public": public})

    shared = dh_shared_secret(bob_public, private, p)
    key = dh_to_aes_key(shared)
    logging.info("[*] DH shared secret = {}".format(shared))

    received = _receive_aes(sock, key)
    if received is None:
        return None
    send_msg(sock, aes_msg(key, message))
    return received


# ---------------------------------------------------------------------------
# Bob (서버)
# ---------------------------------------------------------------------------
def _bob_params(bad_prime, bad_generator):
    """보낼 (p, g). 테스트 옵션이면 일부러 틀린 값을 만든다."""
    if bad_prime:
        p = random_non_prime()
        return p, random.randint(2, p - 1)
    if bad_generator:
        p = random_prime()
        return p, find_non_generator(p)
    return generate_dh_params()


def bob_dh(sock, first_msg, message, bad_prime=False, bad_generator=False):
    """Bob 쪽 Protocol III/IV.

    first_msg : handler 에서 이미 받은 {"opcode": 0, "type": "DH"}
    1) p, g, 내 공개키 전송
    2) Alice 의 공개키 수신 (오류 메시지면 출력 후 종료) -> AES 키
    3) 내 메시지(message)를 AES 로 전송, Alice 의 답장 복호화 출력
    """
    if not _expect(first_msg, OP_REQUEST, TYPE_DH):
        return None

    p, g = _bob_params(bad_prime, bad_generator)
    private, public = generate_dh_keypair(p, g)
    send_msg(sock, {"opcode": OP_KEY, "type": TYPE_DH, "public": public,
                    "parameter": {"p": p, "g": g}})

    msg = recv_msg(sock)
    if not _expect(msg, OP_KEY, TYPE_DH):
        return None
    alice_public = msg["public"]

    shared = dh_shared_secret(alice_public, private, p)
    key = dh_to_aes_key(shared)
    logging.info("[*] DH shared secret = {}".format(shared))

    send_msg(sock, aes_msg(key, message))
    return _receive_aes(sock, key)


# ---------------------------------------------------------------------------
# 단독 실행 (alice.py / bob.py 연결 전 테스트용)
#   python protocol_dh.py bob   --port 5555 [--bad-prime | --bad-generator]
#   python protocol_dh.py alice --addr 127.0.0.1 --port 5555
# ---------------------------------------------------------------------------
def _run_bob(addr, port, message, bad_prime, bad_generator):
    import socket
    import threading

    def handler(sock):
        try:
            first = recv_msg(sock)
            bob_dh(sock, first, message, bad_prime=bad_prime, bad_generator=bad_generator)
        finally:
            sock.close()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((addr, port))
    server.listen(10)
    mode = "bad prime" if bad_prime else "bad generator" if bad_generator else "normal"
    print("[*] DH Bob ({}) is listening on {}:{}  (Ctrl+C 로 종료)".format(mode, addr, port))
    while True:
        conn, info = server.accept()
        logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def _run_alice(addr, port, message):
    import socket
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))
    try:
        alice_dh(conn, message)
    finally:
        conn.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Protocol III/IV (DH) 단독 테스트")
    parser.add_argument("role", choices=["alice", "bob"], help="실행할 쪽")
    parser.add_argument("-a", "--addr", type=str, default=None,
                        help="alice: Bob 주소 (기본 127.0.0.1) / bob: 바인드 주소 (기본 0.0.0.0)")
    parser.add_argument("-p", "--port", type=int, required=True)
    parser.add_argument("-m", "--message", type=str, default=None,
                        help="상대에게 보낼 메시지 (기본 alice=world, bob=hello)")
    bad = parser.add_mutually_exclusive_group()
    bad.add_argument("--bad-prime", action="store_true",
                     help="bob 전용: 합성수 p 를 보낸다 (Protocol IV-I)")
    bad.add_argument("--bad-generator", action="store_true",
                     help="bob 전용: 생성원이 아닌 g 를 보낸다 (Protocol IV-II)")
    parser.add_argument("-l", "--log", type=str, default="INFO",
                        help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)")
    args = parser.parse_args()
    logging.basicConfig(level=args.log)
    sys.stdout.reconfigure(line_buffering=True)   # 출력이 바로바로 보이도록

    if args.role == "bob":
        _run_bob(args.addr or "0.0.0.0", args.port, args.message or "hello",
                 args.bad_prime, args.bad_generator)
    else:
        if args.bad_prime or args.bad_generator:
            parser.error("--bad-prime / --bad-generator 는 bob 에서만 쓸 수 있습니다")
        _run_alice(args.addr or "127.0.0.1", args.port, args.message or "world")


if __name__ == "__main__":
    main()
