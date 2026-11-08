"""Additional Task I / II: 수동 공격자(Eve).

Eve 는 Alice 와 Bob 이 주고받는 메시지를 엿보기만 하고(수정하지 않는다), AES 메시지를 복호화한다.

- Additional Task I  (Protocol II, RSA)
    n = p*q 의 p, q 가 400~500 사이 소수라 n 을 바로 소인수분해할 수 있다.
    φ(n) = (p-1)(q-1) -> d = e^-1 mod φ(n) -> encrypted_key 를 한 원소씩 복호화 -> 대칭키 -> AES 복호화
- Additional Task II (Protocol III, DH)
    p < 500 이라 g^a ≡ A (mod p) 인 a 를 전수조사(이산로그)로 찾을 수 있다.
    shared = B^a mod p -> dh_to_aes_key(shared) -> AES 복호화

실행 방법
    # 1) 도청 기록(로그 파일) 분석: 한 줄에 JSON 메시지 하나
    python eve.py adv_protocol_two-prob-1.log adv_protocol_three-prob-1.log
    python eve.py                  # 인자가 없으면 이 폴더의 adv_protocol_*.log 전부

    # 2) 실시간 도청: Alice 와 Bob 사이에서 메시지를 그대로 중계하면서 엿본다
    python eve.py relay --port <Alice 가 접속할 포트> --bob-addr <Bob IP> --bob-port <Bob 포트>
    # Alice 는 Bob 대신 Eve 의 주소/포트로 접속한다. Eve 는 바이트를 바꾸지 않고 그대로 전달한다.
"""
import argparse
import glob
import json
import logging
import os
import socket
import sys
import threading

from common import aes_decrypt, OP_KEY, OP_ENCRYPTED, OP_ERROR, TYPE_RSA, TYPE_DH, TYPE_AES
from math_utils import prime_factors, mod_inverse, rsa_decrypt_bytes, dh_to_aes_key


# ---------------------------------------------------------------------------
# 공격 함수
# ---------------------------------------------------------------------------
def break_rsa(e, n):
    """n 을 소인수분해해서 개인키 d 를 구한다. (p, q, d) 를 돌려준다."""
    factors = sorted(prime_factors(n))
    if len(factors) != 2 or factors[0] * factors[1] != n:
        raise ValueError("n = {} 은(는) 서로 다른 두 소수의 곱이 아님: {}".format(n, factors))
    p, q = factors
    phi = (p - 1) * (q - 1)
    return p, q, mod_inverse(e, phi)


def discrete_log(g, y, p):
    """g^x ≡ y (mod p) 인 가장 작은 x (0 <= x < p-1) 를 전수조사로 찾는다. 없으면 None.

    g 가 생성원이 아니어도 g^x ≡ y 만 만족하면 상대 공개키^x 가 shared secret 과 같다.
    (g^x = g^a 이면 B^x = g^(bx) = (g^x)^b = (g^a)^b = B^a)
    """
    value = 1
    for x in range(p - 1):
        if value == y % p:
            return x
        value = value * g % p
    return None


# ---------------------------------------------------------------------------
# 엿본 메시지를 순서대로 넣으면 키를 복구하고 AES 메시지를 복호화하는 상태 기계
# ---------------------------------------------------------------------------
class Eve:
    def __init__(self):
        self.protocol = None    # "RSA" / "DH"
        self.rsa = None         # (e, n, d)
        self.dh = None          # {"p", "g", "bob_public"}
        self.key = None         # 복구한 32바이트 AES 키
        self.plaintexts = []

    def observe(self, msg, sender="?"):
        """메시지 하나(dict)를 처리한다. sender 는 출력용("Alice"/"Bob"/"?")."""
        if not isinstance(msg, dict):
            print("[!] JSON 객체가 아닌 메시지: {!r}".format(msg))
            return
        opcode, mtype = msg.get("opcode"), msg.get("type")

        if opcode == OP_ERROR:
            print("[*] {} 가 오류를 보냄: {}".format(sender, msg.get("error")))
        elif mtype == TYPE_RSA:
            self.protocol = TYPE_RSA
            self._observe_rsa(msg, opcode)
        elif mtype == TYPE_DH:
            self.protocol = TYPE_DH
            self._observe_dh(msg, opcode)
        elif mtype == TYPE_AES and opcode == OP_ENCRYPTED:
            self._observe_aes(msg, sender)

    # --- Additional Task I: RSA ---------------------------------------------
    def _observe_rsa(self, msg, opcode):
        if opcode == OP_KEY:
            e, n = msg["public"], msg["parameter"]["n"]
            print("[*] RSA 공개키 엿봄: e = {}, n = {}".format(e, n))
            p, q, d = break_rsa(e, n)
            print("    소인수분해: n = {} = {} * {}".format(n, p, q))
            print("    phi(n) = {}, 개인키 d = e^-1 mod phi(n) = {}".format((p - 1) * (q - 1), d))
            self.rsa = (e, n, d)
        elif opcode == OP_ENCRYPTED and "encrypted_key" in msg:
            if self.rsa is None:
                print("[!] 공개키를 보기 전에 encrypted_key 가 왔습니다")
                return
            _, n, d = self.rsa
            self.key = rsa_decrypt_bytes(msg["encrypted_key"], d, n)
            print("[*] encrypted_key 복호화 -> 대칭키 = {}".format(self.key.hex()))

    # --- Additional Task II: DH ---------------------------------------------
    def _observe_dh(self, msg, opcode):
        if opcode != OP_KEY:
            return
        if "parameter" in msg:                  # Bob -> Alice: p, g, Bob 공개키 B
            self.dh = {"p": msg["parameter"]["p"], "g": msg["parameter"]["g"],
                       "bob_public": msg["public"]}
            print("[*] DH 파라미터 엿봄: p = {}, g = {}, Bob 공개키 B = {}".format(
                self.dh["p"], self.dh["g"], self.dh["bob_public"]))
        elif self.dh is not None:               # Alice -> Bob: Alice 공개키 A
            p, g, B = self.dh["p"], self.dh["g"], self.dh["bob_public"]
            A = msg["public"]
            print("[*] Alice 공개키 엿봄: A = {}".format(A))
            a = discrete_log(g, A, p)
            if a is None:
                print("[!] g^a = A (mod p) 인 a 가 없습니다")
                return
            shared = pow(B, a, p)
            print("    이산로그 전수조사: a = {} (g^a mod p = {})".format(a, pow(g, a, p)))
            print("    shared secret = B^a mod p = {}".format(shared))
            self.key = dh_to_aes_key(shared)
            print("    AES 키 = {}".format(self.key.hex()))

    # --- AES 메시지 ----------------------------------------------------------
    def _observe_aes(self, msg, sender):
        if self.key is None:
            print("[!] 키를 복구하기 전에 AES 메시지가 왔습니다: {}".format(msg.get("encryption")))
            return
        try:
            plaintext = aes_decrypt(self.key, msg["encryption"])
        except (KeyError, TypeError, ValueError) as err:
            print("[!] AES 복호화 실패: {}".format(err))
            return
        self.plaintexts.append(plaintext)
        print("[*] Decrypted ({}): {}".format(sender, plaintext))


# ---------------------------------------------------------------------------
# 모드 1: 로그 파일 분석
# ---------------------------------------------------------------------------
def analyze_log(path):
    print("=" * 60)
    print("[*] {}".format(os.path.basename(path)))
    eve = Eve()
    # 프로토콜 II/III 모두 메시지 순서가 Alice, Bob, Alice, Bob, Alice 로 번갈아 간다
    senders = ["Alice", "Bob"]
    with open(path, encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    for i, line in enumerate(lines):
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            print("[!] JSON 이 아닌 줄 {}: {}".format(i + 1, line))
            continue
        logging.info("[*] Observed: {}".format(line))
        try:
            eve.observe(msg, senders[i % 2])
        except (KeyError, TypeError, ValueError) as err:
            print("[!] 메시지 처리 실패 (줄 {}): {}".format(i + 1, err))
    return eve.plaintexts


# ---------------------------------------------------------------------------
# 모드 2: 실시간 중계 도청 (Alice <-> Eve <-> Bob)
# ---------------------------------------------------------------------------
def _pipe(src, dst, eve, lock, sender):
    """src 에서 받은 바이트를 그대로 dst 로 보내면서, JSON 메시지 단위로 잘라 Eve 에게 보여 준다."""
    decoder = json.JSONDecoder()
    buf = ""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)                   # 수동 공격자: 내용을 바꾸지 않고 그대로 전달
            buf += data.decode("ascii", errors="replace")
            while True:
                stripped = buf.lstrip()
                if not stripped:
                    buf = ""
                    break
                try:
                    msg, end = decoder.raw_decode(stripped)
                except json.JSONDecodeError:
                    buf = stripped              # 아직 메시지가 다 안 옴
                    break
                buf = stripped[end:]
                with lock:
                    logging.info("[*] Observed ({}): {}".format(sender, stripped[:end]))
                    try:
                        eve.observe(msg, sender)
                    except (KeyError, TypeError, ValueError) as err:
                        print("[!] 메시지 처리 실패: {}".format(err))
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)        # 한쪽이 끊으면 반대쪽에도 알린다
        except OSError:
            pass


def _relay_session(alice_sock, bob_addr, bob_port):
    try:
        bob_sock = socket.create_connection((bob_addr, bob_port))
    except OSError as err:
        print("[!] Bob ({}:{}) 에 접속하지 못했습니다: {}".format(bob_addr, bob_port, err))
        alice_sock.close()
        return
    eve, lock = Eve(), threading.Lock()
    t1 = threading.Thread(target=_pipe, args=(alice_sock, bob_sock, eve, lock, "Alice"))
    t2 = threading.Thread(target=_pipe, args=(bob_sock, alice_sock, eve, lock, "Bob"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    alice_sock.close()
    bob_sock.close()
    print("[*] 세션 종료\n")


def run_relay(addr, port, bob_addr, bob_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((addr, port))
    server.listen(10)
    print("[*] Eve 가 {}:{} 에서 대기 중, Bob = {}:{}  (Ctrl+C 로 종료)".format(addr, port, bob_addr, bob_port))
    while True:
        conn, info = server.accept()
        print("[*] Alice ({}:{}) 접속 -> Bob 으로 중계".format(info[0], info[1]))
        threading.Thread(target=_relay_session, args=(conn, bob_addr, bob_port), daemon=True).start()


# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) > 1 and sys.argv[1] == "relay":
        parser = argparse.ArgumentParser(prog="eve.py relay", description="실시간 중계 도청")
        parser.add_argument("relay")
        parser.add_argument("-a", "--addr", type=str, default="0.0.0.0", help="Eve 가 바인드할 주소 (기본 0.0.0.0)")
        parser.add_argument("-p", "--port", type=int, required=True, help="Alice 가 접속할 Eve 의 포트")
        parser.add_argument("--bob-addr", type=str, required=True, help="진짜 Bob 의 주소")
        parser.add_argument("--bob-port", type=int, required=True, help="진짜 Bob 의 포트")
        parser.add_argument("-l", "--log", type=str, default="WARNING", help="INFO 로 하면 엿본 원본 메시지도 출력")
    else:
        parser = argparse.ArgumentParser(description="Additional Task I/II: 도청 기록 복호화")
        parser.add_argument("logs", nargs="*", help="로그 파일 (생략하면 이 폴더의 adv_protocol_*.log 전부)")
        parser.add_argument("-l", "--log", type=str, default="WARNING", help="INFO 로 하면 엿본 원본 메시지도 출력")
    args = parser.parse_args()
    logging.basicConfig(level=args.log)
    sys.stdout.reconfigure(line_buffering=True)   # 출력이 바로바로 보이도록

    if hasattr(args, "bob_addr"):
        run_relay(args.addr, args.port, args.bob_addr, args.bob_port)
        return

    paths = args.logs or sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                       "adv_protocol_*.log")))
    if not paths:
        print("[!] 분석할 로그 파일이 없습니다")
        return
    for path in paths:
        analyze_log(path)


if __name__ == "__main__":
    main()
