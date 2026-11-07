import socket
import threading
import argparse
import logging
import sys

from common import recv_msg, TYPE_RSAKEY, TYPE_RSA, TYPE_DH
from protocol_rsa import bob_rsakey, bob_rsa
from protocol_dh import bob_dh

def handler(sock, msg, bad_prime, bad_generator):
    # 받은 첫 메시지의 type 으로 프로토콜을 고른다 (RSAKey: I / RSA: II / DH: III, IV)
    try:
        first = recv_msg(sock)
        msg_type = first.get("type") if isinstance(first, dict) else None
        if first is None:
            print("[!] 상대가 연결을 끊었습니다.")
        elif msg_type == TYPE_RSAKEY:
            bob_rsakey(sock, first)
        elif msg_type == TYPE_RSA:
            bob_rsa(sock, first, msg)
        elif msg_type == TYPE_DH:
            # Protocol IV 테스트: --bad-prime / --bad-generator 로 실행하면 일부러 틀린 p, g 를 보낸다
            bob_dh(sock, first, msg, bad_prime=bad_prime, bad_generator=bad_generator)
        else:
            print("[!] 예상하지 못한 메시지: {}".format(first))
    finally:
        sock.close()

def run(addr, port, msg, bad_prime, bad_generator):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()

        logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))

        conn_handle = threading.Thread(target=handler, args=(conn, msg, bad_prime, bad_generator))
        conn_handle.start()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    parser.add_argument("-m", "--message", metavar="<message>", help="Message", type=str, required=True)
    bad = parser.add_mutually_exclusive_group()
    bad.add_argument("--bad-prime", action="store_true", help="Protocol IV-I 테스트: DH 에서 합성수 p 를 보낸다")
    bad.add_argument("--bad-generator", action="store_true", help="Protocol IV-II 테스트: DH 에서 생성원이 아닌 g 를 보낸다")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)
    sys.stdout.reconfigure(line_buffering=True)   # 출력이 바로바로 보이도록

    run(args.addr, args.port, args.message, args.bad_prime, args.bad_generator)

if __name__ == "__main__":
    main()
