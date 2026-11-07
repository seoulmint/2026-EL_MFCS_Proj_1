import socket
import argparse
import logging
import sys

from protocol_rsa import alice_rsakey, alice_rsa
from protocol_dh import alice_dh

def run(addr, port, protocol, msg):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    # --protocol 로 실행할 프로토콜을 고른다
    if protocol == 1:
        alice_rsakey(conn)          # Protocol I   : RSA 키쌍 수신 + 검증
    elif protocol == 2:
        alice_rsa(conn, msg)        # Protocol II  : RSA 로 대칭키 전달 + AES
    else:
        alice_dh(conn, msg)         # Protocol III : DH + AES / Protocol IV : p, g 검증 실패 시 오류 전송 (Alice 동작은 같음)

    conn.close()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    parser.add_argument("--protocol", metavar="<protocol (1/2/3/4)>", help="Protocol: 1 (RSAKey), 2 (RSA), 3 (DH), 4 (DH error handling)", type=int, choices=[1, 2, 3, 4], required=True)
    parser.add_argument("-m", "--message", metavar="<message>", help="Message (required for protocol 2, 3, 4)", type=str)
    args = parser.parse_args()
    # 교수님 예제(aes_bob.py)처럼 보낼 메시지는 -m 으로 받는다. Protocol I 은 보낼 메시지가 없어서 제외
    if args.protocol != 1 and args.message is None:
        parser.error("-m/--message is required for protocol 2, 3, 4")
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)
    sys.stdout.reconfigure(line_buffering=True)   # 출력이 바로바로 보이도록

    run(args.addr, args.port, args.protocol, args.message)
    
if __name__ == "__main__":
    main()
