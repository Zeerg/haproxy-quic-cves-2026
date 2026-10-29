#!/usr/bin/env python3
"""Send a protected QUIC Initial with a truncated frame-type varint."""

import argparse
import hashlib
import hmac
import os
import socket
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
LAB_HOST = "127.0.0.1"


def hkdf_extract(salt: bytes, key_material: bytes) -> bytes:
    return hmac.new(salt, key_material, hashlib.sha256).digest()


def hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full_label)]) + full_label + b"\x00"
    return HKDFExpand(algorithm=hashlib_to_crypto(), length=length, info=info).derive(secret)


def hashlib_to_crypto():
    from cryptography.hazmat.primitives import hashes

    return hashes.SHA256()


def build_packet() -> bytes:
    dcid = os.urandom(8)
    scid = os.urandom(8)
    packet_number = 0

    initial_secret = hkdf_extract(INITIAL_SALT_V1, dcid)
    client_secret = hkdf_expand_label(initial_secret, b"client in", 32)
    key = hkdf_expand_label(client_secret, b"quic key", 16)
    iv = hkdf_expand_label(client_secret, b"quic iv", 12)
    hp = hkdf_expand_label(client_secret, b"quic hp", 16)

    header = bytearray([0xC0])
    header.extend(struct.pack("!I", 1))
    header.append(len(dcid))
    header.extend(dcid)
    header.append(len(scid))
    header.extend(scid)
    header.append(0)  # Empty token.

    plaintext = b"\x00\x00\x00\x40"  # Padding, then an incomplete two-byte varint.
    protected_length = 1 + len(plaintext) + 16
    header.append(protected_length)
    pn_offset = len(header)
    header.append(packet_number)

    nonce = bytearray(iv)
    nonce[-1] ^= packet_number
    ciphertext = AESGCM(key).encrypt(bytes(nonce), plaintext, bytes(header))
    packet = header + ciphertext

    sample = bytes(packet[pn_offset + 4 : pn_offset + 20])
    encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()
    packet[0] ^= mask[0] & 0x0F
    packet[pn_offset] ^= mask[1]

    packet.extend(bytes(1200 - len(packet)))
    return bytes(packet)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--receive", action="store_true")
    args = parser.parse_args()

    packet = build_packet()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.0)
        sock.sendto(packet, (LAB_HOST, args.port))
        print(f"sent {len(packet)}-byte protected QUIC Initial")
        if args.receive:
            try:
                response, peer = sock.recvfrom(65535)
                print(f"received {len(response)} bytes from {peer}")
            except socket.timeout:
                print("no response received")


if __name__ == "__main__":
    main()
