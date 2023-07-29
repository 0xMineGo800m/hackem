#!/usr/bin/python3

import argparse

from Crypto.Hash import MD5
from Crypto.Cipher import DES
import base64
import re

_password = b'48gREsTkb1evb3J8UfP7'
_salt = bytearray()
_salt.extend(x % 256 for x in [ -87, -101, -56, 50, 86, 53, -29, 3 ])

_iterations = 19

# Pad plaintext per RFC 2898 Section 6.1

if "__main__" == __name__:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices={'e', 'd'}, default='e')
    parser.add_argument('value', type=str)
    args = parser.parse_args()

    """Mimic Java's PBEWithMD5AndDES algorithm to produce a DES key"""
    hasher = MD5.new()
    hasher.update(_password)
    hasher.update(_salt)
    result = hasher.digest()

    for i in range(1, _iterations):
        hasher = MD5.new()
        hasher.update(result)
        result = hasher.digest()
    # encrypt
    if args.mode == 'e':
        encoder = DES.new(result[:8], DES.MODE_CBC, result[8:16])
        padding = 8 - len(args.value) % 8
        plaintext_to_encrypt = args.value + chr(padding) * padding
        encrypted = encoder.encrypt(plaintext_to_encrypt.encode())
        print(base64.urlsafe_b64encode(encrypted).decode())
    else:
        decoder = DES.new(result[:8], DES.MODE_CBC, result[8:])
        d = decoder.decrypt(base64.urlsafe_b64decode(args.value))
        padding = d[-1:]

        print(d.strip(padding).decode())