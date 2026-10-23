#!/usr/bin/env python3
"""Create a local API JWT for TellStick firmware 1.3.3 from its saved config.

Requires the cryptography Python package
"""

import argparse
import base64
import configparser
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def recover_signing_key(config_path, secret):
    config = configparser.RawConfigParser(interpolation=None, strict=False)
    config.optionxform = str
    with Path(config_path).open(encoding='utf-8') as fd:
        config.read_file(fd)
    if not config.has_section('telldus.api'):
        raise ValueError('Config has no [telldus.api] section')

    def field(name):
        value = config.get('telldus.api', name).strip()
        # ConfigObj can quote string values; these fields contain no escapes.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if not value:
            raise ValueError('Empty telldus.api field: ' + name)
        return value

    password = secret.encode('utf-8')
    stored_hash = field('pw')
    pieces = stored_hash.split('$')
    if len(pieces) != 5 or pieces[:3] != ['', 'p5k2', ''] or not pieces[3]:
        raise ValueError('Unsupported password-hash format')
    hash_salt = '$p5k2$$' + pieces[3]
    verifier = hashlib.pbkdf2_hmac('sha1', password, hash_salt.encode('ascii'), 400, dklen=24)
    actual_hash = hash_salt + '$' + base64.b64encode(verifier, altchars=b'./').decode('ascii')
    if not hmac.compare_digest(actual_hash, stored_hash):
        raise ValueError('Device secret does not match the API settings password hash')

    salt = base64.b64decode(field('salt'), validate=True)
    ciphertext = base64.b64decode(field('tokenKey'), validate=True)
    if len(salt) != 16 or len(ciphertext) != 32:
        raise ValueError('Expected a 16-byte salt and a 32-byte encrypted tokenKey')
    wrapping_key = hashlib.pbkdf2_hmac('sha1', password, salt, 1000, dklen=32)
    decryptor = Cipher(algorithms.AES(wrapping_key), modes.ECB()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def create_token(signing_key, app, ttl_seconds, now=None):
    if not app or ttl_seconds <= 0:
        raise ValueError('App must be nonempty and TTL must be positive')
    now = int(time.time()) if now is None else int(now)
    # This firmware expects aud/exp in the signed HEADER, not the payload.
    header = {'typ': 'JWT', 'alg': 'HS256', 'aud': app, 'exp': now + ttl_seconds}

    def encode(value):
        raw = json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        return base64.urlsafe_b64encode(raw).rstrip(b'=')

    signing_input = encode(header) + b'.' + encode({})
    signature = hmac.new(signing_key, signing_input, hashlib.sha256).digest()
    return (signing_input + b'.' + base64.urlsafe_b64encode(signature).rstrip(b'=')).decode('ascii')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path, help='Decrypted Telldus.conf')
    parser.add_argument('--app', default='local-audit', help='Application identity (default: local-audit)')
    parser.add_argument('--ttl-seconds', type=int, default=3600, help='Lifetime (default: 3600 seconds)')
    parser.add_argument('--output', type=Path, help='Create a new token file with mode 0600; otherwise print token')

    args = parser.parse_args()
    if args.ttl_seconds <= 0 or not args.app:
        parser.error('--ttl-seconds must be positive and --app must be nonempty')
    try:
        secret = getpass.getpass('Device secret: ')
        key = recover_signing_key(args.config, secret)
        token = create_token(key, args.app, args.ttl_seconds)
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='ascii') as output:
                output.write(token + '\n')
            print('Token written to {}'.format(args.output), file=sys.stderr)
        else:
            print(token)
    except (OSError, ValueError, configparser.Error) as error:
        parser.exit(1, 'Error: {}\n'.format(error))


if __name__ == '__main__':
    main()
