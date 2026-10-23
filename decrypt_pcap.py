#!/usr/bin/env python3
"""Recover a TellStick config upload from an Ethernet/IPv4 classic PCAP."""

import argparse
import bz2
import configparser
from email import policy
from email.parser import BytesParser
import getpass
import hashlib
import json
from pathlib import Path
import socket
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def streams_from_pcap(data):
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
              b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}.get(data[:4])
    if endian is None or len(data) < 24:
        raise ValueError('Expected a classic PCAP')
    if struct.unpack_from(endian + 'I', data, 20)[0] != 1:
        raise ValueError('Only Ethernet captures are supported')
    offset, streams = 24, {}
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError('Truncated PCAP record header')
        size, original = struct.unpack_from(endian + 'II', data, offset + 8)
        offset += 16
        packet = data[offset:offset + size]
        offset += size
        if len(packet) != size or size < original:
            raise ValueError('Truncated captured packet')
        if len(packet) < 14:
            continue
        ethertype = struct.unpack_from('!H', packet, 12)[0]
        ip_start = 14
        while ethertype in (0x8100, 0x88a8, 0x9100):
            ethertype = struct.unpack_from('!H', packet, ip_start + 2)[0]
            ip_start += 4
        if ethertype != 0x0800:
            continue
        ip = packet[ip_start:]
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        if struct.unpack_from('!H', ip, 6)[0] & 0x3fff:
            raise ValueError('Fragmented IPv4 TCP requires a fuller reassembler')
        ip_length = struct.unpack_from('!H', ip, 2)[0]
        if len(ip) < ip_length:
            raise ValueError('Truncated IPv4 packet')
        tcp = ip[(ip[0] & 15) * 4:ip_length]
        if len(tcp) < 20:
            raise ValueError('Truncated TCP header')
        sport, dport, seq = struct.unpack_from('!HHI', tcp)
        payload = tcp[(tcp[12] >> 4) * 4:]
        if not payload:
            continue
        key = (socket.inet_ntoa(ip[12:16]), sport, socket.inet_ntoa(ip[16:20]), dport)
        streams.setdefault(key, []).append((seq, payload))
    for key, segments in streams.items():
        segments.sort(key=lambda item: item[0])
        start, result = segments[0][0], bytearray()
        for sequence, payload in segments:
            relative = sequence - start
            if relative > len(result):
                # This stream is incomplete. Do not treat it as a full request.
                result = None
                break
            overlap = min(len(payload), len(result) - relative)
            if result[relative:relative + overlap] != payload[:overlap]:
                raise ValueError('Conflicting retransmitted TCP bytes')
            result.extend(payload[overlap:])
        if result is not None:
            yield key, bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('output', type=Path, help='New output directory')
    parser.add_argument('--secret-stdin', action='store_true')
    args = parser.parse_args()
    secret = (sys.stdin.readline().rstrip('\r\n') if args.secret_stdin
              else getpass.getpass('Device secret: ')).encode('utf-8')
    data = args.capture.read_bytes()
    uploads = []
    for endpoint, stream in streams_from_pcap(data):
        if not stream.startswith(b'POST /upload/config HTTP/'):
            continue
        headers, separator, body = stream.partition(b'\r\n\r\n')
        if not separator:
            raise ValueError('Incomplete upload headers')
        mime_headers = headers.split(b'\r\n', 1)[1]
        message = BytesParser(policy=policy.default).parsebytes(mime_headers + b'\r\n\r\n')
        length = int(message['Content-Length'])
        if len(body) < length:
            raise ValueError('Incomplete HTTP upload body')
        multipart = BytesParser(policy=policy.default).parsebytes(
            mime_headers + b'\r\n\r\n' + body[:length])
        for part in multipart.iter_parts():
            if part.get_filename() == 'Telldus.conf.bz2':
                uploads.append((endpoint, part.get_payload(decode=True)))
    if len(uploads) != 1:
        raise ValueError('Expected exactly one complete config upload; found {}'.format(len(uploads)))
    endpoint, encrypted = uploads[0]
    if len(encrypted) < 40 or (len(encrypted) - 24) % 16:
        raise ValueError('Invalid encrypted backup dimensions')
    length = struct.unpack_from('<Q', encrypted)[0]
    iv = encrypted[8:24]
    key = hashlib.pbkdf2_hmac('sha1', secret, iv, 1000, dklen=32)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(encrypted[24:]) + decryptor.finalize()
    if not 0 < length <= len(padded) or len(padded) - length >= 16:
        raise ValueError('Invalid stored plaintext length')
    if padded[length:] != b' ' * (len(padded) - length):
        raise ValueError('Wrong secret or invalid space padding')
    compressed = padded[:length]
    decoder = bz2.BZ2Decompressor()
    config = decoder.decompress(compressed)
    if not decoder.eof or decoder.unused_data:
        raise ValueError('Invalid bzip2 stream')
    parsed = configparser.RawConfigParser(strict=False, interpolation=None)
    parsed.optionxform = str
    parsed.read_string(config.decode('utf-8'))
    if not parsed.sections():
        raise ValueError('No configuration sections found')
    summary = {
        'capture_sha256': hashlib.sha256(data).hexdigest(),
        'upload_endpoint': list(endpoint),
        'encrypted_bytes': len(encrypted),
        'compressed_bytes': len(compressed),
        'config_bytes': len(config),
        'config_sha256': hashlib.sha256(config).hexdigest(),
        'validation': 'AES decrypted; padding valid; complete bzip2 stream with CRC checks; INI parsed',
        'section_fields': {s: list(parsed[s]) for s in parsed.sections()},
    }
    args.output.mkdir(mode=0o700)
    for name, content in [('Telldus.conf', config), ('Telldus.conf.bz2', compressed),
                          ('upload.encrypted', encrypted),
                          ('summary.json', (json.dumps(summary, indent=2) + '\n').encode())]:
        path = args.output / name
        with path.open('xb') as fd:
            path.chmod(0o600)
            fd.write(content)
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
