"""Verify the delivered samples locally. Does not send or replay packets."""
from pathlib import Path
import collections
import hashlib
import json
import struct
import sys


def pcap_counts(data):
    formats = {
        b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
        b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>',
    }
    if len(data) < 24 or data[:4] not in formats:
        raise ValueError('Not a supported classic PCAP file')
    endian = formats[data[:4]]
    if struct.unpack(endian + 'HH', data[4:8]) != (2, 4):
        raise ValueError('Unexpected PCAP version')
    offset, packets, short_records = 24, 0, 0
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError('Incomplete packet record header')
        _, _, captured, original = struct.unpack(endian + 'IIII', data[offset:offset + 16])
        offset += 16
        if offset + captured > len(data):
            raise ValueError('Incomplete packet record data')
        offset += captured
        packets += 1
        short_records += captured < original
    return packets, short_records


def check_file(file_path, expected):
    data = file_path.read_bytes()
    if len(data) != expected['bytes']:
        raise ValueError(f'{file_path.name}: size mismatch')
    if hashlib.sha256(data).hexdigest() != expected['sha256']:
        raise ValueError(f'{file_path.name}: SHA-256 mismatch')
    print('SHA256 OK:', file_path.relative_to(ROOT))
    return data


ROOT = Path(__file__).resolve().parent
try:
    samples = ROOT / '小樣本資料'
    manifest = json.loads((samples / '來源與檢查紀錄.json').read_text(encoding='utf-8'))
    for case in manifest:
        for entry in case['files']:
            data = check_file(samples / case['case_id'] / entry['filename'], entry)
            if entry['filename'].endswith('.pcap'):
                packets, short = pcap_counts(data)
                if packets != case['pcap']['packet_count'] or short != 0:
                    raise ValueError('Packet count or captured-length mismatch')
                print('PCAP records OK:', packets, 'packets')
            else:
                rows = [line.split() for line in data.decode('utf-8').splitlines()
                        if line and not line.startswith('#')]
                labels = dict(collections.Counter(' '.join(row[-2:]) for row in rows))
                if len(rows) != case['labels']['row_count'] or labels != case['labels']['last_fields_summary']:
                    raise ValueError('Label row count mismatch')
                print('Label rows OK:', len(rows), labels)
    selections = json.loads((ROOT / '裁切小案例' / '裁切與標籤對照.json').read_text(encoding='utf-8'))
    for entry in selections['cases']:
        data = check_file(ROOT / '裁切小案例' / entry['filename'], entry)
        packets, short = pcap_counts(data)
        if packets != entry['packet_count'] or short != 0:
            raise ValueError('Selected PCAP packet count mismatch')
        print('Selected PCAP records OK:', packets, 'packets')
    print('PASS: file identity, PCAP record integrity, packet counts and label counts.')
    print('This does not verify checksum, all flow alignment, rules or router behavior.')
except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
    print('FAIL:', error, file=sys.stderr)
    sys.exit(1)
