"""Recreate the two selected PCAPs locally; does not send any packets."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output-dir', type=Path, default=root / '重新裁切結果')
args = parser.parse_args()
metadata = json.loads((root / '裁切小案例' / '裁切與標籤對照.json').read_text(encoding='utf-8'))
source = root / '小樣本資料' / 'Hakai-8-1' / '2018-07-31-15-15-09-192.168.100.113.pcap'
data = source.read_bytes()
assert data[:4] == b'\xd4\xc3\xb2\xa1', 'Unexpected PCAP encoding'
args.output_dir.mkdir(parents=True, exist_ok=True)
for case in metadata['cases']:
    assert hashlib.sha256(data).hexdigest() == case['source_pcap_sha256'], 'Source file hash mismatch'
    forward = case['original_tuple']
    reverse = [forward[2], forward[3], forward[0], forward[1], forward[4]]
    first = float(case['selection_time_start_epoch']) - 0.000001
    last = float(case['selection_time_end_epoch']) + 0.000001
    offset = 24
    chosen = []
    while offset < len(data):
        start = offset
        sec, usec, captured, _ = struct.unpack('<IIII', data[offset:offset + 16])
        offset += 16
        packet = data[offset:offset + captured]
        offset += captured
        timestamp = sec + usec / 1e6
        if not first <= timestamp <= last or len(packet) < 34 or packet[12:14] != b'\x08\x00':
            continue
        ip = 14
        protocol = packet[ip + 9]
        header_size = (packet[ip] & 15) * 4
        fragment = struct.unpack('!H', packet[ip + 6:ip + 8])[0]
        if fragment & 0x1fff or protocol not in (6, 17) or len(packet) < ip + header_size + 4:
            continue
        origin = '.'.join(map(str, packet[ip + 12:ip + 16]))
        destination = '.'.join(map(str, packet[ip + 16:ip + 20]))
        origin_port, destination_port = struct.unpack('!HH', packet[ip + header_size:ip + header_size + 4])
        flow = [origin, origin_port, destination, destination_port, protocol]
        if flow == forward or flow == reverse:
            chosen.append(data[start:offset])
    recreated = data[:24] + b''.join(chosen)
    assert len(chosen) == case['packet_count'], 'Selected packet count mismatch'
    assert hashlib.sha256(recreated).hexdigest() == case['sha256'], 'Reproduced file hash mismatch'
    destination = args.output_dir / case['filename']
    if destination.exists() and destination.read_bytes() != recreated:
        raise RuntimeError('Output already exists with different contents: ' + str(destination))
    destination.write_bytes(recreated)
    print('REPRODUCED:', destination.name, len(chosen), 'packets, SHA256 matches')
print('PASS: both selected files are byte-identical to the supplied cases.')
print('This only recreates file selections; it does not test a router or rule engine.')
