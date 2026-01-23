"""
PAV File Analyzer for WCW CyberRing (1999)
Examines PAVENCRYPT file structure without decrypting.
Shows: header info, encryption boundary, key length, tail periodicity.
"""

import os
import struct
import sys
from collections import Counter


def analyze_file(filepath):
    """Analyze a single PAV file and print structural information."""
    with open(filepath, 'rb') as f:
        data = f.read()

    filename = os.path.basename(filepath)
    print(f'{"=" * 60}')
    print(f'File: {filename}')
    print(f'Size: {len(data):,} bytes ({len(data)/1024:.1f} KB)')
    print()

    # Check magic
    if data[:10] != b'PAVENCRYPT':
        print(f'  NOT A PAV FILE (magic: {data[:10]})')
        return
    print(f'  Magic: PAVENCRYPT (confirmed)')
    print(f'  Bytes 10-11: {data[10]:02X} {data[11]:02X}')

    # Parse clear MPEG section
    pos = 10
    pack_count = 0
    sys_hdr_count = 0
    video_pes_count = 0
    audio_pes_count = 0
    padding_pes_count = 0

    while pos < min(len(data), 0x10000):
        if pos + 4 > len(data):
            break
        if data[pos:pos+3] != b'\x00\x00\x01':
            break

        stream_id = data[pos+3]

        if stream_id == 0xBA:  # Pack header
            if pos + 12 > len(data):
                break
            if (data[pos+4] & 0xF0) != 0x20:
                break
            pack_count += 1

            # Extract SCR
            scr_bytes = data[pos+4:pos+9]
            scr = ((scr_bytes[0] & 0x0E) << 29 |
                   scr_bytes[1] << 22 |
                   (scr_bytes[2] & 0xFE) << 14 |
                   scr_bytes[3] << 7 |
                   (scr_bytes[4] >> 1))

            # Extract mux rate
            mux_rate = (data[pos+9] << 14 | data[pos+10] << 6 | data[pos+11] >> 2) * 50

            if pack_count == 1:
                print(f'  First pack SCR: {scr} (0x{scr:X})')
                print(f'  Mux rate: {mux_rate:,} bytes/sec')

            pos += 12
        elif stream_id == 0xBB:  # System header
            if pos + 6 > len(data):
                break
            hdr_len = struct.unpack('>H', data[pos+4:pos+6])[0]
            sys_hdr_count += 1
            pos += 6 + hdr_len
        elif stream_id == 0xE0:  # Video PES
            if pos + 6 > len(data):
                break
            pes_len = struct.unpack('>H', data[pos+4:pos+6])[0]
            if pes_len == 0:
                break
            video_pes_count += 1
            pos += 6 + pes_len
        elif stream_id == 0xC0:  # Audio PES
            if pos + 6 > len(data):
                break
            pes_len = struct.unpack('>H', data[pos+4:pos+6])[0]
            if pes_len == 0:
                break
            audio_pes_count += 1
            pos += 6 + pes_len
        elif stream_id == 0xBE:  # Padding
            if pos + 6 > len(data):
                break
            pes_len = struct.unpack('>H', data[pos+4:pos+6])[0]
            if pes_len == 0:
                break
            padding_pes_count += 1
            pos += 6 + pes_len
        else:
            break

    enc_start = pos
    print(f'\n  Clear section: 0x0C - 0x{enc_start:X} ({enc_start - 12:,} bytes)')
    print(f'    Packs: {pack_count}, System headers: {sys_hdr_count}')
    print(f'    Video PES: {video_pes_count}, Audio PES: {audio_pes_count}, '
          f'Padding PES: {padding_pes_count}')

    print(f'\n  Encrypted section: 0x{enc_start:X} - 0x{len(data):X} '
          f'({len(data) - enc_start:,} bytes, '
          f'{(len(data) - enc_start) / len(data) * 100:.1f}% of file)')

    # Analyze tail for key length
    print(f'\n  Tail analysis:')
    print(f'    Last 4 bytes: {data[-4:].hex()}')
    has_end_code = (data[-4:] == b'\x00\x00\x01\xb9')
    print(f'    Program end code: {"YES" if has_end_code else "NO"}')

    # Find periodicity
    tail_section = data[-(min(500, len(data) - enc_start)):-4] if has_end_code else data[-500:]
    best_period = 0
    best_ratio = 0
    for kl in range(1, 65):
        if len(tail_section) < kl * 3:
            continue
        matches = sum(1 for i in range(kl, len(tail_section))
                      if tail_section[i] == tail_section[i - kl])
        total = len(tail_section) - kl
        ratio = matches / total if total > 0 else 0
        if ratio > best_ratio:
            best_ratio = ratio
            best_period = kl
        if ratio > 0.99:
            break

    print(f'    Detected key length: {best_period} (confidence: {best_ratio:.4f})')

    if best_period > 0 and best_ratio > 0.90:
        # Show one cycle of the encrypted pattern
        cycle = tail_section[:best_period]
        hex_str = ' '.join(f'{b:02X}' for b in cycle)
        print(f'    Key pattern (encrypted 0xFF): {hex_str}')

        # Derive the key
        key = bytes((b - 0xFF) & 0xFF for b in cycle)
        key_ascii = ''.join(chr(b) if 32 <= b < 127 else '.' for b in key)
        print(f'    Derived key: "{key_ascii}"')

    # Byte frequency of encrypted section
    enc_data = data[enc_start:enc_start + min(10000, len(data) - enc_start)]
    freq = Counter(enc_data)
    min_freq = freq.most_common()[-1][1]
    max_freq = freq.most_common()[0][1]
    print(f'\n  Byte distribution (first 10KB encrypted):')
    print(f'    Min frequency: {min_freq}, Max frequency: {max_freq}, '
          f'Ratio: {max_freq/max(min_freq,1):.2f}')
    print(f'    (Flat distribution = encrypted, Peaked = not encrypted)')

    print()


def main():
    if len(sys.argv) > 1:
        # Analyze specific files
        for path in sys.argv[1:]:
            if os.path.isfile(path):
                analyze_file(path)
            elif os.path.isdir(path):
                for f in sorted(os.listdir(path)):
                    if f.upper().endswith('.PAV'):
                        analyze_file(os.path.join(path, f))
    else:
        # Default: analyze all PAV files in iso_contents/
        pav_dir = 'iso_contents'
        if not os.path.isdir(pav_dir):
            print(f'Directory not found: {pav_dir}')
            print(f'Usage: python analyze_pav.py [file_or_directory]')
            sys.exit(1)

        pav_files = sorted(f for f in os.listdir(pav_dir)
                           if f.upper().endswith('.PAV'))
        print(f'Analyzing {len(pav_files)} PAV files in {pav_dir}/\n')
        for f in pav_files:
            analyze_file(os.path.join(pav_dir, f))


if __name__ == '__main__':
    main()
