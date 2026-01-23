"""
PAV File Decryptor for WCW CyberRing (1999)

Decrypts PAVENCRYPT-format files by recovering per-file encryption keys
through a known-plaintext attack on MPEG-1 PS padding bytes.

Algorithm: subtraction cipher
  plaintext[i] = (ciphertext[i] - key[i % key_len]) mod 256

Usage:
  python decrypt_pav.py                    # Decrypt iso_contents/*.PAV -> extracted/*.mpg
  python decrypt_pav.py input/ output/     # Custom directories
"""

import os
import struct
import sys
from collections import Counter


def find_encryption_start(data):
    """Find where encryption begins by parsing valid MPEG-1 PS structures.

    Walks through the clear MPEG-1 Program Stream starting after the
    PAVENCRYPT header, parsing pack headers, system headers, and PES
    packets until an invalid structure is encountered.
    """
    pos = 10  # Skip PAVENCRYPT header (MPEG-1 PS starts immediately after)

    while pos < min(len(data), 0x10000):
        if pos + 4 > len(data):
            break

        # Must start with a start code prefix
        if data[pos:pos+3] != b'\x00\x00\x01':
            break

        stream_id = data[pos+3]

        if stream_id == 0xBA:  # Pack header
            if pos + 12 > len(data):
                break
            # MPEG-1 pack: byte 4 bits 7-4 must be 0010
            if (data[pos+4] & 0xF0) != 0x20:
                break
            pos += 12

        elif stream_id == 0xBB:  # System header
            if pos + 6 > len(data):
                break
            hdr_len = struct.unpack('>H', data[pos+4:pos+6])[0]
            pos += 6 + hdr_len

        elif stream_id in (0xBE, 0xBF, 0xE0, 0xE1, 0xC0, 0xC1):  # PES packets
            if pos + 6 > len(data):
                break
            pes_len = struct.unpack('>H', data[pos+4:pos+6])[0]
            if pes_len == 0:
                break
            pos += 6 + pes_len

        else:
            break

    return pos


def derive_key(data, enc_start):
    """Derive the decryption key using known-plaintext attack on tail padding.

    MPEG-1 PS files typically end with 0xFF padding bytes (PES padding packet)
    followed by Program End Code (00 00 01 B9). When encrypted with a repeating
    subtraction key, the 0xFF region produces a repeating ciphertext pattern.

    Steps:
    1. Detect key length via autocorrelation of the tail
    2. Derive key: key[i] = (ciphertext[i] - 0xFF) mod 256
    3. Verify by decrypting first encrypted bytes (must be valid MPEG start code)
    """
    # Valid MPEG-1 start codes that can appear at the encryption boundary
    valid_starts = [
        bytes([0x00, 0x00, 0x01, 0xBA]),  # Pack header
        bytes([0x00, 0x00, 0x01, 0xE0]),  # Video PES
        bytes([0x00, 0x00, 0x01, 0xC0]),  # Audio PES
        bytes([0x00, 0x00, 0x01, 0xBB]),  # System header
    ]

    # Determine tail region. Skip last 8 bytes to avoid the program end code
    # (00 00 01 B9) which is encrypted differently from the 0xFF padding.
    # The end code is only 4 bytes but we skip 8 for safety margin.
    tail_end = len(data) - 8

    for key_len in range(1, 129):
        # Try multiple window sizes, smallest first (some files have very
        # short padding sections, as few as 3 key-length cycles)
        best_tail = None
        best_ratio = 0
        best_tail_start = enc_start
        for multiplier in [3, 5, 8, 12, 20]:
            tail_start = max(enc_start, tail_end - key_len * multiplier)
            candidate = data[tail_start:tail_end]

            if len(candidate) < key_len * 3:
                continue

            matches = sum(1 for i in range(key_len, len(candidate))
                          if candidate[i] == candidate[i - key_len])
            total = len(candidate) - key_len
            ratio = matches / total if total > 0 else 0

            if ratio > best_ratio:
                best_ratio = ratio
                best_tail = candidate
                best_tail_start = tail_start

        if best_ratio < 0.90 or best_tail is None:
            continue

        tail = best_tail
        tail_start = best_tail_start

        # Derive key assuming plaintext is 0xFF
        key = bytearray(key_len)
        for ki in range(key_len):
            votes = []
            for j in range(len(tail)):
                file_pos = tail_start + j - enc_start
                if file_pos % key_len == ki:
                    votes.append((tail[j] - 0xFF) & 0xFF)
            if votes:
                c = Counter(votes)
                key[ki] = c.most_common(1)[0][0]

        # Verify: decrypt first 4 encrypted bytes
        if enc_start + 4 <= len(data):
            test_dec = bytearray(4)
            for i in range(4):
                test_dec[i] = (data[enc_start + i] - key[i % key_len]) & 0xFF

            if bytes(test_dec) in valid_starts:
                return key, key_len

    return None, 0


def decrypt_pav(filepath, output_path):
    """Decrypt a single PAV file and write clean MPEG-1 PS.

    Returns True on success, False on failure.
    """
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    filename = os.path.basename(filepath)

    # Verify PAVENCRYPT header
    if len(data) < 20 or data[:10] != b'PAVENCRYPT':
        print(f'  SKIP {filename}: Not a PAVENCRYPT file')
        return False

    # Find where clear MPEG ends and encryption begins
    enc_start = find_encryption_start(data)

    # Recover the key via known-plaintext attack
    key, key_len = derive_key(data, enc_start)

    if key is None:
        print(f'  FAIL {filename}: Could not derive key '
              f'(enc_start=0x{enc_start:X}, size={len(data)})')
        return False

    # Decrypt the encrypted region in-place
    for i in range(enc_start, len(data)):
        data[i] = (data[i] - key[(i - enc_start) % key_len]) & 0xFF

    # Write output: strip PAVENCRYPT header, output clean MPEG-1 PS
    with open(output_path, 'wb') as f:
        f.write(data[10:])

    # Verify integrity
    end_code = data[-4:]
    valid_end = (end_code == bytearray([0x00, 0x00, 0x01, 0xB9]))

    key_display = ''.join(chr(b) if 32 <= b < 127 else '.' for b in key)
    status = "valid" if valid_end else "no-end-code"
    out_size = os.path.getsize(output_path)

    print(f'  OK   {filename:<16} key_len={key_len:<3} enc=0x{enc_start:04X} '
          f'end={status:<12} out={out_size/1024:.0f}KB  key="{key_display}"')
    return True


def main():
    # Parse arguments
    if len(sys.argv) >= 3:
        pav_dir = sys.argv[1]
        output_dir = sys.argv[2]
    elif len(sys.argv) == 2:
        pav_dir = sys.argv[1]
        output_dir = 'extracted'
    else:
        pav_dir = 'iso_contents'
        output_dir = 'extracted'

    if not os.path.isdir(pav_dir):
        print(f'ERROR: Input directory not found: {pav_dir}')
        print(f'Usage: python decrypt_pav.py [input_dir] [output_dir]')
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    pav_files = sorted(f for f in os.listdir(pav_dir) if f.upper().endswith('.PAV'))
    if not pav_files:
        print(f'No .PAV files found in {pav_dir}/')
        sys.exit(1)

    print(f'WCW CyberRing PAV Decryptor')
    print(f'Input:  {os.path.abspath(pav_dir)}/ ({len(pav_files)} files)')
    print(f'Output: {os.path.abspath(output_dir)}/')
    print()

    success = 0
    fail = 0
    for pav_file in pav_files:
        input_path = os.path.join(pav_dir, pav_file)
        output_name = os.path.splitext(pav_file)[0] + '.mpg'
        output_path = os.path.join(output_dir, output_name)

        if decrypt_pav(input_path, output_path):
            success += 1
        else:
            fail += 1

    total_size = sum(
        os.path.getsize(os.path.join(output_dir, f))
        for f in os.listdir(output_dir) if f.endswith('.mpg')
    )

    print(f'\nResults: {success} succeeded, {fail} failed out of {len(pav_files)} files')
    print(f'Total output: {total_size/1024/1024:.1f} MB')

    if fail > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
