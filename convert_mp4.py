"""
Batch converter for decrypted WCW CyberRing MPEG-1 files.
Converts .mpg files in extracted/ to H.264/AAC .mp4 in extracted/mp4/.
Requires ffmpeg in PATH or at the default winget install location.
"""

import os
import subprocess
import shutil
import sys


def find_ffmpeg():
    """Locate ffmpeg executable."""
    # Check PATH first
    ffmpeg = shutil.which('ffmpeg')
    if ffmpeg:
        return ffmpeg

    # Check common Windows install locations
    winget_path = os.path.expanduser(
        r'~\AppData\Local\Microsoft\WinGet\Packages')
    if os.path.isdir(winget_path):
        for d in os.listdir(winget_path):
            if 'FFmpeg' in d:
                candidate = os.path.join(winget_path, d)
                for root, dirs, files in os.walk(candidate):
                    if 'ffmpeg.exe' in files:
                        return os.path.join(root, 'ffmpeg.exe')

    return None


def main():
    input_dir = 'extracted'
    output_dir = os.path.join('extracted', 'mp4')
    os.makedirs(output_dir, exist_ok=True)

    ffmpeg = find_ffmpeg()
    if not ffmpeg:
        print('ERROR: ffmpeg not found. Install via: winget install Gyan.FFmpeg')
        sys.exit(1)

    print(f'Using ffmpeg: {ffmpeg}')

    files = sorted(f for f in os.listdir(input_dir) if f.endswith('.mpg'))
    if not files:
        print('No .mpg files found in extracted/. Run decrypt_pav.py first.')
        sys.exit(1)

    print(f'Converting {len(files)} files to MP4...\n')

    success = 0
    for i, f in enumerate(files):
        input_path = os.path.join(input_dir, f)
        output_name = os.path.splitext(f)[0] + '.mp4'
        output_path = os.path.join(output_dir, output_name)

        result = subprocess.run([
            ffmpeg, '-y', '-i', input_path,
            '-c:v', 'libx264', '-crf', '18', '-preset', 'medium',
            '-c:a', 'aac', '-b:a', '128k',
            '-movflags', '+faststart',
            output_path
        ], capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            out_size = os.path.getsize(output_path)
            print(f'  [{i+1:2d}/{len(files)}] {f:<20} -> {output_name:<20} '
                  f'({out_size/1024:.0f} KB)')
            success += 1
        else:
            err = result.stderr.strip().split('\n')[-1] if result.stderr else 'unknown'
            print(f'  [{i+1:2d}/{len(files)}] {f:<20} FAILED: {err}')

    total_size = sum(
        os.path.getsize(os.path.join(output_dir, f))
        for f in os.listdir(output_dir) if f.endswith('.mp4')
    )
    print(f'\nDone: {success}/{len(files)} converted')
    print(f'Total MP4 size: {total_size/1024/1024:.1f} MB')
    print(f'Output directory: {os.path.abspath(output_dir)}')


if __name__ == '__main__':
    main()
