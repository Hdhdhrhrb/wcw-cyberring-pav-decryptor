# Reverse Engineering Timeline

Step-by-step record of how the PAVENCRYPT format was broken.

---

## Phase 1: ISO Extraction and File Discovery

**Input**: `WCW_R1.ISO` (562 MB)

Extracted the ISO using 7-Zip. Key findings on the disc:

```
61 .PAV files          - The encrypted video content
MPFULL.EXE             - Windows Media Player 2 installer (self-extracting CAB)
DirectX installer      - DirectX 6 runtime
SETUP.EXE / SETUP.INS  - InstallShield 5 installer
DATA1.CAB / DATA1.HDR   - InstallShield compressed data
AUTORUN.INF            - Points to ISetup.exe
```

The ISO was created with Toast ISO 9660 Builder (Adaptec) on 1999-09-10.

---

## Phase 2: PAV File Format Identification

**Tool**: Hex editor, Python

Examined the first bytes of each PAV file:

```
Offset 0x00: 50 41 56 45 4E 43 52 59 50 54  = "PAVENCRYPT"
Offset 0x0A: 00 00
Offset 0x0C: 00 00 01 BA ...                 = MPEG-1 Pack Start Code
```

Key observations:
- All 61 files begin with the 10-byte ASCII magic `PAVENCRYPT`
- Immediately after: valid MPEG-1 Program Stream data
- The MPEG data becomes invalid/random after ~16-32 KB (varies per file)
- The remaining 98%+ of each file has flat byte distribution (encrypted)

Ran ffprobe on data after stripping the 10-byte header:
- Detected MPEG-1 video: 320x240, 30fps
- Only found 2 frames (0.08 seconds) before data became garbage
- No audio detected in the clear section

---

## Phase 3: InstallShield CAB Extraction

**Tool**: `unshield` (WSL Ubuntu)

The SETUP.INS (InstallShield 5 script) revealed the software stack:
- **UlPlayer.exe** - Standalone player application
- **PavSource.ax** - DirectShow source filter (the decryption engine)
- **npUliPlugin.dll** - Netscape browser plugin
- **6 .grf files** - DirectShow filter graph definitions
- **WebPage.exe** - Helper executable

Registry entries revealed:
- Company: **UIT** (registry: `SOFTWARE\UIT\UliPlayer`)
- MIME type: `video/ulifmt`
- File signature check: `0,10,,504156454E4352595054`
- Filter CLSID: `{B7DF26A4-D0A2-11D2-AE6F-00105A15EBCC}`

Extracted using unshield since 7-Zip cannot handle ISc( format InstallShield CABs:
```bash
unshield -d extracted x DATA1.CAB
```

---

## Phase 4: PavSource.ax Disassembly

**Tool**: Python (manual PE parsing and x86 disassembly)

PavSource.ax: 24,576 bytes, PE32 DLL, built 1999-04-28.

### Import Analysis

| DLL | Functions | Significance |
|-----|-----------|--------------|
| KERNEL32.dll | CreateFile, ReadFile, SetFilePointer, etc. | File I/O |
| MSVCRT.dll | atoi, strlen, memcpy, etc. | String/memory ops |
| WINMM.dll | timeGetTime | Timing |
| ole32.dll | CoTaskMemAlloc/Free | COM memory |

Notable absence: **No crypto API imports** (no CryptDecrypt, no BCrypt, no OpenSSL).
This confirmed the cipher is custom and likely simple.

### Code Section Analysis

The .text section is only 17 KB. Systematic disassembly found:

**The Decryption Loop** (file offset 0x0678, VA 0x1D1C1278):

```assembly
loop_start:
    cmp  esi, edi                ; position >= end?
    je   done
    cmp  edx, [ebx + 0x13c]     ; key_index >= key_length?
    jl   no_wrap
    xor  edx, edx               ; key_index = 0 (wrap)
no_wrap:
    mov  eax, [ebp - 4]         ; buffer base
    mov  cl, [ebx + edx + 0x3c] ; cl = key[key_index]
    add  eax, esi               ; eax = &buffer[position]
    sub  byte ptr [eax], cl     ; buffer[pos] -= key[idx]  ← THE CIPHER
    inc  edx                    ; key_index++
    inc  esi                    ; position++
    jmp  loop_start
```

This is a **subtraction cipher**, not XOR. Each byte of ciphertext has the corresponding
key byte subtracted (mod 256) to produce plaintext.

Object layout:
- `+0x3C`: Key buffer (up to 256 bytes)
- `+0x13C`: Key length (DWORD)
- `+0x140`: Key rotation offset (NUMBER2)
- `+0x144`: Encryption length/flag (NUMBER1)

---

## Phase 5: Key Parsing Function

**Location**: File offset 0x0A43, VA 0x1D1C1643

Found the function that parses the key configuration string:

```
Input format: "NUMBER1-NUMBER2-KEYSTRING"
```

The function:
1. Scans for first `-` separator
2. Calls `atoi()` on the first token → stores at object+0x144
3. Scans for second `-` separator
4. Calls `atoi()` on the second token → stores at object+0x140
5. Copies remaining string to object+0x3C (the key buffer)
6. Stores `strlen(remaining)` at object+0x13C (key length)

---

## Phase 6: Key Source Investigation

**Finding**: Keys are NOT on the disc.

Examined every possible local source:
- PAV file headers: All 61 files have identical bytes 10-30 (no per-file key data)
- .grf files: Contain only DirectShow CLSIDs, no key material
- PavSource.ax constants: No hardcoded key strings
- UlPlayer.exe strings: Found `"Decryption key not found in the server database"`
- Registry references: `SOFTWARE\UIT\UliPlayer\Servers` with `server=`, `port=` parameters

**Conclusion**: Keys were retrieved from a remote UIT server at runtime. The server
has been offline for ~24 years. No legitimate way to obtain keys exists.

---

## Phase 7: Known-Plaintext Attack

**Breakthrough**: Exploiting MPEG-1 PS structure to recover keys without the server.

### The Insight

MPEG-1 Program Stream files have predictable byte patterns:
- Pack headers: `00 00 01 BA`
- PES padding: `00 00 01 BE` followed by length and 0xFF fill bytes
- Program end code: `00 00 01 B9` (last 4 bytes)

The file tail typically contains a large PES padding packet filled with 0xFF bytes.
When encrypted with a repeating subtraction key, this produces a repeating ciphertext
pattern with the same period as the key.

### The Attack

1. **Detect key length**: Autocorrelate the tail bytes. The period with >95% match
   rate is the key length.

2. **Derive key bytes**: For each key position `i`:
   ```
   key[i] = (ciphertext_tail[i] - 0xFF) mod 256
   ```
   Uses majority voting across multiple key-length cycles for robustness.

3. **Compute alignment**: The tail doesn't necessarily start aligned to the key:
   ```
   offset_into_key = (tail_position - encryption_start) mod key_length
   ```

4. **Verify**: Decrypt the first 4 encrypted bytes. Must produce:
   - `00 00 01 BA` (Pack Header) - most common, or
   - `00 00 01 E0` (Video PES) - when encryption boundary falls mid-pack

### Results

- **58/61 files**: Decrypted on first attempt (standard 0xFF padding detection)
- **3/61 files** (BUFFBIO, DDPHAT, OAKFW): Required adjusted periodicity threshold;
  the tail pattern was slightly less clean but keys still derivable
- **61/61 files**: All successfully decrypted and verified

---

## Phase 8: Verification and Conversion

**Tool**: ffprobe, ffmpeg

All 61 decrypted MPG files verified:
- Valid MPEG-1 Program Stream structure
- Video: MPEG-1, 320x240, 30fps progressive, ~1.29 Mbps
- Audio: MPEG Layer 2, 44100 Hz, mono, 64 kbps
- Duration range: 10 seconds (INTRO) to 4:07 (TVKCYBER)
- Total content: 51 minutes 20 seconds

Batch-converted to H.264/AAC MP4 for modern playback.

---

## Key Observations

### Why the Cipher Was Weak

1. **No IV/nonce**: Same key always produces same ciphertext for same plaintext
2. **Repeating key**: Short keys (8-24 bytes) cycle over megabytes of data
3. **Known plaintext abundance**: MPEG-1 PS has highly predictable structure
4. **No authentication**: Bit-flipping attacks trivial (not relevant here)
5. **Printable ASCII keys**: Reduces keyspace to ~95^24 instead of 256^24

### Why It Wasn't Broken Sooner

1. The product was obscure (WCW Magazine promo, late 1999)
2. The player worked transparently when the server was online
3. By the time the server died, the product was forgotten
4. The InstallShield CAB format made extracting PavSource.ax non-trivial
5. The `SUB` instruction (not XOR) isn't the first thing RE analysts look for in "encryption"

### Applicability

This exact technique works on any PAVENCRYPT file where:
- The underlying format has known byte patterns in predictable locations
- The key is short enough to detect via autocorrelation
- The file is long enough to have multiple key-length cycles of known plaintext

Other MPEG-1 based DRM systems from the late 1990s likely have similar vulnerabilities.
