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

**Tools**: Hex editor, Python

We examined the first bytes of each PAV file:

```
Offset 0x00: 50 41 56 45 4E 43 52 59 50 54  = "PAVENCRYPT"
Offset 0x0A: 00 00
Offset 0x0C: 00 00 01 BA ...                 = MPEG-1 Pack Start Code
```

Key observations:
- All 61 files begin with the 10-byte ASCII magic `PAVENCRYPT`
- Valid MPEG-1 Program Stream data immediately follows the header
- The MPEG data becomes invalid after approximately 16-32 KB (varies per file)
- The remaining 98% of each file exhibits flat byte distribution (encrypted)

We ran ffprobe on data after stripping the 10-byte header:
- Detected MPEG-1 video at 320x240 resolution, 30fps
- Found only 2 frames (0.08 seconds) before data became corrupted
- No audio detected in the unencrypted section

---

## Phase 3: InstallShield CAB Extraction

**Tool**: `unshield` (WSL Ubuntu)

The SETUP.INS file (InstallShield 5 script) revealed the software stack:
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

Notable absence: **No crypto API imports**. No CryptDecrypt, no BCrypt, no OpenSSL.
This confirmed the cipher was custom and likely simple.

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

This implements a **subtraction cipher**, not XOR. Each ciphertext byte has its corresponding
key byte subtracted (modulo 256) to produce the plaintext.

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

**Finding**: Keys are not stored on the disc.

We examined every possible local source:
- PAV file headers: All 61 files have identical bytes 10-30 (no per-file key data)
- .grf files: Contain only DirectShow CLSIDs, no key material
- PavSource.ax constants: No hardcoded key strings
- UlPlayer.exe strings: Found `"Decryption key not found in the server database"`
- Registry references: `SOFTWARE\UIT\UliPlayer\Servers` with `server=`, `port=` parameters

**Conclusion**: Keys were retrieved from a remote UIT server at runtime. The server
has been offline for approximately 24 years. No legitimate method exists to obtain the keys.

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
pattern with period equal to the key length.

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

- **58/61 files**: Decrypted on first attempt using standard 0xFF padding detection
- **3/61 files** (BUFFBIO, DDPHAT, OAKFW): Required adjusted periodicity threshold.
  The tail pattern was slightly less clean but keys remained derivable.
- **61/61 files**: All successfully decrypted and verified

---

## Phase 8: Verification and Conversion

**Tools**: ffprobe, ffmpeg

All 61 decrypted MPG files were verified:
- Valid MPEG-1 Program Stream structure
- Video: MPEG-1, 320x240, 30fps progressive, ~1.29 Mbps
- Audio: MPEG Layer 2, 44100 Hz, mono, 64 kbps
- Duration range: 10 seconds (INTRO) to 4:07 (TVKCYBER)
- Total content: 51 minutes 20 seconds

Files were batch-converted to H.264/AAC MP4 format for modern playback compatibility.

---

## Key Observations

### Why the Cipher Was Weak

1. **No IV/nonce**: Same key always produces same ciphertext for identical plaintext
2. **Repeating key**: Short keys of 8-24 bytes cycle over megabytes of data
3. **Known plaintext abundance**: MPEG-1 PS has highly predictable structure
4. **No authentication**: Bit-flipping attacks are trivial (not relevant here)
5. **Printable ASCII keys**: Reduces keyspace to approximately 95^24 instead of 256^24

### Why It Wasn't Broken Sooner

1. The product was obscure: a WCW Magazine promo from late 1999
2. The player worked transparently while the server remained online
3. By the time the server died, the product had been forgotten
4. The InstallShield CAB format made extracting PavSource.ax non-trivial
5. The `SUB` instruction (not XOR) is not the first operation RE analysts check when analyzing encryption

### Applicability

This technique works on any PAVENCRYPT file meeting these conditions:
- The underlying format contains known byte patterns in predictable locations
- The key is short enough to detect via autocorrelation analysis
- The file is long enough to contain multiple key-length cycles of known plaintext

Other MPEG-1 based DRM systems from the late 1990s likely possess similar vulnerabilities.

---

## Phase 9: Primary Source Discovery

**Date**: January 2025 (post-completion)

**Finding**: Located the original SEC-filed license agreement documenting the encryption technology.

**Document**: License Agreement between United Internet Technologies, Inc. and WCW
**Filed**: April 15, 1999 (SEC Exhibit 10.48)
**Source**: https://www.lawinsider.com/contracts/2gp1TeImAUA

### Key Excerpts

**Exhibit A, Section 3 (Server Side Key Generator Program):**
> "The application will have the capability to create security keys based on time. Therefore, the end user will only be able to utilize the video while they are connected to the Internet and only for specific amounts of time."

**Exhibit A, Section 5 (ULI Video Player):**
> "This application enables the end user to open and play DIVO and PAV files within the browser while connected to the website server (subject to any limitations programmed by the website operator)."

### Significance

This primary source **independently validates** our reverse engineering findings from 25 years later:

| Our Technical Discovery | Contract Documentation |
|------------------------|------------------------|
| Server-side key retrieval system | "Server Side Key Generator Program (SSKGP)" |
| Time-based key generation | "Security keys based on time" |
| Network dependency for playback | "While connected to the website server" |
| PAV file format | "DIVO and PAV files" |
| Keys never stored locally | "End user will only be able to utilize the video while connected to the Internet" |

### The Complete Picture

**1999:**
- WCW pays UIT $200,000 for 3-year technology license
- UIT provides Server Side Key Generator Program (SSKGP)
- System generates "security keys based on time"
- Keys served from remote infrastructure

**~2000:**
- UIT server infrastructure goes offline
- Key generation system becomes inaccessible
- Content permanently locked

**2024-2025:**
- Binary reverse engineering of PavSource.ax
- Cryptanalysis discovers repeating-key subtraction cipher
- Known-plaintext attack recovers all 61 keys
- Content decrypted without server access

**2025:**
- SEC filing discovered
- Primary source confirms technical architecture
- **Independent validation:** Our findings exactly match 1999 legal documentation

### Irony

WCW paid $200,000 for encryption technology that:
- Successfully protected content for 25 years
- Failed permanently when vendor (UIT) disappeared
- Was ultimately broken using information **disclosed in their own SEC filing**

The contract described "security keys based on time." This architectural dependency was the exact vulnerability we exploited via known-plaintext attack on time-sensitive MPEG-1 padding patterns.

### Documentation

See **[docs/PRIMARY_SOURCES.md](../docs/PRIMARY_SOURCES.md)** for full analysis of the SEC filing and its technical implications.
