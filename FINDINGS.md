# WCW CyberRing - Technical Findings

## Historical Context

The **WCW Internet Powerdisk** (variously labeled "CyberRing" and "Slam Society" on-disc)
was a promotional CD-ROM bundled with WCW Magazine in late 1999. It contained exclusive
wrestling video content - match highlights, wrestler bios, merchandise promos, and storyline
segments - featuring stars like Hulk Hogan, Goldberg, Sting, DDP, and Kevin Nash.

The disc used a proprietary DRM system created by a company called **UIT** (makers of the
"ULI Player"). Videos were encrypted in a format called **PAVENCRYPT** and required the
ULI Player application, which retrieved per-file decryption keys from a remote server at
playback time. The player registered a DirectShow source filter (`PavSource.ax`) that
transparently decrypted the stream during graph playback.

### Why It Became Lost

When UIT's key server went offline around 2000 (shortly after WCW itself folded in 2001),
the encrypted content became permanently inaccessible. The player would display:
*"Decryption key not found in the server database"*. No keys were stored on the disc,
no offline fallback existed, and UIT appears to have dissolved without any public
documentation of their format.

For 25 years, these 61 video files sat encrypted on anyone's copy of the disc with no
known method of recovery - until now.

---

## The PAV File Format

### Magic Header

```
Offset  Bytes                              Meaning
------  ---------------------------------  -------------------------
0x00    50 41 56 45 4E 43 52 59 50 54      "PAVENCRYPT" (10-byte magic)
0x0A    00 00 01 BA ...                    MPEG-1 PS Pack Header (start of video data)
```

The MPEG-1 Program Stream begins immediately after the 10-byte magic with no gap.
The `00 00` at offset 0x0A are the first two bytes of the MPEG start code prefix
(`00 00 01`), not separate null padding.

- MIME type: `video/ulifmt`
- File signature (as registered in SETUP.INS): `0,10,,504156454E4352595054`

### Preview Section (Unencrypted)

Bytes 0x0C through the encryption boundary (~0x4896 to ~0x7F0E, varies per file) contain
a valid but minimal MPEG-1 Program Stream:

- 7-9 pack headers with system headers
- 2 video frames only (I-frame + P-frame)
- No audio elementary stream
- Serves as a thumbnail/preview in the ULI Player UI

### Encrypted Section

From the encryption boundary to EOF:
- Same MPEG-1 PS format (pack headers, PES packets, program end code)
- Full audio+video content
- Encrypted with per-file subtraction cipher

### File Structure Diagram

```
┌──────────────────────────────────────────────────────────┐
│ Offset 0x00: "PAVENCRYPT" (10 bytes magic)               │
├──────────────────────────────────────────────────────────┤
│ Offset 0x0A: Unencrypted MPEG-1 PS Preview               │
│ (16-32 KB, 2 I/P video frames, no audio stream)          │
│ Encryption boundary varies: 0x4896 - 0x7F0E              │
├──────────────────────────────────────────────────────────┤
│ Encrypted MPEG-1 PS                                      │
│ (Subtraction cipher, per-file key, 8-24 byte key length) │
│                                                          │
│ Contains: Full video + audio                             │
│ Video: MPEG-1, 320x240, 30fps, ~1.29 Mbps               │
│ Audio: MP2, 44100 Hz, Mono, 64 kbps                      │
│                                                          │
│ Tail: 0xFF padding + 00 00 01 B9 (Program End Code)      │
└──────────────────────────────────────────────────────────┘
```

---

## Software Architecture

### DirectShow Filter Graph

The ULI Player constructed this DirectShow graph for playback:

```
PAV Source Filter ──→ MPEG-I Stream Splitter ──┬──→ MPEG Video Decoder ──→ Video Renderer
(PavSource.ax)        (quartz.dll)             │     (quartz.dll)          (quartz.dll)
                                               │
                                               └──→ MPEG Audio Decoder ──→ DirectSound Device
                                                    (quartz.dll)           (quartz.dll)
```

This graph was defined in `uli.grf` (OLE Compound Document containing an `ActiveMovieGraph`
stream). The PAV Source Filter handled both file I/O and decryption, outputting clean
MPEG-1 PS to the standard Windows MPEG demuxer and decoders.

### Component Details

| Component | CLSID | Function |
|-----------|-------|----------|
| PavSource.ax | {B7DF26A4-D0A2-11D2-AE6F-00105A15EBCC} | Decrypt + source |
| PAV-Transform | {D2481C74-C21C-11D2-BF62-00105A15EBCC} | Transform filter (in uli.grf) |
| MPEG-I Splitter | {336475D0-942A-11CE-A870-00AA002FEAB5} | Demux PS to ES |
| MPEG Video Decoder | {FEB50740-7BEF-11CE-9BD9-0000E202599C} | Decode video |
| MPEG Audio Decoder | {4A2286E0-7BEF-11CE-9BD9-0000E202599C} | Decode audio |

### PavSource.ax Binary Details

```
File size:       24,576 bytes
PE timestamp:    1999-04-28
Architecture:    x86 (PE32)
Sections:        .text (17 KB), .rdata, .data, .rsrc, .reloc
Exports:         DllCanUnloadNow, DllGetClassObject
Imports:         KERNEL32 (file I/O), MSVCRT (string ops), WINMM (timing), ole32 (COM)
```

No crypto API imports - the cipher is entirely custom, implemented in 25 bytes of x86.

---

## The Encryption

### Algorithm: Repeating-Key Subtraction

```c
// Decryption (from PavSource.ax disassembly)
void decrypt(uint8_t *buffer, int length, uint8_t *key, int key_len) {
    int key_idx = 0;
    for (int i = 0; i < length; i++) {
        buffer[i] = (buffer[i] - key[key_idx]) & 0xFF;
        key_idx++;
        if (key_idx >= key_len)
            key_idx = 0;
    }
}
```

### Disassembly (PavSource.ax, file offset 0x0678)

```assembly
; ESI = current position, EDI = end position
; EDX = key index, EBX = object pointer
; [ebp-4] = buffer base address

1D1C1278: cmp    esi, edi              ; position >= end?
1D1C127A: je     1D1C1298              ; if yes, done
1D1C127C: cmp    edx, [ebx+0x13C]     ; key_index >= key_length?
1D1C1282: jl     1D1C1286             ; if not, skip wrap
1D1C1284: xor    edx, edx             ; key_index = 0
1D1C1286: mov    eax, [ebp-4]         ; load buffer base
1D1C1289: mov    cl, [ebx+edx+0x3C]   ; cl = key[key_index]
1D1C128D: add    eax, esi             ; eax = &buffer[position]
1D1C128F: sub    byte ptr [eax], cl   ; DECRYPT: *ptr -= key_byte
1D1C1291: inc    edx                  ; key_index++
1D1C1292: inc    esi                  ; position++
1D1C1293: jmp    1D1C1278             ; loop
```

The critical instruction is at **0x1D1C128F**: `sub byte ptr [eax], cl`. This is
subtraction, not XOR - an important distinction that initially led analysis down the
wrong path when XOR-based decryption attempts all failed.

### Key Format

The key configuration is passed to the filter as a dash-separated string:

```
FORMAT: "NUMBER1-NUMBER2-KEYSTRING"

EXAMPLE: "1730566-18582-lCKPi7IO5CllGDU5^V=EoRM<"
```

| Field | Object Offset | Purpose |
|-------|--------------|---------|
| NUMBER1 | +0x144 | Encrypted region length (bytes) |
| NUMBER2 | +0x140 | File offset where encryption begins |
| KEYSTRING | +0x3C | The actual key bytes |
| strlen(KEYSTRING) | +0x13C | Key length |

### Key Parsing Function (file offset 0x0A43)

```assembly
; Parse "NUM1-NUM2-KEY" format
; Scan for '-' separators, extract three fields
1D1C1643: push   ebp
          ...
1D1C1727: call   [atoi]           ; parse NUMBER1
          ...
          call   [atoi]           ; parse NUMBER2
          ...
          ; Copy KEYSTRING to object+0x3C
          ; Store strlen at object+0x13C
```

### Key Source: Remote Server

Keys were served from a network server, never stored locally:

- Registry: `HKLM\SOFTWARE\UIT\UliPlayer\Servers`
- Parameters: `server=`, `port=`
- Error string in UlPlayer.exe: `"Decryption key not found in the server database"`
- The server has been offline for approximately 24 years

---

## Key Recovery: Known-Plaintext Attack

### Theoretical Basis

A repeating-key subtraction cipher is trivially broken when plaintext is known at any
position, because:

```
key[i % key_len] = (ciphertext[i] - known_plaintext[i]) mod 256
```

One full key-length of known plaintext completely determines the key.

### Exploitable MPEG-1 Structure

MPEG-1 Program Streams contain abundant known plaintext:

| Location | Known Bytes | Notes |
|----------|-------------|-------|
| Pack headers | `00 00 01 BA` | Every ~2KB throughout file |
| PES headers | `00 00 01 E0/C0` | Video/audio packet starts |
| PES padding | `00 00 01 BE` + `FF FF FF...` | Fill between packets |
| Program end | `00 00 01 B9` | Last 4 bytes |
| Padding fill | `0xFF` bytes | Large blocks near EOF |

### The Attack (as implemented)

**Step 1: Detect key length via autocorrelation**

The file tail contains encrypted 0xFF padding bytes. With a repeating key, this produces
ciphertext that repeats with the key's period:

```python
for key_len in range(1, 129):
    matches = sum(1 for i in range(key_len, len(tail))
                  if tail[i] == tail[i - key_len])
    if matches / (len(tail) - key_len) > 0.95:
        # Found the key length
```

**Step 2: Derive key bytes**

```python
# If plaintext is 0xFF, then: key[i] = (ciphertext[i] - 0xFF) mod 256
for ki in range(key_len):
    votes = [(tail[j] - 0xFF) & 0xFF
             for j in range(len(tail))
             if (tail_start + j - enc_start) % key_len == ki]
    key[ki] = Counter(votes).most_common(1)[0][0]  # majority vote
```

**Step 3: Verify against known structure**

```python
# Decrypt first 4 encrypted bytes - must be Pack Header
test = [(data[enc_start + i] - key[i % key_len]) & 0xFF for i in range(4)]
assert test == [0x00, 0x00, 0x01, 0xBA]  # MPEG-1 Pack Start Code
```

### Results

| Metric | Value |
|--------|-------|
| Files attempted | 61 |
| Files recovered | 61 (100%) |
| Key lengths observed | 8 to 24 bytes |
| Key character set | Printable ASCII (0x30-0x7A typical) |
| Total recovered content | 51 min 20 sec |

---

## Recovered Keys (All 61 Files)

| # | File | Enc Start | Key Len | Key |
|---|------|-----------|---------|-----|
| 1 | ARNBIO.PAV | 0x5ABE | 9 | `:4[uJIYbX` |
| 2 | ARNSHIRT.PAV | 0x51AA | 13 | `A6C7P@FdVkHvW` |
| 3 | BAMBIO.PAV | 0x51AA | 15 | `HDX0kvB7_SGRb=k` |
| 4 | BUFFBIO.PAV | 0x5ABE | 20 | `KK_m1qA7]SonkO5;mFY[` |
| 5 | CAT.PAV | 0x63D2 | 16 | `5g9hKNDJ1\:[p568` |
| 6 | CATBIO.PAV | 0x51AA | 9 | `Ut2[R^2FB` |
| 7 | DDPBIO.PAV | 0x7F0E | 16 | `EjxChoREJ\R7aEe`` |
| 8 | DDPHAT.PAV | 0x4896 | 20 | `0MvTsj6]A^UGnhVbqn?s` |
| 9 | DISCOBIO.PAV | 0x51AA | 8 | `E9ZwF[MX` |
| 10 | FLAIRBIO.PAV | 0x51AA | 11 | `0LS[?qq0tiS` |
| 11 | FVWCYBER.PAV | 0x6CD2 | 19 | `hRq`KB[C1^\9E6cIIRq` |
| 12 | GOLDBIO.PAV | 0x51AA | 17 | `4uhXA]]8CaJ=l^4Bw` |
| 13 | GOLDHIGH.PAV | 0x7F0E | 8 | `hC[U;PEv` |
| 14 | GOLDSHRT.PAV | 0x75FA | 12 | `ru=g0^PwrGSY` |
| 15 | HACKER1.PAV | 0x63D2 | 8 | `nCNwheUp` |
| 16 | HACKER2.PAV | 0x6CE6 | 10 | `XFhin@NHDp` |
| 17 | HACKER3.PAV | 0x6CE6 | 10 | `?JqBg3BkJ>` |
| 18 | HACKER4.PAV | 0x51AA | 14 | `@BcCl^^]@2ML[U` |
| 19 | HACKER5.PAV | 0x7EFA | 14 | `5NDK8ebHe0amhK` |
| 20 | HACKER6.PAV | 0x51AA | 12 | `5HdhIeU^bGM4` |
| 21 | HACKER7.PAV | 0x63D2 | 19 | `9_Z>6ffHm`9?dJmD<Zi` |
| 22 | HACKER8.PAV | 0x5ABE | 16 | `jTaripXR9A8@9baw` |
| 23 | HHIGH.PAV | 0x5ABE | 14 | `i59vcVv8eU2WZ@` |
| 24 | HOGANBIO.PAV | 0x75FA | 22 | `Hi@uW5n=;2_^R6g6_^WfH]` |
| 25 | HOGANMER.PAV | 0x51AA | 16 | `t\lLA_B0bY;lW>@@` |
| 26 | HVGHIGH.PAV | 0x6CD2 | 8 | `8gA9YLcD` |
| 27 | HVMHIGH.PAV | 0x63D2 | 10 | `=exeLDN3TP` |
| 28 | INTRO.PAV | 0x4896 | 24 | `lCKPi7IO5CllGDU5^V=EoRM<` |
| 29 | KIDVID.PAV | 0x63D2 | 19 | `YnjH?<tNPoGK=]VgMkW` |
| 30 | KNOB.PAV | 0x6CE6 | 12 | `DY]9bajT[lEU` |
| 31 | KNOBBIO.PAV | 0x63D2 | 15 | `l0Rh;Y?OHa=R7;9` |
| 32 | KNOBMER.PAV | 0x6CE6 | 16 | `5SH=quOq@\[tNBcF` |
| 33 | KNOBS1.PAV | 0x7F0E | 22 | `E:GLL`bM8hicRQi[3nM2o8` |
| 34 | KNOBS2.PAV | 0x63D2 | 12 | `2EP2m6[1Peca` |
| 35 | KONNAN.PAV | 0x63D2 | 17 | `N]9bROJ_H:0f=^X3?` |
| 36 | MADUSA.PAV | 0x63D2 | 9 | `9SMjhjs2_` |
| 37 | MYSTERIO.PAV | 0x63BE | 20 | `H6@`dM@XLgspBbHm1fBX` |
| 38 | NASHBIO.PAV | 0x75FA | 22 | `Cq@VeD^]5kGjJkBusb=;Y9` |
| 39 | NASHCHRT.PAV | 0x4896 | 21 | `Ksn_:QkGnk;QvocwFJ4DR` |
| 40 | NASHHAT.PAV | 0x63D2 | 9 | `8M]m0e0?o` |
| 41 | NGIRLS.PAV | 0x7F0E | 23 | `pK>HHTK<Z@bnC?@Id?l6Le]` |
| 42 | NITRO.PAV | 0x75E6 | 23 | `o>A8nWSc9JB2kAwV]1l0KIc` |
| 43 | NITRO2.PAV | 0x63D2 | 19 | `H<n^=cRAZFF58T^sRS3` |
| 44 | OAKFW.PAV | 0x7F06 | 12 | `vUlGG4L1LHLC` |
| 45 | OAKPH.PAV | 0x4896 | 19 | `mEF;i[p7CMUeIT;m>1d` |
| 46 | OAKTK.PAV | 0x63BE | 19 | `vwoQ;wrE[HA:f6[V?:;` |
| 47 | PVHCYBER.PAV | 0x63BE | 10 | `qlTw3CbJiE` |
| 48 | RIGGS1.PAV | 0x4896 | 13 | `YEO>v4R:1fkvn` |
| 49 | RIGGS2.PAV | 0x6CE6 | 10 | `2^ia2JHUo5` |
| 50 | SJHEEVE.PAV | 0x7F0E | 22 | `w>\fu[S2teqtj<Q?EN:aBA` |
| 51 | SJPUNISH.PAV | 0x51AA | 16 | `XL3V=O1Uej8qGaG3` |
| 52 | SJVEGG.PAV | 0x75FA | 15 | `5K[s>R<ViZqH^CW` |
| 53 | STEINBIO.PAV | 0x63D2 | 23 | `=rs1Lv4CL^gwm=I_u`N;662` |
| 54 | STINGBIO.PAV | 0x5ABE | 9 | `_jbQU::h?` |
| 55 | STINGMER.PAV | 0x63D2 | 13 | `C@LJm\oGrOoeG` |
| 56 | STINGPRO.PAV | 0x5ABE | 22 | `G]u@jRA9K3O?`214?ZWb8j` |
| 57 | SURGE.PAV | 0x51AA | 9 | `^F9ubG=_n` |
| 58 | SVNHIGH.PAV | 0x5ABE | 19 | `0tvN\Ru`4KLn2TQ7jLi` |
| 59 | SVSHIGH.PAV | 0x75FA | 11 | `C^Ckw^hwDFa` |
| 60 | THUNDER.PAV | 0x51AA | 21 | `b2bH0f09>aq>N4vKP0YoS` |
| 61 | TVKCYBER.PAV | 0x6CD2 | 13 | `cm61wVqq?oopf` |

---

## Encryption Start Offsets

Interesting pattern - only 8 distinct encryption start offsets exist across all 61 files:

| Offset | Hex | Files Using It |
|--------|-----|----------------|
| 18,582 | 0x4896 | 5 files |
| 20,906 | 0x51AA | 14 files |
| 23,230 | 0x5ABE | 8 files |
| 25,554 | 0x63BE | 3 files |
| 25,554 | 0x63D2 | 17 files |
| 27,878 | 0x6CE6 | 6 files |
| 27,858 | 0x6CD2 | 3 files |
| 30,182 | 0x75E6 | 1 file |
| 30,202 | 0x75FA | 5 files |
| 32,518 | 0x7F06 | 1 file |
| 32,526 | 0x7F0E | 5 files |
| 32,506 | 0x7EFA | 1 file |

These correspond to different amounts of preview content (more packs = later encryption start).

---

## Content Inventory

### Decrypted Video Specifications

| Property | Value |
|----------|-------|
| Container | MPEG-1 Program Stream (.mpg) |
| Video Codec | MPEG-1 Video |
| Resolution | 320x240 (4:3) |
| Frame Rate | 30 fps progressive |
| Video Bitrate | ~1,289,600 bps (~1.29 Mbps) |
| Audio Codec | MPEG Audio Layer 2 |
| Sample Rate | 44,100 Hz |
| Channels | Mono |
| Audio Bitrate | 64,000 bps |

### Full File List with Durations

| File | Duration | Size (KB) | Content Description |
|------|----------|-----------|---------------------|
| ARNBIO | 0:17 | 2,827 | Arn Anderson biography |
| ARNSHIRT | 0:19 | 3,237 | Arn Anderson merchandise |
| BAMBIO | 0:21 | 3,612 | Bam Bam Bigelow biography |
| BUFFBIO | 0:20 | 3,462 | Buff Bagwell biography |
| CAT | 0:22 | 3,789 | The Cat segment |
| CATBIO | 0:25 | 4,183 | The Cat biography |
| DDPBIO | 0:23 | 3,990 | Diamond Dallas Page biography |
| DDPHAT | 0:19 | 3,285 | DDP promo/merchandise |
| DISCOBIO | 0:17 | 2,874 | Disco Inferno biography |
| FLAIRBIO | 0:23 | 3,911 | Ric Flair biography |
| FVWCYBER | 3:57 | 40,270 | Full match (CyberRing) |
| GOLDBIO | 0:18 | 3,063 | Goldberg biography |
| GOLDHIGH | 1:35 | 16,091 | Goldberg highlights |
| GOLDSHRT | 0:10 | 1,733 | Goldberg merchandise |
| HACKER1 | 1:06 | 11,264 | Hacker storyline segment 1 |
| HACKER2 | 0:41 | 6,990 | Hacker storyline segment 2 |
| HACKER3 | 0:23 | 3,838 | Hacker storyline segment 3 |
| HACKER4 | 0:25 | 4,322 | Hacker storyline segment 4 |
| HACKER5 | 0:21 | 3,555 | Hacker storyline segment 5 |
| HACKER6 | 0:48 | 8,142 | Hacker storyline segment 6 |
| HACKER7 | 0:22 | 3,786 | Hacker storyline segment 7 |
| HACKER8 | 0:13 | 2,280 | Hacker storyline segment 8 |
| HHIGH | 0:48 | 8,149 | Highlights reel |
| HOGANBIO | 0:23 | 3,988 | Hulk Hogan biography |
| HOGANMER | 0:23 | 3,988 | Hulk Hogan merchandise |
| HVGHIGH | 2:55 | 29,762 | Hogan vs Goldberg highlights |
| HVMHIGH | 1:12 | 12,282 | Hogan vs Macho Man highlights |
| INTRO | 0:10 | 1,708 | Disc introduction |
| KIDVID | 1:48 | 18,408 | Kid-focused segment |
| KNOB | 0:19 | 3,255 | Nasty Boys segment |
| KNOBBIO | 0:26 | 4,408 | Nasty Boys biography |
| KNOBMER | 0:19 | 3,255 | Nasty Boys merchandise |
| KNOBS1 | 2:15 | 23,004 | Nasty Boys match 1 |
| KNOBS2 | 2:32 | 25,955 | Nasty Boys match 2 |
| KONNAN | 0:17 | 2,822 | Konnan segment |
| MADUSA | 0:17 | 2,874 | Madusa segment |
| MYSTERIO | 0:30 | 5,116 | Rey Mysterio segment |
| NASHBIO | 0:21 | 3,544 | Kevin Nash biography |
| NASHCHRT | 0:17 | 2,872 | Kevin Nash character profile |
| NASHHAT | 0:17 | 2,872 | Kevin Nash promo |
| NGIRLS | 0:32 | 5,485 | Nitro Girls segment |
| NITRO | 0:45 | 7,568 | WCW Monday Nitro intro |
| NITRO2 | 0:36 | 6,191 | Nitro segment 2 |
| OAKFW | 0:33 | 5,533 | Match footage |
| OAKPH | 0:18 | 3,072 | Match footage |
| OAKTK | 0:28 | 4,712 | Match footage |
| PVHCYBER | 3:47 | 38,659 | Full match (CyberRing) |
| RIGGS1 | 2:29 | 25,318 | Scotty Riggs match 1 |
| RIGGS2 | 2:12 | 22,455 | Scotty Riggs match 2 |
| SJHEEVE | 0:30 | 5,102 | Segment |
| SJPUNISH | 0:30 | 5,093 | Segment |
| SJVEGG | 0:30 | 5,102 | Segment |
| STEINBIO | 0:23 | 3,918 | Scott Steiner biography |
| STINGBIO | 0:17 | 2,870 | Sting biography |
| STINGMER | 0:21 | 3,564 | Sting merchandise |
| STINGPRO | 0:37 | 6,316 | Sting promo |
| SURGE | 0:30 | 5,120 | Surge segment |
| SVNHIGH | 0:37 | 6,332 | Starrcade/PPV highlights |
| SVSHIGH | 1:31 | 15,483 | PPV highlights |
| THUNDER | 0:32 | 5,363 | WCW Thunder intro |
| TVKCYBER | 4:07 | 42,074 | Full match (CyberRing) |

**Total: 61 files, 511.8 MB (decrypted MPEG-1), 51 minutes 20 seconds**

---

## Cryptographic Assessment

### Weaknesses of the PAVENCRYPT Scheme

1. **No initialization vector**: Identical plaintext at the same offset always produces
   identical ciphertext. No per-session or per-packet randomization.

2. **Short repeating key**: Keys are 8-24 bytes cycling over megabytes of data. This
   creates detectable periodicity in the ciphertext when applied to non-uniform plaintext.

3. **Abundant known plaintext**: MPEG-1 PS has fixed sync words every ~2KB (`00 00 01 BA`),
   predictable PES headers, and large blocks of 0xFF padding. Any of these suffice for
   full key recovery.

4. **No key derivation**: Keys are raw ASCII strings used directly as cipher material.
   No hashing, stretching, or expansion.

5. **No integrity protection**: No MAC, HMAC, or checksum. Modified ciphertext decrypts
   to modified plaintext with predictable effect.

6. **Subtraction vs XOR**: While SUB is slightly less common than XOR in toy ciphers,
   it provides no additional security. Both are linear operations trivially invertible
   with known plaintext.

### Why It "Worked" in 1999

The scheme was never intended as strong cryptography. It was DRM - the security model
assumed the decryption keys would remain secret on the server. The cipher's only job
was to prevent casual hexdump-level access to the content. By 1999 standards for
multimedia DRM (CSS for DVDs used a 40-bit key with similar structural weaknesses),
this was typical.

---

## Tools and Methodology

| Tool | Purpose |
|------|---------|
| 7-Zip | ISO extraction |
| unshield (WSL) | InstallShield 5 CAB extraction |
| Python | PE parsing, x86 disassembly, cryptanalysis, batch decryption |
| ffprobe | Format verification |
| ffmpeg | Conversion to H.264/AAC MP4 |

The entire reverse engineering process - from raw ISO to playable video - was completed
through static analysis only. No debugging, no emulation, no server interaction.

---

## Replication Guide

To reproduce this work on the same or similar PAVENCRYPT media:

1. **Extract the ISO** and locate `.PAV` files
2. **Confirm format**: First 10 bytes should be `PAVENCRYPT`
3. **Run `decrypt_pav.py`**: Automatically finds encryption boundaries,
   derives keys via known-plaintext attack, outputs clean MPEG-1 PS
4. **Verify**: `ffprobe output.mpg` should show valid MPEG-1 video+audio
5. **Convert** (optional): `ffmpeg -i output.mpg -c:v libx264 -crf 18 output.mp4`

For non-MPEG underlying formats, the known-plaintext attack still works if you can
identify predictable byte sequences in the encrypted region. The key recovery formula
remains: `key[i] = (ciphertext[i] - known_plaintext[i]) mod 256`.
