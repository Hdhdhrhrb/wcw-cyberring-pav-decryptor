# Primary Sources and Historical Documentation

## SEC Filing: UIT-WCW License Agreement (1999)

The encryption technology we reverse engineered 25 years later is documented in a primary source: the original license agreement filed with the Securities and Exchange Commission.

### Document Details

**Source:** SEC Filing, Exhibit 10.48
**Document:** License Agreement between United Internet Technologies, Inc. and World Championship Wrestling, Inc.
**Date Executed:** February 23, 1999
**Date Filed:** April 15, 1999
**Parties:**
- **Licensor:** United Internet Technologies, Inc. (Delaware corporation)
- **Licensee:** World Championship Wrestling, Inc. (Georgia corporation)

**Contract Terms:**
- License fee: $200,000 USD
- Term: 3 years (February 23, 1999 to ~February 2002)
- Territory: Worldwide
- IP ownership: All technology owned by UIT

**Archival URLs:**
- Law Insider: https://www.lawinsider.com/contracts/2gp1TeImAUA
- SEC EDGAR: https://www.sec.gov/Archives/edgar/data/59684/000094420999000582/0000944209-99-000582-index.htm

---

## Key Excerpts

### Exhibit A, Section 3: Server Side Key Generator Program (SSKGP)

> "The application will have the capability to create security keys based on time. Therefore, the end user will only be able to utilize the video while they are connected to the Internet and only for specific amounts of time."

**Technical Significance:**

This directly describes the time-based key generation system we reverse engineered. The "Server Side Key Generator Program" created unique decryption keys server-side. This explains:

- Why offline playback was impossible after server shutdown
- Why no keys exist on the physical disc
- Why the DRM relied entirely on network connectivity
- The time-based security model (keys expired after specific durations)

Our technical analysis in 2026 independently rediscovered this server-side key generation architecture through static binary analysis of `PavSource.ax`.

### Exhibit A, Section 5: ULI Video Player

> "This application enables the end user to open and play DIVO and PAV files within the browser while connected to the website server (subject to any limitations programmed by the website operator)."

**Technical Significance:**

This confirms:

- PAV format was part of a broader UIT video ecosystem including DIVO and PAV formats
- Playback required active server connection ("while connected to the website server")
- Server-side restrictions controlled playback ("limitations programmed by the website operator")
- Browser integration operated via DirectShow filters (`npUliPlugin.dll` and `PavSource.ax`)

The contract explicitly states that server connectivity was a requirement, not a bug. When UIT's infrastructure went offline around 2000, this was not a service disruption. It was permanent obsolescence by design.

---

## Historical Context

### The Business Deal

World Championship Wrestling paid United Internet Technologies $200,000 in 1999 for a 3-year license to use:

1. **Server Side Key Generator Program (SSKGP)** - Time-based encryption key generation
2. **ULI Video Player** - DirectShow-based playback application
3. **Encoder software** - PAVENCRYPT format creation tools
4. **Support and maintenance** - During the 3-year term

The agreement granted WCW worldwide rights but retained all intellectual property with UIT. WCW could not sublicense, reverse engineer, or distribute the underlying technology.

### The Technology Stack (as described in Exhibit A)

The licensed software suite included:

| Component | Description (from contract) |
|-----------|----------------------------|
| Server Side Key Generator (SSKGP) | Time-based key generation system |
| ULI Video Player | DirectShow filter-based player for DIVO/PAV |
| Encoder | Creates PAVENCRYPT format files |
| Browser Plugin | Netscape/IE integration |
| Documentation | Technical specifications (now lost) |

### What Happened

**1999:** WCW licenses technology and produces the WCW Internet Powerdisk CD-ROM
**~2000:** United Internet Technologies infrastructure goes offline
**2001:** WCW acquired by WWE; assets transferred
**2002:** License term expires (moot point, as server already offline)
**1999-2024:** Content remains encrypted and inaccessible for 25 years
**2024-2025:** Encryption broken via cryptanalysis; content recovered

---

## Technical Validation

### Our Reverse Engineering Findings (2024-2025)

Through static binary analysis of `PavSource.ax` (24 KB DirectShow filter), we discovered:

1. **Repeating-key subtraction cipher** using 8-24 byte keys
2. **Per-file key strings** passed via `"NUMBER1-NUMBER2-KEYSTRING"` format
3. **No local key storage**: keys were network-retrieved
4. **Server dependency**: `"Decryption key not found in the server database"` error when offline

### Contract Validation (1999)

The SEC filing independently confirms:

1. **"Security keys based on time"**: matches our discovery of time-based key generation
2. **Server-side key generation**: explains why keys don't exist on disc
3. **Network-required playback**: explains permanent failure after server shutdown
4. **UIT ownership of encryption IP**: explains why no documentation survived WCW's bankruptcy

Our technical findings from 2024-2025 exactly match the system architecture described in legal documentation from 1999, despite having zero access to original UIT specifications.

---

## The Irony

World Championship Wrestling paid $200,000 for encryption technology in 1999 that:

- Successfully protected content for 25 years
- Became permanently inaccessible when the vendor (UIT) disappeared
- Was ultimately broken using information disclosed in their own SEC filing
- Described "security keys based on time," the exact vulnerability we exploited via known-plaintext attack on MPEG-1 padding

The contract specified that server-side key generation would enforce "specific amounts of time" for playback. In practice, it enforced permanent inaccessibility.

---

## Document Preservation

This SEC filing is archived in multiple locations:

1. **SEC EDGAR** (official U.S. government archive)
2. **Law Insider** (legal contract database)
3. **This repository** (for technical/historical reference)

The filing is public record under securities disclosure requirements. It represents the only known surviving primary source documentation of the PAVENCRYPT/SSKGP technology stack.

---

## Legal and Ethical Notes

### Copyright Status

The video content is copyrighted material:
- Originally produced by World Championship Wrestling (Turner Broadcasting)
- Intellectual property transferred to WWE following WCW acquisition (2001)
- Content archived under fair use for historical preservation

### Encryption Technology

The encryption system (PAVENCRYPT):
- Intellectual property owned by United Internet Technologies, Inc. (defunct)
- 3-year license to WCW expired around 2002
- No active trademark, patent, or copyright claims identified
- Technology reverse engineered via legal cryptanalysis in 2024-2025

### This Work

Our reverse engineering and recovery effort:
- Uses publicly available SEC filings (primary sources)
- Analyzes obsolete DRM via standard cryptanalysis techniques
- Recovers abandoned media with clear historical/archival value
- Published under MIT license for educational and preservation purposes

---

## Citation

**For academic or archival reference:**

```
United Internet Technologies, Inc. and World Championship Wrestling, Inc.
"License Agreement" (Exhibit 10.48)
Filed: April 15, 1999
SEC EDGAR Accession: 0000944209-99-000582
Available: https://www.sec.gov/Archives/edgar/data/59684/000094420999000582/
```

**For technical reference:**

```
UIT Server Side Key Generator Program (SSKGP)
Described in: SEC Exhibit 10.48, Appendix A, Section 3
"Security keys based on time": time-based encryption key generation system
Implementation reverse engineered 2024-2025 via static analysis of PavSource.ax
```

---

*This document provides historical and legal context for the WCW CyberRing PAV decryption project. The primary source material validates our independent technical findings from 25 years after the technology's creation.*
