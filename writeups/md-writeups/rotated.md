# rotated

**Author:** Jordan Lanham
**Event:** TJCTF 2026
**Category:** rev
**Date:** May 16, 2026
**Read Time:** 6 minutes

---

## Overview

A 6480-byte "data" blob whose every byte has been **shifted up by `+0x1d`** (modulo 256). The challenge name "rotated" was a red herring pointing at bit rotations; the real transform is an **additive Caesar shift over the whole byte space (mod 256)**. Subtracting `0x1d` from each byte reveals a UPX-packed x86-64 ELF. Unpacking with `upx -d` yields a tiny Linux binary that `write()`s a bash `script.sh` containing a heavily obfuscated one-liner. Cleaning the obfuscation leaves `printf '<base64>' | base64 -d | gunzip -c`, and the gunzipped payload contains `echo "Looking for a flag?" # <base64-flag>`. Decoding that comment yields the flag.

## Challenge Description

> this file isn't making any sense to me. can you discover what it means?
> hint: look at the title
> hint 2: consider each byte separately

**Files provided:** `chall` (6480 bytes, `file` reports it as `data`)
**Endpoints:** —

## Initial Analysis

`xxd` on `chall`:

```
00000000: 9c62 6963 1f1e 1e1d 1d1d 1d1d 1d1d 1d1d
00000010: 201d 5b1d 1e1d 1d1d e575 1d1d 1d1d 1d1d
...
00000110: 9c62 6963 1f1e 1e1d 201d 5b1d 2aad 2d2c
```

Frequency analysis: byte `0x1d` appears 644 times (~10%), followed by `0x1c`, `0x65`, `0x24`, `0x2c`, `0x1e`, `0x20`, `0x1f`. There are also two identical 7-byte headers (`9c 62 69 63 1f 1e 1e`) at offsets `0x000` and `0x110` — a strong UPX tell (UPX prepends a small custom header twice in the packed binary).

The title "rotated" and hint "consider each byte separately" strongly suggest a per-byte transform. The earlier (failed) attempt brute-forced bit rotations (rol/ror by every reasonable key) — none of them produced printable text.

## Solution Approach

### Step 1: Reconnaissance — Spot the Caesar Shift

The dominant byte `0x1d` is suspicious. `0x1d - 0x1d = 0x00`, and `0x00` is the most common byte in nearly every ELF (large stretches of zero padding). That is the giveaway:

```python
out = bytes((b - 0x1d) % 256 for b in data)
out[:4]  # b'\x7fELF'
```

Subtracting `0x1d` from every byte produces a perfect ELF magic `7f 45 4c 46` at offset 0. The "rotated" in the title is **rotation in the additive ring Z/256Z**, not bit rotation — i.e., `chall[i] = (real[i] + 0x1d) mod 256`. Every byte has been Caesar-shifted by 29.

That also explains the "bic" ASCII teaser at offset 1: `0x62 - 0x1d = 0x45 ('E')`, `0x69 - 0x1d = 0x4c ('L')`, `0x63 - 0x1d = 0x46 ('F')` → "ELF".

### Step 2: Unpack UPX

`file rotated_decoded.elf` →

```
ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), statically linked, no section header
```

`strings` shows `UPX!` near the top and `script.sh`, `#!/bin/bash`, and a base64 string. So this is UPX-packed.

```bash
upx -d files/rotated_decoded.elf -o files/rotated_unpacked.elf
# Unpacked 1 file. 6480 -> 16152 bytes
```

After unpacking: `ELF 64-bit LSB pie executable, dynamically linked, ... not stripped, main present`.

### Step 3: Recover the Embedded Bash Script

`strings` on the unpacked binary reveals an in-memory shell script the program writes to `script.sh`:

```bash
#!/bin/bash
   ${*,} ${@//nj2p#@$\!/^Bis\X}  e\val   "$(      ${*#+*=\`gr4#}  ${*~~}   'p'r\i"n"tf 'H4sIAEDAzmkC/0tNzshXUPLJz8/OzEtXSMsvUkhUSMtJTLdXUlBWSHEvyEpxjzKPzAo0THSzzPY18jL0y7Es8XMJNfY19rJ0Tre1BQCGqZA9QQAAAA=='  ${!*} | ${*%b:d\)} b""'a'''s"e"6"${@^^}"4  -d   ${*}  |  ${*//\`FsXY^F} ${*#0ms7JMci}  \gu${*//.Km\`1B/vmdvatBX}n$'\172''i'p  -c  ${*,,}      )"  ${*%TB.h}
```

This is a classic bash de-obfuscation puzzle. Strip every `${*...}`, `${@...}`, `${!*}` parameter expansion (they all expand to the empty string when the script is run with no arguments), strip the backslash/quote noise inside the words, and the script collapses to:

```bash
eval "$( printf '<base64>' | base64 -d | gunzip -c )"
```

The flag string "**b**4**sh** **d**3**bu**6 **m**4573**r**" matches this exactly — it's a bash-deobfuscation problem.

### Step 4: Decode the Payload

```python
import base64, gzip
b64 = 'H4sIAEDAzmkC/0tNzshXUPLJz8/OzEtXSMsvUkhUSMtJTLdXUlBWSHEvyEpxjzKPzAo0THSzzPY18jL0y7Es8XMJNfY19rJ0Tre1BQCGqZA9QQAAAA=='
inner = gzip.decompress(base64.b64decode(b64))
# b'echo "Looking for a flag?" # dGpjdGZ7YjQ1aF9kM2J1Nl9tNDU3M3J9Cg=='
print(base64.b64decode('dGpjdGZ7YjQ1aF9kM2J1Nl9tNDU3M3J9Cg==').decode())
# tjctf{b45h_d3bu6_m4573r}
```

The `eval` body is `echo "Looking for a flag?" # <base64>` — a bash comment. The flag is hiding **in the comment** of the deobfuscated script, base64-encoded.

## Code / Exploit

```python
#!/usr/bin/env python3
"""TJCTF 2026 - rotated solver."""
import base64, gzip, subprocess, pathlib, re

data = pathlib.Path('files/rotated__chall').read_bytes()

# Step 1: Caesar shift by -0x1d (the title "rotated" = additive rotation in Z/256Z)
shifted = bytes((b - 0x1d) % 256 for b in data)
pathlib.Path('files/rotated_decoded.elf').write_bytes(shifted)
assert shifted[:4] == b'\x7fELF', 'not an ELF after shift'

# Step 2: UPX unpack
subprocess.run(['upx', '-d', 'files/rotated_decoded.elf',
                '-o', 'files/rotated_unpacked.elf'], check=True)

# Step 3: extract the embedded base64 from the binary's strings
unpacked = pathlib.Path('files/rotated_unpacked.elf').read_bytes()
b64 = re.search(rb"H4sI[A-Za-z0-9+/=]{40,}", unpacked).group().decode()

# Step 4: gunzip -> strip 'echo ... # <inner-b64>' -> base64-decode -> flag
inner = gzip.decompress(base64.b64decode(b64)).decode()
flag_b64 = inner.split('# ', 1)[1].strip()
print(base64.b64decode(flag_b64).decode())  # tjctf{b45h_d3bu6_m4573r}
```

## Technical Details

- **Vulnerability class:** Reverse engineering — multi-layer obfuscation (additive cipher -> UPX pack -> bash quote-obfuscation -> base64+gzip -> bash comment).
- **Encryption / encoding:** Per-byte additive shift by `+0x1d` (mod 256). UPX compression. Base64 + gzip. Base64 again on the inner flag.
- **Protocol:** Static file.
- **Key trick:** Recognizing that `0x1d` being the dominant byte (~10%) is the **shifted form of `0x00`** that pads every ELF — diff-from-the-modal-byte instantly reveals the cipher offset. The "rotated" title misdirected toward *bit* rotation; the real operation is *additive* rotation on `Z/256Z`.
- **Why "bic" appeared in plaintext:** `'b','i','c'` = `0x62,0x69,0x63` = `'E','L','F' + 0x1d`. The ELF magic survives as the deceptively-readable string "bic" because each of E/L/F + 29 lands inside printable ASCII.

## Key Insights

- **"Rotated" can mean Caesar-shift, not just bit-rotation.** When a binary file's modal byte is not `0x00` but some small value `k`, try `(b - k) mod 256` first - it's a one-liner and catches the entire class of "file with every byte +k" obfuscations.
- **ASCII-bait inside a binary is a clue, not noise.** `9c bic ...` looked random; in fact "bic" was literally `ELF + 0x1d` displayed by xxd's character column. The same trick can hide other magics in plain sight.
- **UPX has its own giveaways.** Two identical custom headers near each other (here at `0x000` and `0x110`) plus the dominant zero-byte once decoded is enough to predict UPX without even running `strings`.
- **Bash quote-obfuscation always collapses with no-argument expansions.** Once you see `${*,}`, `${@^^}`, `${!*}`, `${*%foo}` peppered through a script you can mentally erase them all - they evaluate to empty when invoked with no positional parameters. What remains is the actual code.
- **Skipping a step costs hours.** The prior attempt assumed bit rotations from the word "rotated" and brute-forced them; the right move was to ask "what byte would be 10% of an unknown file?" The answer (`0x00` -> padding) makes the diff `0x1d` jump out instantly.

## The Flag

```
tjctf{b45h_d3bu6_m4573r}
```

## Resources

- [UPX - the Ultimate Packer for eXecutables](https://upx.github.io/)
- [Bash parameter expansion reference (GNU Bash manual)](https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html)
- [ELF format - Wikipedia](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
- [List of file signatures - Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)
