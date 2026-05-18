# bit-leak

**Author:** Jordan Lanham
**Event:** TJCTF 2026
**Category:** crypto
**Date:** May 15, 2026
**Read Time:** 6 minutes

---

## Overview

A textbook RSA **LSB parity oracle** challenge: the server happily decrypts arbitrary ciphertexts under a 512-bit RSA key but only reveals the **single least-significant bit** of each plaintext. That one bit per query is enough — repeatedly multiplying the target ciphertext by `2^e mod n` turns each query into a binary-search step on `m`, recovering the full 512-bit plaintext in roughly `log2(n) ≈ 511` queries (well inside the 2100-query budget).

## Challenge Description

> Our security monitor only ever tips us off about the parity of RSA decryptions.
>
> `nc tjc.tf 31001`

**Files provided:** `server.py`
**Endpoints:** `nc tjc.tf 31001`

## Initial Analysis

The server (`server.py`) does the following on connect:

1. Generates two 256-bit primes `p, q`, sets `n = p*q`, `e = 65537`, `d = e^{-1} mod phi(n)`.
2. Reads `flag.txt`, encrypts the flag integer to produce `ciphertext`.
3. Prints `n`, `e`, and `ciphertext`.
4. Enters a loop offering up to **2100** queries. Each query takes an integer `c ∈ [0, n)` and returns `lsb = pow(c, d, n) & 1` — i.e. the parity of the decryption.

This is the canonical setup for the LSB / parity oracle attack on RSA, attributed to Bleichenbacher.

## Solution Approach

### Step 1: Reconnaissance

The protocol is plain-text and stateless: each query is independent and is given the full power of the decryption function — except only its LSB is leaked. There is no padding check, no rate-limit beyond `MAX_QUERIES = 2100`, and `n` has only 512 bits.

### Step 2: Vulnerability Identification

The oracle returns `D(c) & 1`. Two homomorphic-style observations break the system:

- RSA is multiplicatively homomorphic: `D(c1 * c2 mod n) = D(c1) * D(c2) mod n`.
- For any odd `n`, parity of `2m mod n` reveals whether `m < n/2`:
  - If `2m < n`, then `2m mod n == 2m`, an even number — `parity = 0`.
  - If `2m ≥ n`, then `2m mod n == 2m - n`, and since `n` is odd, `2m - n` is odd — `parity = 1`.

So querying the oracle on `c * 2^e mod n` reveals one bit of comparison between `m` and `n/2`. Repeating with `c * 4^e, c * 8^e, ...` halves the interval each time.

### Step 3: Exploitation

Maintain a real interval `[lo, hi)` initialised to `[0, n)`. Iteratively:

1. Compute `c_i = c * (2^i)^e mod n` (in practice multiply the running value by `2^e mod n` each step).
2. Query the oracle on `c_i` to get the parity `p_i` of `(2^i * m) mod n`.
3. If `p_i == 0`: set `hi = (lo + hi) / 2`. If `p_i == 1`: set `lo = (lo + hi) / 2`.
4. After ~`log2(n)` iterations the interval has length < 1 and contains the integer `m`.

Using `fractions.Fraction` keeps the bookkeeping exact, sidestepping the well-known float-rounding pitfall in naïve implementations.

### Step 4: Flag Extraction

After convergence we verify the candidate by checking `pow(cand, e, n) == ciphertext`, then convert the integer to bytes — which spell out `tjctf{parity_isnt_privacy}`.

## Code / Exploit

```python
#!/usr/bin/env python3
"""bit-leak (TJCTF 2026) — RSA LSB parity oracle attack."""
import socket, re
from fractions import Fraction

HOST, PORT = "tjc.tf", 31001

class Conn:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port))
        self.s.settimeout(120)
        self.buf = b""
    def recv_until(self, marker):
        while marker not in self.buf:
            data = self.s.recv(4096)
            if not data: raise EOFError
            self.buf += data
        idx = self.buf.index(marker) + len(marker)
        out = self.buf[:idx]; self.buf = self.buf[idx:]
        return out
    def send(self, b):
        self.s.sendall(b if isinstance(b, bytes) else b.encode())

def main():
    c = Conn(HOST, PORT)
    banner = c.recv_until(b"parity queries.").decode()
    n  = int(re.search(r"n = (\d+)", banner).group(1))
    e  = int(re.search(r"e = (\d+)", banner).group(1))
    ct = int(re.search(r"ciphertext = (\d+)", banner).group(1))

    lo, hi   = Fraction(0), Fraction(n)
    mult     = pow(2, e, n)
    c_cur    = ct

    for _ in range(n.bit_length() + 4):
        c_cur = (c_cur * mult) % n
        c.recv_until(b"> ");          c.send(b"1\n")
        c.recv_until(b"ciphertext = "); c.send(f"{c_cur}\n".encode())
        line = c.recv_until(b"\n").decode()
        parity = int(re.search(r"lsb = ([01])", line).group(1))

        mid = (lo + hi) / 2
        if parity == 0: hi = mid
        else:           lo = mid
        if hi - lo < 1: break

    for k in range(-5, 6):
        for base in (lo, hi):
            cand = int(base) + k
            if 0 < cand < n and pow(cand, e, n) == ct:
                bl = (cand.bit_length() + 7) // 8
                print("FLAG:", cand.to_bytes(bl, "big").decode())
                return

main()
```

Output (last few lines):

```
[507] parity=0  width=7.00
[508] parity=0  width=3.50
[509] parity=1  width=1.75
[510] parity=0  width=0.87
[+] Recovered m = 187072624539866400004961598762110639072614111000177936087349629
[+] Flag: b'tjctf{parity_isnt_privacy}'
```

## Technical Details

- **Vulnerability class:** Side-channel / partial-information oracle on RSA decryption.
- **Encryption / encoding:** Textbook RSA — 512-bit modulus, `e = 65537`, no padding.
- **Protocol:** Line-based oracle: send ciphertext, get 1-bit parity response.
- **Key trick:** Multiply by `2^e mod n` per round so the oracle answers parity of `(2^i · m) mod n`, which is exactly the i-th bit of a binary search comparison `m` vs `n/2`.

## Key Insights

- The lesson is the same as Bleichenbacher 1998: **any** decryption side channel — even a single bit — is a full decryption oracle when RSA has no padding integrity check.
- Use exact rationals (`fractions.Fraction`) for the interval; popular older write-ups using floats can lose the last byte to rounding.
- `n.bit_length()` queries are sufficient. With 2100 queries available, there is room for sanity-check rounds and small overshoot.
- Defence in depth: never expose decryption results, even partial; use authenticated padding (OAEP) or hybrid schemes that fail closed before any plaintext side-channel can leak.

## The Flag

```
tjctf{parity_isnt_privacy}
```

## Resources

- [Bleichenbacher-style LSB Oracle on RSA — Dan Boneh, Stanford CS 255 notes](https://crypto.stanford.edu/~dabo/cs255/lectures/PKCS-attack.pdf)
- [CryptoHack — RSA Parity Oracle challenge](https://cryptohack.org/challenges/rsa/)
- ["Twenty Years of Attacks on the RSA Cryptosystem" — Dan Boneh, AMS Notices 1999](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf)
