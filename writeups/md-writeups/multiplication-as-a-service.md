# multiplication-as-a-service

**Author:** Jordan Lanham
**Event:** TJCTF 2026
**Category:** crypto
**Date:** May 15, 2026
**Read Time:** 8 minutes

---

## Overview

An **Invalid Curve Attack** against a hand-rolled elliptic-curve scalar-multiplication "service". The server multiplies any user-supplied point by a secret scalar `d` (the flag-as-integer) on the curve `y^2 = x^3 + 2x + 3 mod 10007` — but it never checks that the point actually lies on that curve. Because the short-Weierstrass addition formulas don't reference `B`, any point we send is faithfully multiplied on whatever curve `y^2 = x^3 + 2x + B'` it does live on. By cycling through `B'` values we find auxiliary curves whose groups contain points of small prime order `ell`, learn `d mod ell` from each, and **CRT** the residues back into the full secret. The Latin epigraph — *Mendacem oportet esse memorem*, "a liar must have a good memory" — is the hint: the server lies to itself about which curve it's on, and we exploit its forgetfulness.

## Challenge Description

> Mendacem oportet esse memorem.  (Latin: "A liar must have a good memory")
>
> `nc tjc.tf 31313`

**Files provided:** `server.py`
**Endpoints:** `nc tjc.tf 31313`

## Initial Analysis

`server.py` reads `flag.txt`, interprets the bytes as a big-endian integer `secret_d`, and then enters a loop:

- Prints the "official" curve parameters `A=2, B=3, p=10007`.
- Accepts a user-supplied `(x, y)` pair (read mod p).
- Computes `Q = d * P` using its own implementation of `point_add` / `scalar_mul`.
- Prints `Q`.

Three observations leap out immediately:

1. **`p = 10007` is tiny.** No real ECC system would use a 14-bit prime.
2. **There is no on-curve check.** Whatever `(x, y)` we send is just plugged into the addition formulas.
3. The addition formula `s = (3x1^2 + A) / (2y1)` for doubling and `s = (y2 - y1) / (x2 - x1)` for addition uses only `A`. **`B` never appears** in the math.

That third fact is what makes the attack possible.

## Solution Approach

### Step 1: Reconnaissance

Counts of points on the official curve E: |E(F_p)| factors as 9933 = 3 · 7 · 11 · 43. Nice small factors, but only ~13 bits' worth of information from this single curve — not enough to recover a flag of any reasonable length. We need *more* curves.

### Step 2: Vulnerability Identification — Invalid Curve Attack

Because `B` is absent from the addition formulas, any point `(x, y)` lies on **some** twist `E_{B'} : y^2 = x^3 + 2x + B' mod p`, where `B' = y^2 - x^3 - 2x mod p`. The server's scalar multiplication is consistent on that curve; it just thinks it's on `E_3`. So we can:

- Pick any `B' ∈ F_p`.
- Compute `|E_{B'}(F_p)|` and factor it.
- Pick a small prime `ell` dividing that order and a point `P_ell` of exact order `ell` on `E_{B'}`.
- Send `P_ell`. The server returns `Q = d · P_ell` (still on `E_{B'}`).
- Brute-force / BSGS to find `k ∈ [0, ell)` with `k · P_ell == Q`. That `k` is `d mod ell`.
- Repeat with enough distinct primes `ell_1, ell_2, ...` so that `Π ell_i ≥ d` (in bits), then CRT.

### Step 3: Exploitation

Offline (Sage) I enumerated `B' ∈ [1, p)`, computed each `|E_{B'}|`, and recorded the smallest prime factors. I greedily collected one prime per `ell`, stopping once the product covered 400 bits. Fifty primes did the trick, ranging from `ell = 3` to `ell = 10091`, with total coverage `~409 bits` — comfortable margin over the actual flag length of 263 bits.

For each `(ell, B', P_ell)` triple I:

1. Connected to the server.
2. Sent `x, y` of `P_ell`.
3. Parsed `Q = qx qy` (or `Q = inf` meaning `ell | d`).
4. Ran BSGS in `O(sqrt(ell))` time to recover `k = d mod ell`.

All discrete logs took < 1 second each because the largest `ell` is only ~10k.

### Step 4: Flag Extraction

Chinese Remainder Theorem on the 50 `(k_i, ell_i)` pairs yields `d` modulo `M = Π ell_i`. Since `M.bit_length() = 409` exceeds the flag's bit length (263), `d mod M = d`. Convert to bytes: `tjctf{per_mendacium_ad_veritatem}`. Fittingly, the flag itself reads *"through a lie, to the truth."*

## Code / Exploit

The attack runs in two stages: an offline Sage planner to enumerate curves, then a runtime Python exploit using a small pure-Python EC implementation.

**Stage 1 — `sol_mas_plan.sage`** (Sage; produces `mas_curves.json`):

```python
p = 10007
A = 2
F = GF(p)
collected = {}     # ell -> (B', order, x, y)
target_bits = 400

for B in range(1, p):
    try:    E = EllipticCurve(F, [A, B])
    except: continue
    order = E.order()
    for (ell, _) in factor(order):
        ell = int(ell)
        if ell < 3 or ell > 200000 or ell in collected: continue
        for _ in range(50):
            P = E.random_point()
            if P.is_zero(): continue
            R = (order // ell) * P
            if not R.is_zero() and (ell * R).is_zero():
                collected[ell] = (B, int(order), int(R[0]), int(R[1]))
                break
    if prod(collected).bit_length() >= target_bits: break
```

**Stage 2 — `sol_multiplication-as-a-service.py`** (network exploit, pure Python):

```python
#!/usr/bin/env python3
"""multiplication-as-a-service (TJCTF 2026) — Invalid Curve Attack."""
import json, re, socket, math
from functools import reduce

P_MOD, A = 10007, 2

def inv(x):  return pow(x % P_MOD, -1, P_MOD)
def ec_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1,y1 = P1; x2,y2 = P2
    if x1 == x2 and (y1 + y2) % P_MOD == 0: return None
    if x1 == x2 and y1 == y2:
        s = (3*x1*x1 + A) * inv(2*y1)
    else:
        s = (y2 - y1) * inv(x2 - x1)
    s %= P_MOD
    x3 = (s*s - x1 - x2) % P_MOD
    y3 = (s*(x1 - x3) - y1) % P_MOD
    return (x3, y3)
def ec_mul(k, P1):
    R, Q = None, P1
    while k:
        if k & 1: R = ec_add(R, Q)
        Q = ec_add(Q, Q); k >>= 1
    return R
def ec_neg(P): return None if P is None else (P[0], (-P[1]) % P_MOD)

def bsgs(P1, Q, ell):
    m = int(math.isqrt(ell)) + 1
    table, R = {}, None
    for j in range(m):
        table.setdefault(R, j); R = ec_add(R, P1)
    neg_mP, cur = ec_neg(ec_mul(m, P1)), Q
    for i in range(m + 1):
        if cur in table:
            k = (i*m + table[cur]) % ell
            if ec_mul(k, P1) == Q: return k
        cur = ec_add(cur, neg_mP)
    return None

def crt(rs, ms):
    M = reduce(lambda a,b: a*b, ms, 1)
    return sum(r * (M//m) * pow(M//m, -1, m) for r, m in zip(rs, ms)) % M, M

class Conn:
    def __init__(self, h, p):
        self.s = socket.create_connection((h, p)); self.s.settimeout(60); self.buf = b""
    def recv_until(self, m):
        while m not in self.buf:
            d = self.s.recv(4096)
            if not d: raise EOFError
            self.buf += d
        i = self.buf.index(m) + len(m); o = self.buf[:i]; self.buf = self.buf[i:]; return o
    def send(self, d): self.s.sendall(d if isinstance(d, bytes) else d.encode())
    def query(self, x, y):
        self.recv_until(b"x = "); self.send(f"{x}\n")
        self.recv_until(b"y = "); self.send(f"{y}\n")
        line = self.recv_until(b"\n").decode()
        body = re.search(r"Q = (inf|\d+ \d+)", line).group(1)
        return None if body == "inf" else tuple(map(int, body.split()))

curves = json.load(open("mas_curves.json"))
items  = sorted((int(e), v["B"], v["x"], v["y"]) for e, v in curves.items())

c = Conn("tjc.tf", 31313); c.recv_until(b"x = ")
residues, moduli, first = [], [], True
for (ell, B, x, y) in items:
    if first:
        c.send(f"{x}\n"); c.recv_until(b"y = "); c.send(f"{y}\n")
        body = re.search(r"Q = (inf|\d+ \d+)", c.recv_until(b"\n").decode()).group(1)
        Q = None if body == "inf" else tuple(map(int, body.split()))
        first = False
    else:
        Q = c.query(x, y)
    k = 0 if Q is None else bsgs((x, y), Q, ell)
    residues.append(k); moduli.append(ell)

d, M = crt(residues, moduli)
bl = (d.bit_length() + 7) // 8
print("FLAG:", d.to_bytes(bl, "big").decode())
```

Output:

```
[+] 50 prime orders prepared
  ell=     3  d≡1 (mod 3)
  ell=     5  d≡0 (mod 5)
  ...
  ell= 10091  d≡1208 (mod 10091)   covered=409 bits
[+] CRT: d.bit_length()=263
[+] Flag (k=0): b'tjctf{per_mendacium_ad_veritatem}'
```

## Technical Details

- **Vulnerability class:** Invalid Curve Attack (also called twist attack) against an unauthenticated EC scalar-mul oracle.
- **Encryption / encoding:** Short-Weierstrass elliptic curve `y^2 = x^3 + Ax + B mod p`, with `A=2, p=10007`, `B` unused in formulas.
- **Protocol:** Plaintext TCP — server reads `(x, y)`, returns `Q = d · (x, y)`.
- **Key trick:** Since the addition formulas omit `B`, any `(x, y)` is on `E_{B'}` for `B' = y^2 - x^3 - 2x mod p`. Pick `B'` whose group order has a small prime factor `ell`, generate a point of order `ell`, query the oracle, BSGS to recover `d mod ell`, CRT.

## Key Insights

- ECC implementations **must** verify that every input point satisfies the curve equation. Skipping this single check is catastrophic when the addition formulas are missing the constant term (as they are for short Weierstrass).
- The attack only works because `p` is small enough that group orders can be factored cheaply and BSGS over each `ell` is trivial. Production curves (256+ bit primes) make the same arithmetic infeasible — but the principle still applies on **twists**, hence the importance of using twist-secure curves like Curve25519.
- For low-stakes implementations a quick `assert y*y % p == (x**3 + A*x + B) % p` would have killed this entire bug.
- Latin Easter eggs are a fun classics-nerd touch — *Mendacem oportet esse memorem* (Quintilian) cleanly hints at the server "forgetting" its claimed `B`.

## The Flag

```
tjctf{per_mendacium_ad_veritatem}
```

## Resources

- [Biehl, Meyer, Müller — "Differential Fault Attacks on Elliptic Curve Cryptosystems" (2000)](https://www.iacr.org/archive/crypto2000/18800131/18800131.pdf) — original invalid-curve idea.
- [Antipa, Brown, Menezes, Struik, Vanstone — "Validation of Elliptic Curve Public Keys" (2003)](https://www.iacr.org/archive/pkc2003/25670211/25670211.pdf) — formal treatment of why point validation matters.
- [CryptoHack — Curveball / Invalid Curve set](https://cryptohack.org/challenges/ecc/) — interactive practice with these primitives.
- [Sage `EllipticCurve` docs](https://doc.sagemath.org/html/en/reference/curves/sage/schemes/elliptic_curves/ell_finite_field.html)
