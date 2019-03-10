# Writeup for namespaces, 35C3 CTF, 2 solves

> Here is another linux user namespaces challenge by popular demand.
>
> For security reasons, this sandbox needs to run as root. If you can break out of the sandbox, there's a flag in /, but even then you might not be able to read it :).
>
> The files are here: <https://35c3ctf.ccc.ac/uploads/namespaces-a4b1ac039830f7c430660bc155dd2099.tar> Service running at: `nc 35.246.140.24 1`
>
> **Hints:**
>
> - You'll need to create your own user namespace for the intended solution.

## TL;DR

- The challenge binary doesn't join our `net` namespace when creating a new process

- Connect two sandboxes via a unix socket and transfer a file descriptor of one sandbox's root directory to the other

- Use that file descriptor to access files outside of the chroot

- During sandbox creation, replace the chroot directory with a symbolic link to `/` to obtain an unchrooted process

- Create new namespaces to gain capabilities

- Fake a `/proc/$pid/ns` directory using bind mounts to take control of a joining process before it drops its privileges

- Inject shellcode into that process and read the flag

## Overview

`namespaces` was a challenge in the 35C3 CTF. I didn't look at this challenge during the CTF, because I attended the conference, but decided to look at it a couple of weeks later. So, let's jump right in:

We are provided with a `namespaces` binary and a Dockerfile. To get an overview about the setup we're dealing with, let's look at the Dockerfile first:

```dockerfile
FROM tsuro/nsjail
COPY challenge/namespaces /home/user/chal
CMD /bin/sh -c "/usr/bin/setup_cgroups.sh && cp /flag /tmp/flag && chmod 400 /tmp/flag && chown user /tmp/flag && su user -c '/usr/bin/nsjail -Ml --port 1337 --chroot / -R /tmp/flag:/flag -T /tmp --proc_rw -U 0:1000:1 -U 1:100000:1 -G 0:1000:1 -G 1:100000:1 --keep_caps --cgroup_mem_max 209715200 --cgroup_pids_max 100 --cgroup_cpu_ms_per_sec 100 --rlimit_as max --rlimit_cpu max --rlimit_nofile max --rlimit_nproc max -- /usr/bin/stdbuf -i0 -o0 -e0 /usr/bin/maybe_pow.sh /home/user/chal'"
```

The challenge binary is run inside an nsjail, which in turn runs inside a Docker container.

The challenge is copied to `/home/user/chal` inside the Docker container and the flag is found in two places: `/flag` with unknown owner and permissions and `/tmp/flag` with owner `user` and permissions `r--------`.
The container then runs the nsjail as user `user`.

The nsjail is passed quite a few options, but the `cgroup` and `rlimit`-related options are only used to limit the amount of resources the challenge binary may consume and are not further relevant to us.
The other options set up the environment the challenge binary will run in:

- `-Ml --port 1337`: Listen on port 1337 and start the challenge when someone connects

- `--chroot /`: Don't chroot

- `-R /tmp/flag:/flag`: Bind mount `/tmp/flag` over `/flag`. This shadows the original `/flag`

- `-T /tmp`: Mount a tmpfs over `/tmp`. This shadows `/tmp/flag`

- `--proc_rw`: `/proc` remains writeable, so that the challenge binary can create its own namespaces and uid/gid mappings

- `-U 0:1000:1 -U 1:100000:1 -G 0:1000:1 -G 1:100000:1`: Map user and group IDs inside the nsjail. `0` inside is `1000` (`user`) outside and `1` inside is `100000` outside

- `--keep_caps`: The challenge binary is run with full capabilities inside the nsjail. Again, that's needed for the challenge binary to create namespaces

Finally, in the nsjail, the challenge binary is run. Its interface presents two options to the user:

- `Start sandbox`: Create a new sandbox and run an executable provided by us inside it, as the init process

- `Run ELF`: Run an executable inside an already existing sandbox

This triple-layered setup may look intimidating at first, but for our purposes we can ignore the outer two layers (Docker and nsjail) and imagine the challenge binary running as root outside of a container (that's actually how I ran the binary while developing the exploit).

Our goal is to get code execution in the context of the challenge process, i.e. escape the sandbox and escalate to root inside the nsjail (which is actually the user `user` when viewed from outside the nsjail).

## Background: Linux Namespaces

In order to solve this challenge, we need some background knowledge about namespaces.
On a high level, Linux namespaces allow the isolation of access to certain system resources. To processes inside the namespace it appears that they have their own instance of the resource and changes to the resource are only visible to processes inside the same namespace.
There are seven different types of namespaces, named after the resource they provide isolation for:

- `cgroup` namespaces for Linux cgroups

- `ipc` namespaces for inter process communication

- `net` namespaces for network interfaces

- `mnt` namespaces for mount points

- `pid` namespaces for process IDs

- `user` namespaces for user and group IDs

- `uts` namespaces for the hostname

In this challenge we will be dealing with four of those:

- Network namespaces. They separate the interfaces used by sockets (internet sockets as well as other types like UNIX domain sockets)

- Mount namespaces. When a new mount namespace is created, the mount points of the parent mount namespace are copied

- PID namespaces. Which PID namespace a process belongs to is fixed at process creation and cannot be changed afterwards. Only the PID namespace of future children can be changed

- User namespaces. Every namespace has an associated user namespace, which is used when checking if a user has capabilities for privileged actions. When a process creates or joins a user namespace, it gains all capabilities in that namespace

Now that we have the necessary background knowledge, let's move on to analyzing the challenge binary.

## Reversing the Binary

Looking at the binary, the first thing we notice it that the sandboxes' root directories are stored in `/tmp/chroots/`.
The `/tmp/chroots/` directory as well as its subdirectories are chmodded to mode `777` after creation -- that's way too permissive and will come in handy later in the exploit.

When we create a new sandbox, the challenge binary does the following:

- Fork off a new process with all new namespaces

  - The parent returns to the main loop, while the child continues

- Map user ID 1 of the parent user namespace to user ID 1 in the new user namespace

- Load the user-provided init binary into a memfd

- Create the directory `/tmp/chroots/$idx`, where `$idx` is the number of sandboxes already created

- Chroot into the directory created above

- Change user and group IDs to `1`

- Execute the init binary from the memfd

When we run an executable inside an already existing sandbox, the challenge binary does the following:

- Load the user-provided binary into a memfd

- Fork off a new process. The parent returns to the main loop

- Use `/proc/$pid/ns/$type` to enter the namespaces of the sandbox's init process

  - `$pid` is the PID of the sandbox's init process

  - `$type` is iterated to join, in order, its `user`, `mnt`, `pid`, `uts`, `ipc` and `cgroup` namespaces

  - After the `pid` namespaces was joined, the process forks, with the parent exiting, to really join the `pid` namespace

- Chroot into `/tmp/chroots/$idx`

- Set user and group IDs to `1`

- Execute the binary from the memfd

Did you already notice the bug? It occurs when joining the sandboxes namespaces.

The process joins all namespaces but the `net` namespace, which means all processes have access to the hosts network interfaces.

## Escaping the Chroot

Now we know that processes in different sandboxes will share their network namespace, but how can we use that to escape the chroot?
If we could open a connection between two processes in different sandboxes and send a file descriptor of one sandbox's root directory over to the other sandbox, we could access files outside the chroot!

Unix domain sockets allow us to do exactly that. The sandboxes don't share any part of the file system, so we cannot create a socket file and open it in both sandboxes. However, we can bind a unix domain socket to a name in the abstract socket namespace.
Not to be confused with the Linux namespaces discussed above, the abstract socket namespace allows us to bind a socket to a name not visible on the file system.

The last thing that's missing now is being able to transfer file descriptors over this socket connection. But we are lucky again: sending file descriptors is possible with ancillary messages of type `SCM_RIGHTS`.
Now we can send a file descriptor of the first sandbox's root directory to the second sandbox and use it to access files outside of the chroot directories. However, we still cannot read `/flag`, because it is only readable by user ID `0` and we are user `1`.

## Really Escaping the Chroot

In order to have any chance at escalating our privileges, we first have to really escape the chroot. Currently, we can access the filesystem outside of the chroot, but our processes remain chrooted.

Do you remember the lax permissions of the `/tmp/chroots/` directory we noticed earlier? We can use them now to delete one of the sandbox directories and replace it with a symbolic link to `/`.
That way, when we run a new process inside the sandbox, the challenge binary will chroot it to `/tmp/chroots/$idx`, which now points to `/`, and we will have an unchrooted process.
With this technique, the init process of the sandbox will remain chrooted, but all other processes joined after we replaced the chroot directory will not be chrooted.

## Gaining Capabilities

Chrooted processes are not allowed to create a new user namespace, because they could then escape the chroot, and other types of namespaces may only be created by processes which have the `CAP_SYS_ADMIN` capability inside their user namespace.
So, now that we have escaped the chroot, we can create new namespaces and thus gain all capabilities inside them.

With this newly acquired capabilities we could try to somehow access the original `/flag` file, the one that was shadowed by the bind mount performed by the nsjail. We don't know it's permissions, but maybe it is world-readable.
So, how would we access the file shadowed by a bind mount? We have the necessary capabilities to create our own bind mounts. Bind mounts don't duplicate mount points by default and thus may allow us to "look behind" those mount points and access files shadowed by them.
If we bind mounted `/` to `/tmp/foo` we could access the original filesystem under `/tmp/foo` and the original flag file under `/tmp/foo/flag`. However, if we actually try this, the bind mount fails with the error `EINVAL`. Looking this error up on the `mount(2)` manpage reveals:

```
EINVAL In an unprivileged mount namespace (i.e., a mount namespace owned by a user namespace that was  created  by
       an  unprivileged  user),  a bind mount operation (MS_BIND) was attempted without specifying (MS_REC), which
       would have revealed the filesystem tree underneath one of the submounts of the directory being bound.
```

As it turns out, what we were trying to do is prohibited by the kernel!

Unfortunately, we've kind of hit a dead end, there's nothing interesting left that we can do from here. Instead, we now go back to the step of escaping the chroot, but now we want to obtain an unchrooted init process.

We will again be replacing the chroot directory with a symbolic link to `/`, but now we do it during sandbox creation, after the challenge binary calls `chmod()` and before it calls `chroot()`.
This might require precise timing on our end, but as it turns out in practice we hit the right timing when we simply remove and link the directory as soon as it is visible to us.

## Escalating to Root

Now that we have obtained an unchrooted init process, our goal is to escalate to the root user by gaining code execution in the context of the challenge binary's process. We will be doing that by `ptrace`ing a process joining our sandbox before it is able to drop its privileges.
To be able to `ptrace` the process, it has to be in the same `pid` namespace as us and we have to have the `CAP_SYS_PTRACE` capability.

We can gain all the capabilities in the same way we did before, by creating new namespaces. But, to join the new `pid` namespace, we have to fork off a new process. The new "victim" process will then still join the namespaces of the init process, not those of init's child.

However, there is another subtle flaw in the way the victim joins our namespaces. It joins them one by one, referenced by the path `/proc/$pid/ns/$type`.
Because of that, as soon as it joins our mount namespace, we control its entire view on the filesystem and thus also what files it sees at that path!

To exploit this, we bind mount a directory under `/tmp` to `/proc/$pid/ns` to be able to create arbitrary files inside that directory. Then we replace init's `pid` namespace with a symbolic link to the `pid` namespace of init's child.
Additionaly, we make init's `uts` namespace a pipe, so the victim process blocks when opening it. This way we have enough time to attach to the victim without having to race it.

After having created the fake `/proc/$pid/ns` directory, our attacking process waits for the victim process to appear in its `pid` namespace, attaches to it and injects some shellcode.
Because the victim had no chance to drop it's privileges after joining our `pid` namespace (it was blocked opening the pipe), it still runs as the root user, and so does our shellcode. The shellcode then simply cats the flag.

## Complete Exploit

My exploit consists of two main parts, one written in C and one written in Python.

The C part implements four different binaries run on the target server:

- `sleep`: Do nothing, needed as init process

- `sendfd`: Open a unix domain socket in the abstract socket namespace and send a file descriptor to the sandbox's root directory through it

- `recvfd`: Receive the file descriptor and race sandbox creation to obtain an unchrooted init process

- `escalate`: Gain capabilities and set up a fake `/proc/$pid/ns` directory to gain control of a joining process before it drops its privileges. Then read the flag

The Python part is responsible for compiling the four binaries and for starting the different exploit stages on the target server at the right time.

Below follows the output of my exploit. See the source code for details on the implementation.

## Conclusion

This was a really fun and interesting challenge and I learned a lot about low-level Linux programming on the way, thanks to the author [@_tsuro](https://twitter.com/_tsuro).
I hope you enjoyed this writeup as much as I enjoyed the challenge. If you have any questions, feel free to hit me up on Twitter [@LevitatingLion](https://twitter.com/LevitatingLion).

## Files

- [Challenge: Dockerfile](Dockerfile)

- [Challenge: Binary](namespaces)

- [Exploit: C part](binaries.c)

- [Exploit: Python part](exploit.py)

Exploit output:

```
[+] Opening connection to localhost on port 1337: Done

[+] Starting sandbox: sleep
[*] setgroups deny
[*] writing uid_map
[*] writing gid_map
[*] Creating chroot dir "/tmp/chroots/0"
[*] Chrooting to "/tmp/chroots/0"
[*] changing group ids
[*] changing user ids
[*] starting init
[sleep]  Started sleep

[+] Starting sandbox: sleep
[*] setgroups deny
[*] writing uid_map
[*] writing gid_map
[*] Creating chroot dir "/tmp/chroots/1"
[*] Chrooting to "/tmp/chroots/1"
[*] changing group ids
[*] changing user ids
[*] starting init
[sleep]  Started sleep

[+] Running in sandbox #0: sendfd
[*] entering namespaces of pid 12252
[sendfd]  Started sendfd
[sendfd]  Opening fd
[sendfd]  Creating socket
[sendfd]  Creating addr
[sendfd]  Binding
[sendfd]  Listening
[sendfd]  Accepting

[+] Running in sandbox #1: recvfd
[*] entering namespaces of pid 12253
[recvfd]  Started recvfd
[recvfd]  Creating socket
[recvfd]  Creating addr
[recvfd]  Connecting
[recvfd]  Preparing for receive
[recvfd]  Receiving fd
[sendfd]  Preparing fd message
[sendfd]  Sending fd
[sendfd]  Done
[recvfd]  Extracting fd
[recvfd]  Starting race

[+] Starting sandbox: escalate
[*] setgroups deny
[*] writing uid_map
[*] writing gid_map
[*] Creating chroot dir "/tmp/chroots/2"
[recvfd]  Race done
[*] Chrooting to "/tmp/chroots/2"
[*] changing group ids
[*] changing user ids
[recvfd]  Done
[*] starting init
[escalate]  Started escalate
[escalate]  Checking that we won the race
[escalate]  Reading current pid
[escalate]  Init pid: 12258
[escalate]  Creating new namespaces
[escalate]  Forking
[escalate]  Parent done
[escalate]  Child started
[escalate]  Reading current pid
[escalate]  Child pid: 12259
[escalate]  Creating dir "/tmp/oldproc_fHGEpuOpXK"
[escalate]  Creating bind mount "/tmp/oldproc_fHGEpuOpXK" -> "/proc"
[escalate]  Creating dir "/tmp/newproc_fHGEpuOpXK"
[escalate]  Creating bind mount "/proc" -> "/tmp/newproc_fHGEpuOpXK"
[escalate]  Creating dir "/proc/12258"
[escalate]  Creating dir "/proc/12258/ns"
[escalate]  Linking pid ns "/proc/12258/ns/pid" -> "/tmp/oldproc_fHGEpuOpXK/12259/ns/pid"
[escalate]  Creating fifo "/proc/12258/ns/uts"
[escalate]  Waiting for victim to join

[+] Running in sandbox #2: sleep
[*] entering namespaces of pid 12258
[escalate]  Attached to victim
[escalate]  Reading rip
[escalate]  Writing shellcode to 0x7fe1af29db1c
[escalate]  Detaching
[escalate]  Opening fifo
[shellcode]  FLAG: flag{local_test}
[shellcode]  DONE
[*] Closed connection to localhost port 1337
```
