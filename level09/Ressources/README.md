# Level09

```bash
level09@SnowCrash:~$ ls -lA
total 24
-r-x------ 1 level09 level09  220 Apr  3  2012 .bash_logout
-r-x------ 1 level09 level09 3518 Aug 30  2015 .bashrc
-rwsr-sr-x 1 flag09  level09 7640 Mar  5  2016 level09
-r-x------ 1 level09 level09  675 Apr  3  2012 .profile
----r--r-- 1 flag09  level09   26 Mar  5  2016 token
```

When running with ltrace, a different message appears

```bash
level09@SnowCrash:~$ ./level09
You need to provied only one arg.
level09@SnowCrash:~$ ltrace  ./level09
__libc_start_main(0x80487ce, 1, 0xbffff7f4, 0x8048aa0, 0x8048b10 <unfinished ...>
ptrace(0, 0, 1, 0, 0xb7e2fe38)                                                                                            = -1
puts("You should not reverse this"You should not reverse this
)                                                                                       = 28
+++ exited (status 1) +++
level09@SnowCrash:~$
```

Same thing with strace ....

```bash
level09@SnowCrash:~$ ./
.bash_logout  .bashrc       level09       .profile
level09@SnowCrash:~$ ./level09 ./token
.0vrojt
level09@SnowCrash:~$ strace ./level09 ./token
execve("./level09", ["./level09", "./token"], [/* 18 vars */]) = 0
brk(0)                                  = 0x804b000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7fdb000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=21440, ...}) = 0
mmap2(NULL, 21440, PROT_READ, MAP_PRIVATE, 3, 0) = 0xb7fd5000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/i386-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0000\226\1\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0755, st_size=1730024, ...}) = 0
mmap2(NULL, 1739484, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xb7e2c000
mmap2(0xb7fcf000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1a3) = 0xb7fcf000
mmap2(0xb7fd2000, 10972, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xb7fd2000
close(3)                                = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7e2b000
set_thread_area({entry_number:-1 -> 6, base_addr:0xb7e2b900, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0
mprotect(0xb7fcf000, 8192, PROT_READ)   = 0
mprotect(0x8049000, 4096, PROT_READ)    = 0
mprotect(0xb7ffe000, 4096, PROT_READ)   = 0
munmap(0xb7fd5000, 21440)               = 0
ptrace(PTRACE_TRACEME, 0, 0x1, 0)       = -1 EPERM (Operation not permitted)
fstat64(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 3), ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7fda000
write(1, "You should not reverse this\n", 28You should not reverse this
) = 28
exit_group(1)                           = ?
level09@SnowCrash:~$
```

Documentation about ptrace(2), -> Google related result `ptrace anti debug`

The binary is doing the somewhat famous in the reverse engineering community 'ptrace anti-debug' trick

- https://aaronyoo.github.io/ptrace-anti-debug.html

```text
For the ptrace anti-debug mechanism, the program tries to call ptrace on itself.
This will fail if the program is being debugged and will succeed if the program is not being debugged because no two tracers can trace the same tracee. 
```

This explains why we get the following line in our strace() output !

```bash
ptrace(PTRACE_TRACEME, 0, 0x1, 0)       = -1 EPERM (Operation not permitted)
```

### Exploiting the binary

```bash
level09@SnowCrash:~$ mktemp  -d
/tmp/tmp.98mqTFCvW9

level09@SnowCrash:~$ cd /tmp/tmp.98mqTFCvW9
```

```bash
nano inject.c
long ptrace(int a, int b, void *c, void *d) {
        return 0; // Redefine ptrace()
}
```

```bash
level09@SnowCrash:/tmp/tmp.98mqTFCvW9$ gcc -shared -fPIC -o ptrace_inject.so inject.c

level09@SnowCrash:/tmp/tmp.98mqTFCvW9$ ltrace env LD_PRELOAD=./ptrace_inject.so /home/user/level09/level09 /home/user/level09/token
__libc_start_main(0x8048db0, 4, 0xbffff794, 0x804b700, 0x804b770 <unfinished ...>
strrchr("env", '/')                                                                                                       = NULL
setlocale(6, "")                                                                                                          = "en_US.UTF-8"
bindtextdomain("coreutils", "/usr/share/locale")                                                                          = "/usr/share/locale"
textdomain("coreutils")                                                                                                   = "coreutils"
__cxa_atexit(0x8049500, 0, 0, 0xbffff794, 4)                                                                              = 0
getopt_long(4, 0xbffff794, "+iu:0", 0x0804bc40, NULL)                                                                     = -1
getopt_long(4, 0xbffff794, "+iu:0", 0x0804bc40, NULL)                                                                     = -1
strchr("LD_PRELOAD=./ptrace_inject.so", '=')                                                                              = "=./ptrace_inject.so"
putenv("LD_PRELOAD=./ptrace_inject.so")                                                                                   = 0
strchr("/home/user/level09/level09", '=')                                                                                 = NULL
execvp(0xbffff8d9, 0xbffff79c, 0x804bbea, 0x804bc40, 0 <unfinished ...>
--- Called exec() ---
__libc_start_main(0x80487ce, 2, 0xbffff784, 0x8048aa0, 0x8048b10 <unfinished ...>
ptrace(0, 0, 1, 0, 0xb7e2ce38)                                                                                            = 0
getenv("LD_PRELOAD")                                                                                                      = "./ptrace_inject.so"
fwrite("Injection Linked lib detected ex"..., 1, 37, 0xb7fce980Injection Linked lib detected exit..
)                                                          = 37
+++ exited (status 1) +++
```

Looks like the binary is not that idiot...

LD_PRELOAD=/tmp/tmp.Lhnb115oZ5/ptrace_inject.so

### Exploiting the binary (2)

```bash
level09@SnowCrash:~$ gdb ./level09
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level09/level09...(no debugging symbols found)...done.
(gdb) run ./token
Starting program: /home/user/level09/level09 ./token
You should not reverse this
[Inferior 1 (process 7400) exited with code 01]

(gdb) layout asm


(gdb) set environment LD_PRELOAD /tmp/tmp.98mqTFCvW9/ptrace_inject.so
```


```asm
(gdb) disas /m main
Dump of assembler code for function main:
   0x080487ce <+0>:     push   %ebp
   0x080487cf <+1>:     mov    %esp,%ebp
   0x080487d1 <+3>:     push   %edi
   0x080487d2 <+4>:     push   %ebx
   0x080487d3 <+5>:     and    $0xfffffff0,%esp
   0x080487d6 <+8>:     sub    $0x130,%esp
   0x080487dc <+14>:    mov    0xc(%ebp),%eax
   0x080487df <+17>:    mov    %eax,0x1c(%esp)
   0x080487e3 <+21>:    mov    %gs:0x14,%eax
   0x080487e9 <+27>:    mov    %eax,0x12c(%esp)
   0x080487f0 <+34>:    xor    %eax,%eax
   0x080487f2 <+36>:    movl   $0x0,0x24(%esp)
   0x080487fa <+44>:    movl   $0xffffffff,0x20(%esp)
   0x08048802 <+52>:    movl   $0x0,0xc(%esp)
   0x0804880a <+60>:    movl   $0x1,0x8(%esp)
   0x08048812 <+68>:    movl   $0x0,0x4(%esp)
   0x0804881a <+76>:    movl   $0x0,(%esp)
   0x08048821 <+83>:    call   0x80484e0 <ptrace@plt> ; Check if ptrace() fails with -1
   0x08048826 <+88>:    test   %eax,%eax ; Reassign $eax to 0: break *0x8048826 && info all-registers && set $eax = 0;
   0x08048828 <+90>:    jns    0x8048840 <main+114> ; Jump if not equal ($eax / -1)
   0x0804882a <+92>:    movl   $0x8048b70,(%esp) ; gdb) printf "%s", 0x8048b70 -> You should not reverse this
   0x08048831 <+99>:    call   0x8048480 <puts@plt> ; Print 'You should not reverse this'
   0x08048836 <+104>:   mov    $0x1,%eax
   0x0804883b <+109>:   jmp    0x8048a77 <main+681> ; Goto exit()
   0x08048840 <+114>:   movl   $0x8048b8c,(%esp) ;  printf "%s", 0x8048b8c -> LD_PRELOAD
   0x08048847 <+121>:   call   0x8048470 <getenv@plt> ; Check LD_PRELOAD env variable content
   0x0804884c <+126>:   test   %eax,%eax ; Check if getenv returned NULL
   0x0804884e <+128>:   je     0x8048882 <main+180> ; Jump if getenv("LD_PRELOAD") equals NULL
   0x08048850 <+130>:   mov    0x804a040,%eax
   0x08048855 <+135>:   mov    %eax,%edx
   0x08048857 <+137>:   mov    $0x8048b98,%eax ; (gdb) printf "%s", 0x8048b98 -> ��Injection Linked lib detected exit..
   0x0804885c <+142>:   mov    %edx,0xc(%esp)
   0x08048860 <+146>:   movl   $0x25,0x8(%esp)
   0x08048868 <+154>:   movl   $0x1,0x4(%esp)
   0x08048870 <+162>:   mov    %eax,(%esp)
   0x08048873 <+165>:   call   0x8048460 <fwrite@plt> ; fwrite 'Injection linked lib detected exit..'
   0x08048878 <+170>:   mov    $0x1,%eax
   0x0804887d <+175>:   jmp    0x8048a77 <main+681> ; Goto exit
   0x08048882 <+180>:   movl   $0x0,0x4(%esp)
   0x0804888a <+188>:   movl   $0x8048bbe,(%esp) ; (gdb) printf "%s", 0x8048bbe -> /etc/ld.so.preload
   0x08048891 <+195>:   call   0x80484a0 <open@plt> ; open /etc/ld.so.preload https://unix.stackexchange.com/questions/282057/what-would-suddenly-cause-programs-to-read-etc-ld-so-preload-when-they-start-up
   0x08048896 <+200>:   test   %eax,%eax ; Check if open /etc/ld.so.preload returned -1 to know if we're messing with preload functions
   0x08048898 <+202>:   jle    0x80488cc <main+254> ; jump if (x <= y) (-1 < 0)
   0x0804889a <+204>:   mov    0x804a040,%eax
   0x0804889f <+209>:   mov    %eax,%edx
   0x080488a1 <+211>:   mov    $0x8048b98,%eax ; (gdb) printf "%s", 0x8048b98 -> Injection Linked lib detected exit..
   0x080488a6 <+216>:   mov    %edx,0xc(%esp)
   0x080488aa <+220>:   movl   $0x25,0x8(%esp)
   0x080488b2 <+228>:   movl   $0x1,0x4(%esp)
   0x080488ba <+236>:   mov    %eax,(%esp)
   0x080488bd <+239>:   call   0x8048460 <fwrite@plt> ; Print 'Injection Linked lib detected exit..'
   0x080488c2 <+244>:   mov    $0x1,%eax
   0x080488c7 <+249>:   jmp    0x8048a77 <main+681> ; Goto exit()
   0x080488cc <+254>:   movl   $0x0,0x4(%esp)
   0x080488d4 <+262>:   movl   $0x8048bd1,(%esp) ; (gdb) printf "%s", 0x8048bd1 -> /proc/self/maps ; https://stackoverflow.com/questions/1401359/understanding-linux-proc-id-maps
   0x080488db <+269>:   call   0x80485a4 <syscall_open> ; open /proc/self/maps
   0x080488e0 <+274>:   mov    %eax,0x28(%esp) ; move open() return into %esp
   0x080488e4 <+278>:   cmpl   $0xffffffff,0x28(%esp) ;  Compare unsigned
   0x080488e9 <+283>:   jne    0x8048a50 <main+642> ; Jump if not equal -1
   0x080488ef <+289>:   mov    0x804a040,%eax
   0x080488f4 <+294>:   mov    %eax,%edx
   0x080488f6 <+296>:   mov    $0x8048be4,%eax ; (gdb) printf "%s", 0x8048be4 -> /proc/self/maps is unaccessible, probably a LD_PRELOAD attempt exit..
   0x080488fb <+301>:   mov    %edx,0xc(%esp)
   0x080488ff <+305>:   movl   $0x46,0x8(%esp)
   0x08048907 <+313>:   movl   $0x1,0x4(%esp)
   0x0804890f <+321>:   mov    %eax,(%esp)
   0x08048912 <+324>:   call   0x8048460 <fwrite@plt> ; print /proc/self/maps is unaccessible, probably a LD_PRELOAD attempt exit..
   0x08048917 <+329>:   mov    $0x1,%eax
   0x0804891c <+334>:   jmp    0x8048a77 <main+681> ; goto exit()
   0x08048921 <+339>:   movl   $0x8048c2b,0x4(%esp)
   0x08048929 <+347>:   lea    0x2c(%esp),%eax
   0x0804892d <+351>:   mov    %eax,(%esp)
   0x08048930 <+354>:   call   0x80486cb <isLib>
   0x08048935 <+359>:   test   %eax,%eax
   0x08048937 <+361>:   je     0x8048946 <main+376>
   0x08048939 <+363>:   movl   $0x1,0x24(%esp)
   0x08048941 <+371>:   jmp    0x8048a51 <main+643>
   0x08048946 <+376>:   cmpl   $0x0,0x24(%esp)
   0x0804894b <+381>:   je     0x8048a51 <main+643>
   0x08048951 <+387>:   movl   $0x8048c30,0x4(%esp) ; (gdb)printf "%s", 0x8048c30 -> 'ld'
   0x08048959 <+395>:   lea    0x2c(%esp),%eax
   0x0804895d <+399>:   mov    %eax,(%esp)
   0x08048960 <+402>:   call   0x80486cb <isLib>
   0x08048965 <+407>:   test   %eax,%eax
   0x08048967 <+409>:   je     0x8048a0e <main+576>
   0x0804896d <+415>:   cmpl   $0x2,0x8(%ebp)
   0x08048971 <+419>:   jne    0x80489e4 <main+534>
   0x08048973 <+421>:   jmp    0x8048996 <main+456>
   0x08048975 <+423>:   mov    0x1c(%esp),%eax
   0x08048979 <+427>:   add    $0x4,%eax
   0x0804897c <+430>:   mov    (%eax),%edx
   0x0804897e <+432>:   mov    0x20(%esp),%eax
   0x08048982 <+436>:   add    %edx,%eax
   0x08048984 <+438>:   movzbl (%eax),%eax
   0x08048987 <+441>:   movsbl %al,%eax
   0x0804898a <+444>:   add    0x20(%esp),%eax
   0x0804898e <+448>:   mov    %eax,(%esp)
   0x08048991 <+451>:   call   0x80484c0 <putchar@plt> ; print character in a while loop with a offset
   0x08048996 <+456>:   addl   $0x1,0x20(%esp) ; increment character offset
   0x0804899b <+461>:   mov    0x20(%esp),%ebx
   0x0804899f <+465>:   mov    0x1c(%esp),%eax
   0x080489a3 <+469>:   add    $0x4,%eax
   0x080489a6 <+472>:   mov    (%eax),%eax
   0x080489a8 <+474>:   movl   $0xffffffff,0x18(%esp)
   0x080489b0 <+482>:   mov    %eax,%edx
   0x080489b2 <+484>:   mov    $0x0,%eax
   0x080489b7 <+489>:   mov    0x18(%esp),%ecx
   0x080489bb <+493>:   mov    %edx,%edi
   0x080489bd <+495>:   repnz scas %es:(%edi),%al
   0x080489bf <+497>:   mov    %ecx,%eax
   0x080489c1 <+499>:   not    %eax
   0x080489c3 <+501>:   sub    $0x1,%eax
   0x080489c6 <+504>:   cmp    %eax,%ebx
   0x080489c8 <+506>:   jb     0x8048975 <main+423>
   0x080489ca <+508>:   mov    0x804a060,%eax
   0x080489cf <+513>:   mov    %eax,0x4(%esp)
   0x080489d3 <+517>:   movl   $0xa,(%esp)
   0x080489da <+524>:   call   0x80484d0 <fputc@plt>
   0x080489df <+529>:   jmp    0x8048a75 <main+679>
   0x080489e4 <+534>:   mov    0x804a040,%eax
   0x080489e9 <+539>:   mov    %eax,%edx
   0x080489eb <+541>:   mov    $0x8048c34,%eax
   0x080489f0 <+546>:   mov    %edx,0xc(%esp)
   0x080489f4 <+550>:   movl   $0x22,0x8(%esp)
   0x080489fc <+558>:   movl   $0x1,0x4(%esp)
   0x08048a04 <+566>:   mov    %eax,(%esp)
   0x08048a07 <+569>:   call   0x8048460 <fwrite@plt>
   0x08048a0c <+574>:   jmp    0x8048a75 <main+679>
   0x08048a0e <+576>:   movl   $0x8048c57,0x4(%esp)
   0x08048a16 <+584>:   lea    0x2c(%esp),%eax
   0x08048a1a <+588>:   mov    %eax,(%esp)
   0x08048a1d <+591>:   call   0x8048646 <afterSubstr>
   0x08048a22 <+596>:   test   %eax,%eax
   0x08048a24 <+598>:   jne    0x8048a51 <main+643>
   0x08048a26 <+600>:   mov    0x804a040,%eax
   0x08048a2b <+605>:   mov    %eax,%edx
   0x08048a2d <+607>:   mov    $0x8048c68,%eax
   0x08048a32 <+612>:   mov    %edx,0xc(%esp)
   0x08048a36 <+616>:   movl   $0x30,0x8(%esp)
   0x08048a3e <+624>:   movl   $0x1,0x4(%esp)
   0x08048a46 <+632>:   mov    %eax,(%esp)
   0x08048a49 <+635>:   call   0x8048460 <fwrite@plt>
   0x08048a4e <+640>:   jmp    0x8048a75 <main+679>
   0x08048a50 <+642>:   nop
   0x08048a51 <+643>:   mov    0x28(%esp),%eax
   0x08048a55 <+647>:   mov    %eax,0x8(%esp)
   0x08048a59 <+651>:   movl   $0x100,0x4(%esp)
   0x08048a61 <+659>:   lea    0x2c(%esp),%eax
   0x08048a65 <+663>:   mov    %eax,(%esp)
   0x08048a68 <+666>:   call   0x80485d4 <syscall_gets> ; gets(0);
   0x08048a6d <+671>:   test   %eax,%eax
   0x08048a6f <+673>:   jne    0x8048921 <main+339> ; jump to 339 if %eax != 0
   0x08048a75 <+679>:   jmp    0x8048a77 <main+681> ; else exit()
   0x08048a77 <+681>:   mov    0x12c(%esp),%edx
   0x08048a7e <+688>:   xor    %gs:0x14,%edx
   0x08048a85 <+695>:   je     0x8048a8c <main+702>
   0x08048a87 <+697>:   call   0x8048450 <__stack_chk_fail@plt>
   0x08048a8c <+702>:   lea    -0x8(%ebp),%esp
   0x08048a8f <+705>:   pop    %ebx
   0x08048a90 <+706>:   pop    %edi
   0x08048a91 <+707>:   pop    %ebp
   0x08048a92 <+708>:   ret
End of assembler dump.
```

### Then realizing I should have listened

After some time I realized the token file was readable...

```bash
level09@SnowCrash:~$ ./level09  abcdef
acegik

level09@SnowCrash:~$ xxd ./token
0000000: 6634 6b6d 6d36 707c 3d82 7f70 826e 8382  f4kmm6p|=..p.n..
0000010: 4442 8344 757b 7f8c 890a                 DB.Du{....
```

```bash
level09@SnowCrash:~$ cat /tmp/tmp.DbWvKJIpjK
import sys

for line in sys.stdin:
        offset = 0
        for c in line:
                print(chr(ord(c) - offset)),
                offset += 1
```

```bash
level09@SnowCrash:~$ cat ./token  | python /tmp/tmp.DbWvKJIpjK  | tr -d ' '
f3iji1ju5yuevaus41q1afiuq
```

### Goto level10

```bash
level09@SnowCrash:~$ su flag09
Password: <<< 'f3iji1ju5yuevaus41q1afiuq'
Don't forget to launch getflag !

flag09@SnowCrash:~$ getflag
Check flag.Here is your token : s5cAJpM8ev6XHw998pRWG728z
```
