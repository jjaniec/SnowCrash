# Level13

```bash
level13@SnowCrash:~$ ./level13
UID 2013 started us but we we expect 4242
```

The goal will be to fake the user id of the program

After looking for how to do this with cgroups, by using something like [nsjail](https://github.com/google/nsjail), or even container mappings and seeing that `lxc` & `docker` were not installed, I tried to use gdb

### Exploit

- Start the program with `gdb`

```bash
level13@SnowCrash:~$ gdb ./level13
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level13/level13...(no debugging symbols found)...done.
```

- Look for getuid() calls

```gdb
(gdb) disas /m main
Dump of assembler code for function main:
   0x0804858c <+0>:     push   %ebp
   0x0804858d <+1>:     mov    %esp,%ebp
   0x0804858f <+3>:     and    $0xfffffff0,%esp
   0x08048592 <+6>:     sub    $0x10,%esp
   0x08048595 <+9>:     call   0x8048380 <getuid@plt>
   0x0804859a <+14>:    cmp    $0x1092,%eax
   0x0804859f <+19>:    je     0x80485cb <main+63>
   0x080485a1 <+21>:    call   0x8048380 <getuid@plt>
   0x080485a6 <+26>:    mov    $0x80486c8,%edx
   0x080485ab <+31>:    movl   $0x1092,0x8(%esp)
   0x080485b3 <+39>:    mov    %eax,0x4(%esp)
   0x080485b7 <+43>:    mov    %edx,(%esp)
   0x080485ba <+46>:    call   0x8048360 <printf@plt>
   0x080485bf <+51>:    movl   $0x1,(%esp)
   0x080485c6 <+58>:    call   0x80483a0 <exit@plt>
   0x080485cb <+63>:    movl   $0x80486ef,(%esp)
   0x080485d2 <+70>:    call   0x8048474 <ft_des>
   0x080485d7 <+75>:    mov    $0x8048709,%edx
   0x080485dc <+80>:    mov    %eax,0x4(%esp)
   0x080485e0 <+84>:    mov    %edx,(%esp)
   0x080485e3 <+87>:    call   0x8048360 <printf@plt>
   0x080485e8 <+92>:    leave
   0x080485e9 <+93>:    ret
End of assembler dump.
```

- Place a breakpoint after the getuid() call to replace the return value stored in the register

```bash
(gdb) break *0x0804859a
Breakpoint 1 at 0x804859a
```

- Start the program

```bash
(gdb) run
Starting program: /home/user/level13/level13

Breakpoint 1, 0x0804859a in main ()
```

- Look for register values, our user id is here!

```bash
(gdb) info registers
eax            0x7dd    2013
ecx            0xbffff734       -1073744076
edx            0xbffff6c4       -1073744188
ebx            0xb7fd0ff4       -1208152076
esp            0xbffff680       0xbffff680
ebp            0xbffff698       0xbffff698
esi            0x0      0
edi            0x0      0
eip            0x804859a        0x804859a <main+14>
eflags         0x200246 [ PF ZF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
```

- Replace the userid value stored in the register

```bash
(gdb) set $eax = 4242
```

```bash
(gdb) continue
Continuing.
your token is 2A31L79asukciNyi8uppkEuSx
[Inferior 1 (process 3117) exited with code 050]
(gdb) quit
```

### Goto level14

```bash
level13@SnowCrash:~$ su level14
Password: <<< '2A31L79asukciNyi8uppkEuSx'
```
