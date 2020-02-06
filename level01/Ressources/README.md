# Level01

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

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://ssh.cloud.google.com/cloudshell/editor?cloudshell_git_repo=http://github.com/jjaniec/snowcrash)

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
