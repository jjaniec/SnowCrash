# Level00

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
