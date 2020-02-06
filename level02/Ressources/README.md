# Level02

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
