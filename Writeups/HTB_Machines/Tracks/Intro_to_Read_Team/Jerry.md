
------------
*Windows* - It's realistic as Apache Tomcat often is found exposed and configured with common or weak credentials.

--------------

## Task 1

Which TCP port is open on the remote host?

## Solution 1

Starting the `nmap` scan such as:

```sh
nmap -sC -T4 10.10.10.95
```

doesn't work, with the note `Host seems down. If it is really up, but blocking our ping probes, try -Pn`.

So let's try with the option to block ping probes:

```sh
nmap -sC -Pn -T4 10.10.10.95
```

This provides with the results:

```sh
PORT     STATE SERVICE
8080/tcp open  http-proxy
|_http-title: Apache Tomcat/7.0.88
|_http-favicon: Apache Tomcat
```

So the answer is `8080`.

----------

## Task 2

Which web server is running on the remote host? Looking for two words.

## Solution 2

From the results above we see that the web server running on the host is `Apache Tomcat`.

---------

## Task 3

Which relative path on the webserver leads to the Web Application Manager?

## Solution 3

On the main page of the webpage there is a link `manager webapp`, which goes to the link `/manager/html`.

----------

## Task 4

What is the valid username and password combination for authenticating into the Tomcat Web Application Manager? Give the answer in the format of username:password

## Solution 4

I tried some credentials such as `admin:admin` and I got a `403 Access Denied`, which showed also a page, which tells the default credentials:

```sh
If you have not changed any configuration files, please examine the file conf/tomcat-users.xml in your installation. That file must contain the credentials to let you use this webapp.

For example, to add the manager-gui role to a user named tomcat with a password of s3cret, add the following to the config file listed above.
```


---------------

## Task 5

Which file type can be uploaded and deployed on the server using the Tomcat Web Application Manager?

## Solution 5

On the page where I got access with the credentials there is a section `Deploy` and there is also a subsection to upload `.war` files.

----------

## Task 6

Submit the flag located on the user's desktop.

## Solution 6

Let's try to exploit it using the `tomcat_jsp_upload_bypass` on `Metasploit`.

Edit the following options:
- HttpPassword - `s3cret`.
- HttpUsername - `tomcat`.
- RHOSTS - Ip of the machine.
- RPORT - Port of the machine.
- LHOST - IP address of our machine.

And then run `exploit`.

This gives us `meterpreter`. Navigate to `C:\Users\Administrator\Desktop` and you have a folder `flags`.

Inside there is a file names `2 for the price of 1.txt`.

`cat` to it to read the content, which is `7004dbcef0f854e0fb401875f26ebd00`.

-----------

## Task 7

Submit the flag located on the administrator's desktop.

## Solution 7

When we read the file on the `Task 6` the result was:

```sh
meterpreter > cat 2\ for\ the\ price\ of\ 1.txt 
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```

The final flag, is the content of the `root.txt`.
