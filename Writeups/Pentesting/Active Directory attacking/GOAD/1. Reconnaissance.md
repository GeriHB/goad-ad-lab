# 1. Reconnaissance

First let's start the reconnaissance of the GOAD by searching all the available IPs.

From the first steps, I will launch crackmapexec to get all the windows machine IP, names and domains.

**crackmapexec** is a powerful tool which simplifies the process of interacting with multiple protocols and services. It plays an important role in Reconnaissance as it enables automated enumeration. 

## 1.1 Host Discovery with CrackMapExec


```shell
crackmapexec smb 10.4.10.1/24
```

Via this command I will scan the subnet of devices from 10.4.10.1 to 10.4.10.254 over the SMB protocol. The results will allow to gather information about the SMB services in this IP range.

From this we get the following result:

<img width="1284" alt="Pasted_image_20241218165858" src="https://github.com/user-attachments/assets/20b07e71-b42d-4c9f-9ad9-15df5a64356a" />

Here we can see some important information. We have learned that there are three domains:
- north.sevenkingdoms.local
- sevenkingdoms.local
- essos.local

They have a number of IP-s associated with them.
- north.sevenkingdoms.local:
	- Winterfell (windows server 2019) - **10.4.10.11**
	- Castelblack (windows server 2019) (signing false) - **10.4.10.22**
- sevenkingdoms.local:
	- Kingslanding (windows server 2019) - **10.4.10.10**
- essos.local:
	- Meereen (Windows Server 2016) - **10.4.10.12**
	- Braavos (Windows Server 2019) (signing false) - 10.4.10.23

## 1.2 Enumeration of Users and Groups

We will continue to use "crackmapexec" to enumerate users, and will try to do it for all of GOAD machines.

From the previous command, we saw the hosts available, I will run "cracmapexec" to enumerate users on these hosts.

```bash
crackmapexec smb 10.4.10.10 --users
```

This command didn't bring any results at all! But after checking all the hosts, I got some results, on host 10.4.10.11 "Winterfell".

183db8bc2c33ac4d835e309332489e94a3d9b048

<img width="1279" alt="Pasted_image_20241219165113" src="https://github.com/user-attachments/assets/316b69c5-98d3-4fdd-8efa-7462bd0ab0ae" />


Here there is a user which has also the password on description **Samwell Tarly (Password: Heartsbane).**

Now I will use another tool to get the groups. `enum4linux 10.4.10.11` gave the following groups:

```shell
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44f]
group:[Stark] rid:[0x452]
group:[Night Watch] rid:[0x453]
group:[Mormont] rid:[0x454]
```

`enum4linux` provided also the information of which users belong to which groups:

- Domain Users:
	- Administrator
	- localuser
	- krbtgt
	- SEVENKINGDOMS$
	- arya.stark
	- eddard.stark
	- catelyn.stark
	- robb.stark
	- sansa.stark
	- brandon.stark
	- rickon.stark
	- hodor
	- jon.snow
	- samwell.tarly
	- jeor.mormont
	- sql_svc
- Domain Guests
	- Guest
- Night Watch
	- jon.snow
	- samwell.tarly
	- jeor.mormont
- Mormont
	- jeor.mormont
- Domain Computers
	- CASTELBLACK$
- Group Policy Creator Owners
	- Administrator
- Stark
	- arya.stark
	- eddard.stark
	- catelyn.stark
	- robb.stark
	- sansa.stark
	- brandon.stark
	- rickon.stark
	- hodor
	- jon.snow
### 1.2.1 How did the enumeration happen

It first detected the SMB service on port 445, then identified information such as:
- NetBIOS Name: WINTERFELL
- Domain: north.sevenkingdoms.local
- SMB Signing: It's enabled which makes MitM attacks harder, but it doesn't prevent enumeration.
- SMBV1 is disabled, meaning that more modern SMB protocols are in use.

Then it tries to enumerate domain users using NTLM authentication mechanism, but it fails. This because it requires valid credentials.

The next step is to try the enumeration via SAMRPS (Security Account Manager Remote Protocol), which interacts with the SAM database.

Here the enumeration was successful most probably because null session is allowed.

Null session refers to a connection without any authentication (anonymous connection), which happens because of misconfigured systems. This allowed crackmapexec to query the information from SAM database, and give back the users.

### 1.3 Retrieving the Password Policy

Another important information for attacker is the Password Policy which can give insight to what is the structure of the passwords, and hints that can give unauthorized access.

**crackmapexec** can help retrieving the password policy.

```shell
crackmapexec smb 10.4.10.11 --pass-pol
```

We got success only on the "Winterfell" again:

<img width="1258" alt="Pasted_image_20241220091449" src="https://github.com/user-attachments/assets/82d53236-92f0-43f2-821d-6444d3af3f27" />

One of the important information gained here is:

```shell
SMB  10.4.10.11  445    WINTERFELL       Reset Account Lockout Counter: 5 minutes
SMB  10.4.10.11  445    WINTERFELL       Locked Account Duration: 5 minutes
SMB  10.4.10.11  445    WINTERFELL       Account Lockout Threshold: 5
```

This means that if the password fails 5 times in 5 minutes, the account will be locked for 5 minutes.

This should be taken into consideration if we brute-force.
### 1.4 Kerberos Pre-auth Username Enumeration

We only got information from 10.4.10.11 - the Winterfell DC, but not from the others. The reason is that Winterfell allows anonymous connection.

Other hosts are not allowing anonymous connection. Usually this is what happens in real-life.

But there is another way on getting the users, which is by brute-forcing. Anyways, to do this some initial information is needed, as to what format are the usernames, or any other information that can show how the usernames are formed.

From the previous usernames found we see two hints that may help on finding the other usernames:
- the format of the usernames is "name.lastname"
- usernames are from the characters of Game of Thrones.

So, in this case I will create a list of usernames gained from Game of Thrones characters, and will check them against other hosts.

By going to "https://www.hbo.com/game-of-thrones/cast-and-crew" we can see all GoT characters, and in the Page Source the names can be seen on `aria-label="..."`

<img width="780" alt="Pasted_image_20241220104559" src="https://github.com/user-attachments/assets/b9131521-6a37-4edf-bd79-7a0562553b7e" />

I will use this information and get these names in the format that we need, by using `curl, grep, cut, and awk`.

```shell
curl -s https://www.hbo.com/game-of-thrones/cast-and-crew | grep 'href="/game-of-thrones/cast-and-crew/'| grep -o 'aria-label="[^"]*"' | cut -d '"' -f 2 | awk '{if($2 == "") {print tolower($1)} else {print tolower($1) "." tolower($2);} }' > username`
```

Basically we download the page, search for the part where there is "aria-label", cut it and get the full name, and check if there is no last name, get only the first name in lower characters, and if there is a last name, append it after the first name and add a `.` in between, and in the end save it to a file `username`.

I will brute-force Kerberos (a network authentication protocol designed to authenticate users or systems), which is widely used in Active Directory.

Kerberos uses **pre-authentication** which is a security measure to ensure that only valid users can request a Kerberos ticket.

Basically, when a user wants to authenticate, they send an initial request (AS-REQ) from the Key Distribution Center (KDC), which responds with a challenge that has to be encrypted using the user's password.

This is what I will target to brute-force, by sending requests for each user in the list, and if that user exists, Kerberos will respond with a "Pre-authentication required", which means the user exists.

If the server responds with a "Principal Unknown" it means that the username is not in the database.

This can be done by using `nmap`.

```shell
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='sevenkingdoms.local',userdb=username" 10.4.10.10 > sevenkingdoms_users
```

And we go some results for **Kingslanding** - 10.4.10.10!

<img width="811" alt="Pasted_image_20241220115808" src="https://github.com/user-attachments/assets/2be6a890-aa8f-4932-b7e1-6c762854a991" />

For 10.4.10.11, we launch:
```shell
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='sevenkingdoms.local',userdb=username" 10.4.10.11 > north_evenkingdoms_users
```

And we got the results:

<img width="811" alt="Pasted_image_20241220115230" src="https://github.com/user-attachments/assets/64d46120-e5ad-457d-ba85-bfde074d676d" />

After checking we got some results also from Meeren, by issuing this command:

```shell
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='essos.local',userdb=username" 10.4.10.12 > essos_users
```
<img width="811" alt="Pasted_image_20241220115207" src="https://github.com/user-attachments/assets/e5c64e12-77bf-46e6-962d-b86f87d69b0b" />
