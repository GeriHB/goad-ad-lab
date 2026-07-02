# Discovery and Enumeration

## Objective

The first phase established which Windows systems were reachable, how they were organised into domains, and what information could be obtained without valid credentials.

## Starting position

- Network access to the isolated `10.4.10.0/24` lab subnet
- No usernames or passwords
- No confirmed domain or host inventory

## SMB host discovery

The original assessment used **CrackMapExec** to identify SMB-speaking systems:

```bash
# Command used during hte original assessment
crackmapexec smb 10.4.10.0/24

# Current NetExec equivalent
nxc smb 10.4.10.0/24
```

The scan identified five Windows systems across three domains:

- `10.4.10.10` — `KINGSLANDING` — `sevenkingdoms.local`
- `10.4.10.11` — `WINTERFELL` — `north.sevenkingdoms.local`
- `10.4.10.12` — `MEEREEN` — `essos.local`
- `10.4.10.22` — `CASTELBLACK` — `north.sevenkingdoms.local`
- `10.4.10.23` — `BRAAVOS` — `essos.local`

The output also indicated that SMB signing was not required on `CASTELBLACK` and `BRAAVOS`. That did not provide access by itself, but it identified systems that could become relevant to NTLM relay tsting later in the assessment.

![alt text](../assets/evidence/01-discovery/Enumeration1.png)

## Anonymous account enumeration

Anonymous user enumeration was attempted against the discovered hosts. Most systems rejected the request, but `WINTERFELL` returned domain account information without valid credentials.

```bash
# Original syntax
crackmapexec smb 10.4.10.11 --users

# Current equivalent
nxc smb 10.4.10.11 --users
```

The successful result indicated that anonymous RPC/SAMR access exposed directory infromation. More importantly, one accoutn description contained a plaintext lab password for `samwell.tarly`.

```text
samwell.tarly:<PASSWORD_DISCLOSED_IN_ACCOUNT_DESCRIPTION>
```
![alt text](../assets/evidence/01-discovery/Enumeration2.png)

This was the first direct credential exposure in the assessment. The weakness was not the enumeration tool itself; it was the combination of anonymous directory access and sensitive information stored in a user-controlled descriptive field.

## Group enumeration

`enum4linux` was used to retrieve domain groups and map selected users to them:

```bash
enum4linux 10.4.10.11
```

The output exposed standard domain groups as well as lab-specific groups such as `Stark`, `Night Watch`, and `Mormont`.

This provided context for the account structure and helped prioritise users for later authentication testing.

The complete user and group is intentionally omitted. The important result was that unauthenticated access revealed enough naming and group information to build a credible user list.

## Password-policy retrieval

Before any password spraying, the domain password policy was queried:

```bash
# Original syntax
crackmapexec smb 10.4.10.11 --pass-pol

# Current equivalent
nxc smb 10.4.10.11 --pass-pol
```

The relevant policy values were:

```text
Account lockout threshold:	5 attempts
Lockout counter reset:		5 minutes
Lockout duration:			5 minutes
```

![alt text](../assets/evidence/01-discovery/Password_Policy.png)

Retrieving the policy changed how later authentication testing was performed. Rather than sending repeated attempts against individual accounts, the assessment used a small, controlled password-spray set designed to remain below the known threshold.

## Kerberos username enumeration

The usernames returned from `WINTERFELL` showed a consistent `firstname.lastname` convention and a Game of Thrones naming theme. A larger candidate list was generated from publicly available character names and normalised into that format.


```bash
curl -s https://www.hbo.com/game-of-thrones/cast-and-crew | grep 'href="/game-of-thrones/cast-and-crew/' | grep -o 'aria-label="[^"]*"' | cut -d '"' -f 2 | awk '{
      if ($2 == "") print tolower($1);
      else print tolower($1) "." tolower($2)
    }'  > usernames.txt
```
This was a lab-specific way to create realistic candidates. In a real assessment, username generation would need to stay within the agreed rules of engagement and use approeved sources.

Kerberos responses were then used to distinguish valid principals from unknown accounts:

```bash
nmap -p 88 --script krb5-enum-users --script-args="krb5-enum-users.real='sevenkingdoms.local',userdb=usernames.txt" 10.4.10.10
```

For the child domain, the real must match the target domain:

```bash
nmap -88 --script krb5-enum-users --script-args="krb5-enum-users.real='north.sevenkingdoms.local',userdb=usernames.txt" 10.4.10.11
```

The same method was applied to `essos.local` through `MEEREEN`.

## Result

The discovery phase produced:

- A confirmed inventory of five Windows systems
- Three domain names across two forests
- SMB-signing observations relevant to later relay analysis
- Anonymous user and group enumeration on`WINTERFELL`
- One plaintext lab password exposed in an account description
- The domain lockout policy
- Additional valid usernames discovered through Kerberos responses

This was enough information to move from unauthenticated discovery to targeted credential testing.

## Security impact

Anonymous directory access reduces the amount of uncertainty an attacker must overcome. When it is compbined with descriptive fields containing passwords, it can provide both a target list and an initial credential without requiring exploitation of a software vulnerability.

## Detection opportunities

Defenders should review:

- Anonymous SAMR and RPC queries to domain controllers
- Repeated Kerberos authentication requests for many different usernames from one source
- SMB enumeration from systems that are not administrative workstations
- Changes to accoutn description fields
- Sensitive words or password-like values stored in directory attributes

## Mitigation

- Prevent anonymous account and group enumeration where it is not required
- Remove credential and operational secrets from account descriptions and other directory attributes
- Require SMB signing where operationally possible
- Monitor high-volume Kerberos principal discovery
- Use naming and lockout policies as one control among several, not as the primary defence against credential attacks

## MITRE ATT&CK mapping

- `T1046` - Network Service Discovery
- `T1087.002` - Domain Accoutn Discovery
- `T1069.002` - Domain Groups Discovery
- `T1201` - Password Policy Discovery

## Key takeaway

The first meaningful weakness was not an advanced exploit.

Basic access-control and information-handling problems exposed the domain structure, user population, password policy, and an initial credential.

That information made every later stage more targeted and less noisy.

## Navigation

[Previous: Lab environment and scope](00-lab-environment-and-scope.md) | [Assessment index](../README.md) | [Next: Initial credential access](02-initial-credential-access.md)












































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
