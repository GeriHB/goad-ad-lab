# 2. Initial Access

## 2.1 ASREPRoasting

First I will try **asreproasting** to try and get some passwords from the users I got hands on.

**asreproasting** is a type of attack which exploits accounts that don't require Kerberos pre-authentication. It sends an AS-REQ to KDC, and if the pre-authentication is disabled, the reponse is with an AS-REP message which contains encrypted data, where can be found also the password hash.

First we need to extract only the usernames from the results we got before. 

Now I will try to get the passwords, and for this I will use the `impacket tools` which can be downloaded from `https://github.com/fortra/impacket/tree/master`.

`GetNPUsers` is one of the tools part of `impacket` which I will use for this purpose. It basically attempts to get TGTs for the users that don't have the property "Do not require Kerberos preauthentication".

```shell
GetNPUsers.py north.sevenkingdoms.local/ -no-pass -usersfile north_sevenkingdoms_filtered
```

From this command I got a ticket for `brandon.stark`:

<img width="1655" alt="Pasted_image_20241220161706" src="https://github.com/user-attachments/assets/482dfb60-02a4-4538-ad15-420b6519c845" />

Now I will try hashcat with this hash, after i copy it in a file.

By issuing the command `hashcat -m 18200 hashed /usr/share/wordlists/rockyou.txt` which tells the hashcat to use the Kerberos as a decryption mechanism and try the rockyou wordlist to brute-force it, I got the following results:

<img width="1630" alt="Pasted_image_20241220162914" src="https://github.com/user-attachments/assets/6c2c26c1-d002-4972-b152-5f48ac0bf214" />
Here I can see the cracked password: `iseedeadpeople`.

## 2.2 Password Spraying

Now I will try Password Spraying to see if some additional passwords can be gained. Password Spraying is a technique where a single or small list of passwords is systematically tried across multiple user accounts.

I will use the list of usernames as a password list, so the usernames will be tried if they have a password which is the same as any of the usernames.

For this attack I will use the `Sprayhound` tool:

```shell
sprayhound -U username -d north.sevenkingdoms.local -dc 10.4.10.11 -lu samwell.tarly -lp Heartsbane --lower -t 2
```

In order to avoid the account lockdown, when trying different password, I provide here the credentials of an account that we have `samwell.tarly - Heartsbane`, and I provide the username file as a list of usernames and that will be used as the list of passwords as well.

Via this command, the `sprayhound` will try to get password policies, and then by providing the `-t` I set the threshold to 2, meaning that the tool will stop trying passwords when two tries are left. This information about how many tries are allowed, `sprayhound` hopes to gain via the password policy.

<img width="1214" alt="Pasted_image_20241223094759" src="https://github.com/user-attachments/assets/e99fcedd-9888-4c17-8a19-2076e80839f1" />

And, here I got another password! In total, now I have credentials from three accounts:

```shell
samwell.tarly:Heartsbane
hodor:hodor
brandon.stark:iseedeadpeople
```

## 2.3 Getting the User Accounts

One of the most important and first steps after acquiring credentials to an AD, is to use that account and get as much information about other users as possible.

There are many tools that help on doing this.

GetADUsers:
```shell
GetADUsers.py -all north.sevenkingdoms.local/brandon.stark:iseedeadpeople
```

<img width="1234" alt="Pasted_image_20241223104053" src="https://github.com/user-attachments/assets/6706792c-96b5-4d4f-b6cc-dc7fc76a4dc9" />

Here there are also some additional information as to where was the last time the password was set and the last time where the account has been logged in to the system.

We can also use the users we have credentials to get users not only from the host they belong to, but also from other hosts in the system, as there is a high probability that there exist a trust between them.

For that we can use `ldapsearch`:

```shell
ldapsearch -H ldap://10.4.10.10 -D "brandon.stark@north.sevenkingdoms.local" -w iseedeadpeople -b 'DC=sevenkingdoms,DC=local' "(&(objectCategory=person)(objectClass=user))" | grep 'distinguishedName'
```

So, from a user `brandon.sark` in Winterfell, I was able to get user information in Kingsldanding:

<img width="1438" alt="Pasted_image_20241223105046" src="https://github.com/user-attachments/assets/4cb63fe2-48aa-4d0c-8bc5-6e96b7bb559d" />
