# Lab Environment and Assessment Scope

## Purpose

This assessment was performed to develop and demonstrate a structured methodology for evaluating an Active Directory environment. The focus was not only on executing individual techniques, but on understanding how separate weaknesses could be chained int oa broader compromise.

## Environment

The full GOAD lab was deployed through Ludus and consisted of five Windows systems across two forests and three domains.

### Assessed systems

- `KINGSLANDING` - domain controller for `sevenkingdoms.local`
- `WINTERFELL` - domain controller for `north.sevenkingdoms.local`
- `CASTELBLACK` - member server in `north.sevenkingdoms.local`
- `MEEREEN` - domain controller for `essos.local`
- `BRAAVOS` - member server in `essos.local`

The assessment system was a Kali Linux host connected to the isolated lab network.

## Starting position

The assessment began with:

- Network access to the GOAD subnet
- No domain credentials
- No administrative access
- No prepared list of valid domain users
- Prior knowledge that the systems belonged to an authorised and intentionally vulnerable lab

## Scope

The in-scope activities included:

- Network and service discovery
- Domain, user, group, and policy enumeration
- Authentication and credential attacks
- Lateral movement and privilege escalation
- Kerberos ticket abuse
- AD CS assessment
- Delegation assessment
- Command-and-control validation
- Defensive analysis of the identified weaknesses

## Methodology

The work followed these phases:

1. Discover reachable systems and identify domain relationships
2. Enumerate accounts, groups, and password policies
3. Obtain and validate initial credentials
4. Expand access through Kerberos and NTLM weaknesses
5. Identify administrative relationships and extract privileged credentials
6. Validate domain compromise and Kerberos persistence
7. Assess certificate-service and delegation misconfigurations
8. Exercise a post-compromise command-and-control workflow
9. Translate the technical results into defensive priorities

## Evidence handling

Only the evidence required to support a conclusion is included. Repetitive terminal output and complete credential material are omitted or shortened.

Lab credentials are represented as placeholders such as:

```text
<LAB_PASSWORD>
<NT_HASH_REDACTED>
<KRBTGT_KEY_REDACTED>
<DOMAIN_SID>
```

## Navigation

[Assessment index](../README.md) | [Next: Discovery and enumeration](01-discovery-and-enumeration.md)