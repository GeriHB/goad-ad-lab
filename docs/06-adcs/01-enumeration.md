# AD CS Enumeration

## Objective

The purpose of enumeration was to identify the certificate authorities, enabled templates, enrolment rights, and configuration combinations that could be abused from the current low-privileged account.

## Method

```bash
certipy find -u khal.drogo@essos.local -p 'horse' -vulnerable -dc-ip 10.4.10.12 -stdout
```

## Certificate authority findings

Among others, the assessment identified one enterprise CA:

```text
CA name:                         ESSOS-CA
DNS name:                        braavos.essos.local
Web Enrollment:                  Enabled
User-specified SAN:              Enabled
Request disposition:             Issue
Request encryption enforcement:  Enabled
Enrolment rights:                 Authenticated Users
```

The CA-level configuration exposed two important conditions:

- A user-specified Subject Alternative Name could be accepted
- The Web Enrollment endpoint was enabled, reating an NTLM relay target

The complete findings can be found here: [Findings](../../assets/evidence/06-adcs/findings.md).

## Template findings

`Certipy` identified the following relevant template conditions:

- `ESC1` - enrollee-supplied subject with client authentication
- `ESC2` - Any purpose certificate available to Domain Users
- `ESC3-CRA` - Certificate Request Agent templtae available to Domain Users
- `ESC4` - dangerous template object permissions held by `khal.drogo`

## Result

The enumeration confirmed that a normal domain user had several independent certificate-based escalation paths. 

The most significant issue was not one isolated template, but the breadth of unsafe trust placed in low-privileged enrolment and template-control rigts.

## Detection opportunities

- Changes to certificate templates and their ACLs
- Certificate requests for alternative UPNs or privileged identities
- Use of templates that rarely appear in normal business workflows
- Certificate issuance to low-privileged users followed by privileged logons
- Web Enrollment traffic from unusual clients

## Mitigation

- Review all enabled templates, not only the default ones
- Restrict enrolment to groups that have a documented operational need
- Remove unnecessary client-authentication and Any Purpose EKUs
- Prevent enrollees from supplying arbitrary subject information unless required and safely constrained
- Limit template ownership, `WriteDACL`, `WriteOwner`, and property modification rights
- Disable Web Enrollment when it's not required

## Navigation

[AD CS index](README.md) | [Next: ESC1](02-esc1.md)