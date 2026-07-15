# Active Directory Certificate Services (ADCS) Assessment

## Objective

This section documens the enumeration and validation of certificate-service misconfigurations in the `essos.local` domain.

The assessment focused on whetehr a normal domain user could obtain or influence certificatess in a way that enabled authentication as a more privileged didentity.

## Starting position

- Valid `khal.drogo` credentials in `essos.local`
- Network access to the domain controller rand certificate authority
- No administrative privilege at the start of the AD CS assessment

## Certificate authority

Certipy identified:

```text
CA name:              ESSOS-CA
CA host:              braavoos.essos.local
Web Enrollment:       Enabled
User-specified SAN:   Enabled
Request disposition:  Issue
Enabled templates:    16
Discovered templates: 38
```

The imporant result was not the number of templates, but the combination of enrolment rights, certificate purposes, subject-name controls, and dangerous template permissions.

## Assessment sections

- [AD CS enumeration](01-enumeration.md)
- [ESC1](02-esc1.md)
- [ESC2 and ESC3](03-esc2-and-esc3.md)
- [ESC4](04-esc4.md)
- [ESC6](05-esc6.md)
- [ESC8](06-esc8.md)

## Overall impact

The combined AD CS configuration allowed low-privileged identities to obtain certificates usable for authentication as privileged users or computers. Because certificate-based authentication can remain valid independently of the account password, these weaknesses can provide both privilege escalation and durable access.

## Navigation

[Previous: Golden Ticket and cross-domain trust abuse](../05-golden-ticket-and-cross-domain-trust-abuse.md) | [Assessment index](../../README.md) | [Next: AD CS enumeration](01-enumeration.md)