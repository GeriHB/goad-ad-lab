# Command and Control with Sliver

## Objective

This section documents the use of `Sliver` after administrative access had already been established in the GOAD environment.

The objective was to understand:

- C2 infrastructure and listener setup
- Implant generation and session handling
- Host and domain discovery through an active session
- Selected post-exploitation workflows
- Defender-visible artefacts and cleanup requirements

Sliver was not used as a shortcut to the earlier attack path. It was evaluated as a separate post-compromise operating workflow.

## Sections

- [Infrastructure and initial session](01-infrastructure-and-initial-session.md)
- [Host and domain discovery](02-host-and-domain-discovery.md)
- [Credential and directory assessment](03-credential-and-directory-assessment.md)
- [Cleanup and defensive observations](04-cleanup-and-defensive-observations.md)

## Starting position

- Administrative aaccess to systems in `north.sevenkingdoms.local`
- A Kali Linux operator at `10.4.10.99`
- An isolated lab network

## Validation summary

The following were validated:

- HTTP listener and Windows x64 implant generation
- Initial callback and interactive session
- Privilege escalation to `NT AUTHORITY\\SYSTEM` with a Sliver extension
- Host, network, share, DNS, session, and ticket discovery
- Kerberoastable account discovery
- Retrieval of a stored credential from Windows Credential Manager

## Navigation

[Previous: Kerberos delegation](../07-kerberos-delegation.md) | [Assessment index](../../README.md) | [Next: Infrastructure and initial session](01-infrastructure-and-initial-session.md)
