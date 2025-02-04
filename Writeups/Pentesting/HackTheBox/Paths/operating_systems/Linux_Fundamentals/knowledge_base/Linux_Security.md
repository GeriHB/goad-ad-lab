# Linux Security

Administering the system as the root user is not recommended, so if a user needs to run a command as root, that command should be specified in the `sudoers` configuration.

Another protection mechanism is `fail2ban`, which counts the number of login attempts, and if maximum is reached, an action can take place.

**SELinux** - every process, file, directory and system object is given a label, and then policy rues created, control access between these labeled processes and objects, and are enforced by the kernel.

**TCP Wrappers**
Controls which services are allowed access to the system, by restricting it based on the hostname or IP address of hte user requesting access.

This mechanism uses the following config files:
- /etc/hosts.allow
- /etc/hosts.deny

For example:

/etc/hosts.allow
```sh
cat /etc/hosts.allow

# Allow access to SSH from the local network
sshd : 10.129.14.0/24

# Allow access to FTP from a specific host
ftpd : 10.129.14.10
```

/etc/hosts.deny
```sh
cat /etc/hosts.deny

# Deny access to all services from any host in the inlanefreight.com domain

ALL : .inlanefreight.com

# Deny access to SSH from a specific host
sshd : 10.129.22.22
```

**TCP Wrappers** are not a replacement for a **firewall**, as they can only control access to services, but not to ports.

