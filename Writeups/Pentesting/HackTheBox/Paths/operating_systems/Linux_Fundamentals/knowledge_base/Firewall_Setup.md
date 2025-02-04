# Firewall Setup

Firewalls can filter incoming and outgoing traffic based on rules, protocols, ports, and other criteria.

In Linux this functionality is typically implemented using the **Netfilter** framework, which is an integral part of the kernel.

## Iptables

Provides set of rules to filter network based on some criteria such as source and destination IP addresses, port, protocols, and more.

There are other solutions also such as:
- nftables
- ufw
- firewalld

**nftables** More modern syntax and improved performance.
**UFW** - Uncomplicated firewall - has a simple and user-friendly interface for to configure firewall rules.
**firewalld** a dynamic and flexible solution that can be used to manage complex firewall configurations.
