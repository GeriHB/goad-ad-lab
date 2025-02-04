# Linux Networking

## Network Configuration

Tools like:
- syslog
- rsyslog
- ss (for socket stats)
- lsof (list open files)

can be used to monitor and analyze network traffic.

Then, when it comes to **activating network interfaces**, `ifconfig` and `ip` commands are common tools.

**Activate a Network interface**
```sh
sudo ifconfig eth0 up
```

or

```sh
sudo ip link set eth0 up
```

**Assign IP Address to an interface**
```sh
sudo ifconfig eth0 192.168.1.2
```

**Assign a Netmask**
```sh
sudo ifconfig eth0 netmask 255.255.255.0
```

Often it is necessary to set DNS to ensure proper network functionality.

This can be achieved by updating the `/etc/resolv.conf`, a file that contains DNS information.

But, this file is not persistent across reboots or network configuration changes, as it may be automatically overwritten by network management services such as: `NetowrkManager` or `systemd-resolved`.

So, to make the changes permanent you should configure DNS settings through editing network configuration files or using network management utilities that store persistent settings.

```sh
sudo vim /etc/network/interfaces
```

**/etc/network/interfaces**
```txt
auto eth0
iface eth0 inet static
    address 192.168.1.2
    netmask 255.255.255.0
    gateway 192.168.1.1
    dns-nameservers 8.8.8.8 8.8.4.4
```

## NAC - (Network Access Control)

There are different NAC technologies to enhance security measures:
- DAC (Discretionary Access Control)
- MAC (Mandatory Access Control)
- RBAC (Role-based Access Control)

**DAC** means that users and groups who own a resource can decide who was access to it and what actions they are authorized to perform.

**MAC** each resource is assigned a *Security Label* that defines its *Security Level* and then each user or process is assigned a *Security Clearance*.

So to access a resource, the user or the process must have it's *security level* equal or greater than the *security level* of the resource.

**RBAC** assigns permissions to users based on their roles within an organization, and each role is granted a set of permissions that determine what actions they can perform.

## Troubleshooting
A number of tools that can help to identify and resolve network issues are:
- Ping
- Traceroute
- Netstat
- Tcpdump
- Wireshark
- Nmap

**Traceroute** sends packets with increased TTL values to a remote host and displays the IP addresses of the devices that the packets pass through.

**Netstat** is used to display active network connections and their associated ports, so it can be used to identify network traffic and troubleshoot connectivity issues.

## Hardening
Three such mechanisms are:
- SELinux
- AppArmor
- TCP wrappers

**SELinux** is MAC integrated into the linux. Provides control over access to system resources and apps by enforcing security policies, which define the permissions for each process and file on the system.

**AppArmor** is also a MAC which controls access to apps and system resources, but is more simpler. It's implemented as a Linux Security Module, and uses app profiles to define the resources that an app can access.

**TCP Wrappers** They intercept network requests, and check it against a list of allowed or dernied IP addresses.

# Remote Desktop Protocols in Linux

Two of the most common protocols are:
- RDP primarily used in Windows.
- VNC (Virtual Network Computing) a popular protocol in Linux, but is cross-platform.

## XServer
Is the user-side part of the *X Window System network protocol (X11 /X)*.

X11 consists of a collection of protocols and apps that allow us to call app windows on displays in a GUI.

When a desktop is started on Linux, the communication of the GUI with the OS happens via an X server.

**X11 Forwarding**

X11 is rendered on the local computer, which saves ttraffic on the remote computer, but the disadvantage is that it has unencrypted data.

This can be overcomed by tunneling the SSH protocol, by adding the `yes` value on `/etc/ssh/sshd_config`

```sh
cat /etc/ssh/sshd_config | grep X11Forwarding
X11 Forwarding yes
```

Then we can for example start an app from our client:

```sh
ssh -X username@ip_address /usr/bin/firefox
```

## X11 Security
Is not a secure protocol, since it is unencrypted, so we should pay attenttion for the 6000-6010 TCP ports.

## XDMCP

The **X Display Manager Control Protocol** is used by the X Display Manager for communication through UDP prot 177 between terminals and computers. It's an insecure protocol and shouldn't be used.

It's possible to redirect and entire GUI to a client.

## VBC

**Virtual Networm Computting** is a RD sharing system based on RFB protocol, and allows a user to view and interact with the DE remotely over a network connection.

It uses encryption and requires authentication. 

There are two different concepts:

- The usual server offers the actual screen of the host computer for user support, but because the keyboard and mouse are usable at the remote computer an arrangement should be done.
- Allows usere login to virtual sessions, similar to terminal server concept.

Usually it listens on TCP port 5900, and other displays are assigned a higher port like 8901, 5902, etc.

Some common tools for VNC connections are:
- TigerVNC
- TightVNC
- RealVNC
- UltraVNC

