# Network Services

In a scenario when a pentesting is being conducted, and we encounter a Linux host, by monitoring the network traffic, we can see that a user on this hsot connects to a server via an unencrypted FTP server.

Via this simple scenario, it is shown how important it is to understand the network services and how they work. This, not only for network and systemd adminsitrators but also for penetration testers.

## SSH

It is a network protocol which allows secure transmission of data and commands over a network.

The most commonly used SSH (Secure Shell) server is the **OpenSSH** server.

With it, administrators can trasnfer data and execute commands on remote systems, thus establishing a secure remote connection.

OpenSSH can be installed via this command:

```sh
sudo apt install openssh-server
```

SSH can be used to securely access remote systems, and can be done by using the following command:

```sh
ssh username@ip_address
```

You can configure OpenSSH by editing the `/etc/ssh/sshd_config`, where you can adjust settings such asthe maximum number of concurrent connections, access options such as passwords or keys, and more.

## NFS

Is a network protocol which allow you to store and manage files as if they were stored on local system.

There are a number of (Network File System) servers for Linux, such as: NFS-UTILS (Ubuntu), NFS-Ganesha (Solaris), and OpenNFS (Redhat).

NFS can be installed with the following command: `sudo apt install nfs-kernel-server`

NFS can be configured by editing `/etc/exports` which specifies the directories that should be shared and the access rights. You can configure also settings like the transfer speed and encryption.


| Permissions       | Description                                                                   |
|:------------------|:------------------------------------------------------------------------------|
| rw                | Read and write permissions                                                    |
| ro                | Read-only access                                                              |
| no_root_squash    | Prevents the client's root user from being restricted as a normal user        |
| root_squash       | Restricts the client's root user as a normal user                             |
| sync              | Changes on data are transferred after they have been saved on the file system |
| async             | Trasnfer data asynchronously, which is faster, but may cause inconsistencies  |

In order to share a folder we have to first create it:

```sh
mkdir shared_folder
```

Edit the configuration file, with the settings that we want, such as:

```sh
echo '/home/halil/shared_folder ip_of_the_hoste(rw, sync, no_root_squash)' >> /etc/exports
```

And if we want to work on a target system, in an NFS share, we have to mount it:

```sh
mkdir ~/target_share
mount target_ip:/home/target_user/target_folder ~/target_share
```

## Web Server

From the most used web servers on Linux are: 
- Apache
- Nginx
- Lighttpd
- Caddy

We have to edit the `/etc/apache2/apache2.conf` to specify which folders can be accessed and what actions can be performed on them.

## VPN

Functions like a secure tunnel that connects us to a network, and allowing us to access it like we are physically present. This is done by creating an encrypted tunnel between the client and the server, in order to ensure that all data transmitted is confidential, and guarded by unauthorized access.

This is the reason why a lot of organizations use it to grant their employees secure access to the internal network without requiring them to be on-site.

The most widely used VPN solutions for Linux are:
- OpenVPN, 
- L2TP/IPsec,
- PPTP,
- SSTP,
- SoftEther

OpenVPN can be customized by editing `/etc/openvpn/server.conf`, which contains settings for features such as: encryption, tunneling, traffic shaping, etc.