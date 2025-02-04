# Backup and Restore

There are a number of options when backing up data on Linux:
- Rsync
- Deja Dup
- Duplicity

## Rsync

One of the main advanages is that only trasnfers data that haas been changed, which makes it efficient when dealing with large amount of data.

Can be installed with:

```sh
sudo apt install rsync
```

Backup a local directory to the server:

```sh
rsync -av /path/to/directory user@server:/path/to/directory
```

Backup with compression and incremental backups:

```sh
rsync -avz --backup --backup-dir/path/to/backup/folder --delete /path/to/mydirectory user@server:/path/to/backup/directory
```
Here `mydirectory` is backed up to the server, and with the --backup it creates incremental backups in the `/backup/folder` and the --delete removes files from the remote host that is no longer present in the source directory.

Restore the backup:
```sh
rsync -av user@server:/path/to/directory /path/to/local/directory
```

We can also transfer our data over the encrypted ssh connection:

```sh
rsync -avz -e -ssh /path/to/directory user@server:/path/to/backup
```

## Duplicity

Builds on Rsync, but with additional encryption features to protect backups.

## Deja Dup

Offers a GUI making hte process straightforward. Behind the scenes it uses Rsync, and also supports encrypted backups.

**Encryption**
Another tools like GnuPG, eCryptfs, or LUKS can add another layer protection to the backups.

## Auto-synchronization

A combination of `cron` and `rsync` can be used to automate the syncrhonization process.

For this we need a new script which triggers the `rsync` command to sync our local with the remote directory. If we want to use SSH we need to configure the key-based authentication.

Generate a key pair for the user:
```ssh
ssh-keygen -t rsa -b 2048
```

Copy our public key to the remote server:
```sh
ssh-copy-id user@server
```

Create the backup script:
```sh
#!/bin/bash

rsync -avz -e ssh /path/to/directory user@serveer:/path/to/backup
```

Make it executable:
```sh
chmod +x rsync_script.sh
```

Create a cronjob to tell the `cron` to run the script for example every hour:
`cronjob -e`

```sh
0 * * * * /path/to/rsync_script.sh
```

