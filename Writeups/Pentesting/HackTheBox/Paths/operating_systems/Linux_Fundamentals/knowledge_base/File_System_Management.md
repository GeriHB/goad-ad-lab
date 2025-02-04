# File System Management

Linux supoprts many file systems, such as:
- ext2
- ext3
- ext4
- XFS
- Btrfs
- NTFS, etc.

**ext2** - old file system, without journaling. Still useful in some low-overhead scenarios (USB drives).
**ext3** and **ext4** - Have journaling (helping in recovery from crashes).
**Btrfs** - Has advanced features like snapshotting and built-in data integrity checks - ideal for complex storage setups.
**NTFS** - is useful when dealing with dual-boot systems or external drives, dealing with Windows.

## Inode
The Linux's hierarchical structure consists of components, like **inodes** which are data structures that store metadata about each file and directory (permissions, ownership, size, teimestamps).

They don't store the file's data or name, but contain pointers to the blocks where the file's data is stored on the disk.

The **inode table** acts like a database that the Linux kernel uses to track files and directories.

## File types

Files can be stored one some key types:
- Regular files
- Directories
- Symbolic links

**Regular Files** typically are comprised of text data (ASCII) or binary (image, audio, executables).

**Directories** are special types of files acting as containerrs for other files (regular files or directories).

**Symbolic links** are references to other files or directories, and allow quick access to files located in different places.

## Disk drives

The main tool for disk management is `fdisk` allowing to create, delete, and manage partitions on a drive.

Also has information about the partition table, such as size and type of each partition.

Common partition tools are: 
- fdisk
- gpart
- Gparted

## Mounting

Logical partitions or sotrage drives have to be assigned to a directory in the system. 

`mount` is a ocmmand to manually mount file systems on linux. And if there is a need to automatically mount the system boots, these can be defined in the `/etc/fstab/` file.

**Mounting a USB drive**
Let's say the name of the device is `/dev/sdb` and we want to mount it to `/mnt/usb`, this can be done via this command:

```sh
sudo mount /dev/sdb1 /mnt/usb
```

**Unmounting the USB drive**
```sh
sudo umount /mnt/usb
```

Sometimes there are running processes which are using the file system, and we can use the `lsof` command to list the open files on a file system.

```sh
lsof | grep halil
```

If we find processes using hte file system, we need to stop them before unmounting.

**Unmounting automatically when the system is shutd down**
This can be achieved by modifying `/etc/fstab/` file.

To unmount just add an option `noauto` to the entry, and an example can be like this:

```fstab
/dev/sda1 / ext4 defaults 0 0
/dev/sda2 /home ext4 defaults 0 0
/dev/sdb1 /mnt/usb ext4 rw, noauto, user 0 0
```

## SWAP

When the system runs out of physical memory, the kernel moves the data that is not immediately in use to the swap space, thus freeing the RAM for the processes that need it.

**Creating Swap Space**
If not set during hte installation fo the OS, `mkswap` and `swapon` can be used to add it later.

It's recommedned to put the swap space on a dedicated partition, and since there can be sensitive data, to encrypt the swap space.

