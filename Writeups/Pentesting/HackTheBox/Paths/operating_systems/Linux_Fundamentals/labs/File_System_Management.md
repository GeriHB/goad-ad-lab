# Challenge

How many partitions exist in our Pwnbox?

# Solution

For this I will use the `fdisk` tool and the `-l` to list the partitions in the system.

```sh
fdisk -l
```

The result is:

```sh
Disk /dev/vda: 40 GiB, 42949672960 bytes, 83886080 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xbe9de24c

Device     Boot    Start      End  Sectors  Size Id Type
/dev/vda1  *        2048 81885183 81883136   39G 83 Linux
/dev/vda2       81887230 83884031  1996802  975M  5 Extended
/dev/vda5       81887232 83884031  1996800  975M 82 Linux swap / Solaris
```

Here we see that there are 3 partitions, but to how it shown faster, and not even count, we can combine commands `fdisk -l`, `grep`, and `wc`.

So, after executing the command:

```sh
sudo fdisk -l | grep '^/dev/' | wc -l`
```

it returns the number 3, which means it's the total number of the partitions, as it counts the partitions shown in the beginning of the line, not the deivce itself: `Disk /dev/vda`.

And the number `3` is the correct number and the lab is solved.

