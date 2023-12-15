# The forbidden RAM disk 

```bash
root@qemuarm64:~# insmod xrd.ko
[  567.539646] misc xrd: disk xram0 created.

root@qemuarm64:~# lsblk
NAME  MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
xram0 251:0    0    10M  0 disk /home/root/mnt
vda   253:0    0 227.4M  0 disk /

root@qemuarm64:~# mkfs.ext4 /dev/xram0
mke2fs 1.46.1 (9-Feb-2021)
Creating filesystem with 2560 4k blocks and 2560 inodes

Allocating group tables: done
Writing inode tables: done
Creating journal (1024 blocks): done
Writing superblocks and filesystem accounting information: done

root@qemuarm64:~# mkdir mnt
root@qemuarm64:~# ls
mnt     xrd.ko

root@qemuarm64:~# mount /dev/xram0 mnt/
[  684.585002] EXT4-fs (xram0): mounted filesystem with ordered data mode. Opts: (null)
[  684.585186] ext4 filesystem being mounted at /home/root/mnt supports timestamps until 2038 (0x7fffffff)

root@qemuarm64:~# echo "hello" > mnt/hello.txt
root@qemuarm64:~# cat mnt/hello.txt
hello
```

## References

- https://blog.pankajraghav.com/2022/11/30/BLKRAM.html
- https://github.com/Panky-codes/blkram/blob/master/blkram.c
- https://static.lwn.net/images/pdf/LDD3/ch16.pdf
