# The forbidden RAM disk 

TODO.

## Usage

```bash
root@qemuarm64:~# insmod xrd.ko
[   43.962180] xrd: loading out-of-tree module taints kernel.
[   43.966036] loaded.

root@qemuarm64:~# echo "0x50000000" > /sys/module/xrd/parameters/address
root@qemuarm64:~# echo "0x1000000" > /sys/module/xrd/parameters/size
[   48.082219] create RAM disk... (address: 0x50000000, size: 16777216).
[   48.108744] RAM disk xram0 created.

root@qemuarm64:~# lsblk
NAME  MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
xram0 251:0    0    16M  0 disk
vda   253:0    0 228.1M  0 disk /

root@qemuarm64:~# mkfs.ext4 /dev/xram0
mke2fs 1.46.1 (9-Feb-2021)
Creating filesystem with 4096 4k blocks and 4096 inodes

Allocating group tables: done
Writing inode tables: done
Creating journal (1024 blocks): done
Writing superblocks and filesystem accounting information: done

root@qemuarm64:~# mkdir mnt
root@qemuarm64:~# ls
mnt     xrd.ko

root@qemuarm64:~# mount /dev/xram0 mnt/
[  160.786314] EXT4-fs (xram0): mounted filesystem with ordered data mode. Opts: (null)
[  160.791805] ext4 filesystem being mounted at /home/root/mnt supports timestamps until 2038 (0x7fffffff)

root@qemuarm64:~# echo "hello" > mnt/hello.txt
root@qemuarm64:~# cat mnt/hello.txt
hello
```

## How to reserve memory

### Device tree

Convert your dtb to dts.
```
dtc -I dtb -O dts -o qemu.dts qemu.dtb
```

Add a range in reserved-memory node (ex: xramdisk):
```
    memory@40000000 {
        reg = <0x00 0x40000000 0x00 0x20000000>;
        device_type = "memory";
    };

    reserved-memory {
        #address-cells = <2>;
        #size-cells = <2>;
        ranges;

        xramdisk@0 {
            no-map;
            reg = <0x00 0x50000000 0x00 0x02000000>;
        };
    };
```

Here we reserve 32M starting from 0x50000000 in available RAM memory (512M starting at 0x40000000).

Convert your dts to dtb.
```
dtc -I dts -O dtb -o qemu.dtb qemu.dts
```

When your device is up, we can check if the range is reserved.
```
qemuarm64 login: root
root@qemuarm64:~# cat /proc/iomem
09000000-09000fff : pl011@9000000
  09000000-09000fff : 9000000.pl011 pl011@9000000
09010000-09010fff : pl031@9010000
  09010000-09010fff : rtc-pl031
09030000-09030fff : pl061@9030000
10000000-3efeffff : pcie@10000000
  10000000-1003ffff : 0000:00:01.0
  10040000-10040fff : 0000:00:01.0
  10041000-10041fff : 0000:00:03.0
40000000-4fffffff : System RAM
  40200000-40faffff : Kernel code
  40fb0000-4132ffff : reserved
  41330000-4156ffff : Kernel data
  48000000-48008fff : reserved
50000000-51ffffff : reserved -> xramdisk range
52000000-5fffffff : System RAM
  5e000000-5effffff : reserved
  5fe22000-5fee2fff : reserved
  5fee3000-5fefffff : reserved
  5ff02000-5ff02fff : reserved
  5ff03000-5ff03fff : reserved
  5ff04000-5ff0efff : reserved
  5ff0f000-5fffffff : reserved
4010000000-401fffffff : PCI ECAM
8000000000-ffffffffff : pcie@10000000
  8000000000-8000003fff : 0000:00:01.0
    8000000000-8000003fff : virtio-pci-modern
  8000004000-8000007fff : 0000:00:02.0
    8000004000-8000007fff : virtio-pci-modern
  8000008000-800000bfff : 0000:00:03.0
    8000008000-800000bfff : virtio-pci-modern```
```

### Generate and use a device tree with QEMU (optional)

Add `-machine dumpdtb=qemu.dtb` to your QEMU command, ex:
```
/home/red/distribution/hardknott/poky/build/tmp/work/x86_64-linux/qemu-helper-native/1.0-r1/recipe-sysroot-native/usr/bin/qemu-system-aarch64 \
-device virtio-net-pci,netdev=net0,mac=A4:B1:B1:03:A2:AF \
-netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::2223-:23 \
-drive file=./files/core-image-minimal-qemuarm64.ext4,if=virtio,format=raw \
-object rng-random,filename=/dev/urandom,id=rng0 \
-device virtio-rng-pci,rng=rng0 \
-machine virt \
-cpu cortex-a57 -m 512 \
-serial mon:stdio -serial null \
-kernel ./files/Image \
-append 'root=/dev/vda rw highres=off console=ttyS0 mem=512M ip=dhcp console=ttyAMA0,115200 console=tty ' \
-nographic \
-machine dumpdtb=qemu.dtb
```

> remark: .dtb generated cannot be loaded by QEMU, you will need to convert it to dts, adn convert it back to dtb...

```
# Convert dtb to dts
dtc -I dtb -O dts -o qemu.dts qemu.dtb

# Convert dts to dtb
dtc -I dts -O dtb -o qemu.dtb qemu.dts
```

Once the conversion is done, load the device tree by adding `-dtb ./files/qemu.dtb` to your QEMU command, ex:
```
/home/red/distribution/hardknott/poky/build/tmp/work/x86_64-linux/qemu-helper-native/1.0-r1/recipe-sysroot-native/usr/bin/qemu-system-aarch64 \
-device virtio-net-pci,netdev=net0,mac=A4:B1:B1:03:A2:AF \
-netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::2223-:23 \
-drive file=./files/core-image-minimal-qemuarm64.ext4,if=virtio,format=raw \
-object rng-random,filename=/dev/urandom,id=rng0 \
-device virtio-rng-pci,rng=rng0 \
-machine virt \
-cpu cortex-a57 -m 512 \
-serial mon:stdio -serial null \
-kernel ./files/Image \
-append 'root=/dev/vda rw highres=off console=ttyS0 mem=512M ip=dhcp console=ttyAMA0,115200 console=tty ' \
-nographic \
-dtb ./files/qemu.dtb
```

## TODO

- Support multiple disks.

## References

- https://blog.pankajraghav.com/2022/11/30/BLKRAM.html
- https://github.com/Panky-codes/blkram/blob/master/blkram.c
- https://static.lwn.net/images/pdf/LDD3/ch16.pdf
- https://xilinx-wiki.atlassian.net/wiki/spaces/A/pages/18841683/Linux+Reserved+Memory
- https://docs.u-boot.org/en/latest/develop/devicetree/dt_qemu.html
- https://tldp.org/LDP/lkmpg/2.6/html/x323.html
- https://www.gnu.org/software/libc/manual/html_node/Permission-Bits.html
