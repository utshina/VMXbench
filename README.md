# The VMX benchmark (VMXbench)

VMXbench is a benchmark program written as a UEFI application that measures the number of cycles involved in a VM entry/exit. It currently supports Intel VT-x processors that have the Virtual Machine Extensions (VMX) capability.

## Description

VMXbench measures the number of cycles in a VM exit and entry ten times after warming up, and print the min/max/avg cycles to the console. It is useful for measuring the bare-metal hardware performance of the virtualization technology in different generation processors. It also helps learn the basic usage of Intel VT-x and how to make a UEFI application.

## Sample Output

```
Starting VMXbench ...
VMX is supported
Enable VMX
Enable VMX operation
Enter VMX operation
Initialize VMCS
Launch a VM
VM exit[0]:   330, VM entry[0]:   300
VM exit[1]:   330, VM entry[1]:   294
VM exit[2]:   332, VM entry[2]:   292
VM exit[3]:   330, VM entry[3]:   293
VM exit[4]:   330, VM entry[4]:   296
VM exit[5]:   330, VM entry[5]:   298
VM exit[6]:   326, VM entry[6]:   296
VM exit[7]:   330, VM entry[7]:   293
VM exit[8]:   332, VM entry[8]:   290
VM exit[9]:   332, VM entry[9]:   292
VM exit : min =   326, max =   332, avg =   330
VM entry: min =   290, max =   330, avg =   294
Press any key to go back to the UEFI menu
```

## Build

You first need to install the mingw cross compiler.

Ubuntu: `sudo apt-get install gcc-mingw-w64`

Fedora: `sudo dnf install mingw64-gcc`

CentOS: `sudo yum install mingw64-gcc`

If you use a distribution other than the above, find a 64bit mingw cross compiler, and set its name to "CC" in the Makefile.

Then, type the following command.

`make`

## Test-Run

Typing the following command will run VMXbench on QEMU.

`make qemu`

This will download a UEFI firmware (OVMF-X64-r15214.zip). If you can't download it, find the latest version from http://tianocore.sourceforge.net/wiki/OVMF or in your distribution.

## Run

Copy main.efi into a USB frash drive as \EFI\BOOT\BOOTX64.EFI and boot from the drive. You may need to change the boot order at the boot menu.

## Licence

[The MIT License](http://opensource.org/licenses/MIT)
